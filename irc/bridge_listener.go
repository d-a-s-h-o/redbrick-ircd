// Copyright (c) 2026 Ergo IRC
// released under the MIT license

package irc

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ergochat/ergo/irc/connection_limits"
	"github.com/ergochat/ergo/irc/utils"
)

// BridgeListener handles incoming connections from PHP
type BridgeListener struct {
	server      *Server
	bridge      *BridgeManager
	config      *BridgeConfig
	listener    net.Listener
	shutdown    atomic.Bool
	activeConns atomic.Int32
	rateLimiter *connection_limits.GenericThrottle
	wg          sync.WaitGroup
}

// NewBridgeListener creates and starts a new bridge listener
func NewBridgeListener(server *Server, bridge *BridgeManager, config *BridgeConfig) (*BridgeListener, error) {
	if config.ListenAddress == "" {
		return nil, fmt.Errorf("bridge listen address not configured")
	}

	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to start bridge listener: %w", err)
	}

	bl := &BridgeListener{
		server:   server,
		bridge:   bridge,
		config:   config,
		listener: listener,
	}

	// Initialize rate limiter if configured
	if config.RequestRateLimit > 0 {
		bl.rateLimiter = &connection_limits.GenericThrottle{
			Duration: time.Minute,
			Limit:    config.RequestRateLimit,
		}
	}

	// Start accepting connections
	bl.wg.Add(1)
	go bl.acceptLoop()

	return bl, nil
}

// Stop stops the bridge listener
func (bl *BridgeListener) Stop() {
	if bl.shutdown.Swap(true) {
		return // Already shutdown
	}

	bl.listener.Close()
	bl.wg.Wait()

	bl.server.logger.Info("bridge", "Listener stopped")
}

// acceptLoop accepts incoming connections
func (bl *BridgeListener) acceptLoop() {
	defer bl.wg.Done()

	for {
		conn, err := bl.listener.Accept()
		if err != nil {
			if bl.shutdown.Load() {
				return
			}
			bl.server.logger.Error("bridge", "Accept error:", err.Error())
			continue
		}

		// Check connection limit
		if bl.config.ConnectionLimit > 0 {
			current := bl.activeConns.Load()
			if current >= int32(bl.config.ConnectionLimit) {
				bl.server.logger.Warning("bridge", "Connection limit reached, rejecting", conn.RemoteAddr().String())
				conn.Close()
				continue
			}
		}

		// Check IP allowlist if configured
		if len(bl.config.allowedIPNets) > 0 {
			remoteIP := utils.AddrToIP(conn.RemoteAddr())
			allowed := false
			for _, allowedNet := range bl.config.allowedIPNets {
				if allowedNet.Contains(remoteIP) {
					allowed = true
					break
				}
			}
			if !allowed {
				bl.server.logger.Warning("bridge", "Rejected connection from non-allowed IP", conn.RemoteAddr().String())
				conn.Close()
				continue
			}
		}

		bl.activeConns.Add(1)
		bl.wg.Add(1)
		go bl.handleConnection(conn)
	}
}

// handleConnection handles a single bridge connection
func (bl *BridgeListener) handleConnection(conn net.Conn) {
	defer bl.wg.Done()
	defer bl.activeConns.Add(-1)
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	sessionID := utils.GenerateSecretToken()

	bl.server.logger.Debug("bridge", "New connection from", remoteAddr, "session", sessionID)

	// Set connection timeout
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	session := &BridgeSession{
		id:            sessionID,
		remoteAddr:    remoteAddr,
		authenticated: false,
		connectedAt:   time.Now(),
		lastActivity:  time.Now(),
	}

	// Add session
	bl.bridge.sessionMu.Lock()
	bl.bridge.sessions[sessionID] = session
	bl.bridge.sessionMu.Unlock()

	// Remove session on exit
	defer func() {
		bl.bridge.sessionMu.Lock()
		delete(bl.bridge.sessions, sessionID)
		bl.bridge.sessionMu.Unlock()
	}()

	// Handle messages
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 64*1024) // 64KB max line size

	for scanner.Scan() {
		if bl.shutdown.Load() {
			return
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// Update activity time
		session.lastActivity = time.Now()
		conn.SetDeadline(time.Now().Add(30 * time.Second))

		// Rate limiting
		if bl.rateLimiter != nil {
			throttled, _ := bl.rateLimiter.Touch()
			if throttled {
				bl.sendError(conn, "Rate limit exceeded", "RATE_LIMIT")
				bl.server.logger.Warning("bridge", "Rate limit exceeded for", remoteAddr)
				return
			}
		}

		// Process request
		response := bl.handleRequest(session, line)
		if response != nil {
			data, err := response.Serialize()
			if err != nil {
				bl.server.logger.Error("bridge", "Failed to serialize response:", err.Error())
				continue
			}
			conn.Write(data)
		}
	}

	if err := scanner.Err(); err != nil {
		bl.server.logger.Debug("bridge", "Connection error:", err.Error())
	}
}

// handleRequest processes a single bridge request
func (bl *BridgeListener) handleRequest(session *BridgeSession, data []byte) *BridgeResponse {
	// Parse request
	req, err := ParseBridgeRequest(data)
	if err != nil {
		bl.server.logger.Warning("bridge", "Invalid request:", err.Error())
		return NewBridgeError(err.Error(), "INVALID_REQUEST")
	}

	// Check for nonce reuse (replay attack)
	if bl.bridge.HasSeenNonce(req.Nonce) {
		bl.server.logger.Warning("bridge", "Nonce reuse detected:", req.Nonce)
		return NewBridgeError("Nonce already used", "REPLAY_ATTACK")
	}

	// Validate HMAC
	if err := ValidateHMAC(req, bl.config.AuthKey); err != nil {
		bl.server.logger.Warning("bridge", "HMAC validation failed:", err.Error())
		return NewBridgeError("Authentication failed", "AUTH_FAILED")
	}

	// Mark nonce as seen
	bl.bridge.MarkNonceSeen(req.Nonce)

	// Handle AUTH specially (doesn't require prior authentication)
	if req.Type == MsgTypeAuth {
		session.authenticated = true
		bl.server.logger.Info("bridge", "Session authenticated:", session.id)
		return NewBridgeResponse(MsgTypeAuthOK, map[string]interface{}{
			"session_id": session.id,
			"server":     bl.server.name,
		})
	}

	// All other requests require authentication
	if !session.authenticated {
		return NewBridgeError("Not authenticated", "NOT_AUTHENTICATED")
	}

	// Dispatch to appropriate handler
	return bl.dispatchRequest(req)
}

// dispatchRequest routes requests to appropriate handlers
func (bl *BridgeListener) dispatchRequest(req *BridgeRequest) *BridgeResponse {
	switch req.Type {
	case MsgTypePHPUserJoin:
		return bl.handlePHPUserJoin(req)
	case MsgTypePHPUserLeave:
		return bl.handlePHPUserLeave(req)
	case MsgTypePHPMessage:
		return bl.handlePHPMessage(req)
	case MsgTypePHPDestChange:
		return bl.handlePHPDestChange(req)
	case MsgTypePHPModAction:
		return bl.handlePHPModAction(req)
	case MsgTypePHPMappingUpdate:
		return bl.handlePHPMappingUpdate(req)
	case MsgTypeLinkStart:
		return bl.handleLinkStart(req)
	case MsgTypeLinkStatus:
		return bl.handleLinkStatus(req)
	default:
		return NewBridgeError(fmt.Sprintf("Unknown message type: %s", req.Type), "UNKNOWN_TYPE")
	}
}

// handlePHPUserJoin handles a PHP user joining
func (bl *BridgeListener) handlePHPUserJoin(req *BridgeRequest) *BridgeResponse {
	var payload PHPUserJoinPayload
	if err := ParsePayload(req.Payload, &payload); err != nil {
		return NewBridgeError("Invalid payload", "INVALID_PAYLOAD")
	}

	if payload.UserID == "" || payload.Nickname == "" {
		return NewBridgeError("Missing user_id or nickname", "MISSING_FIELDS")
	}

	// Check for reserved prefix
	if strings.HasPrefix(strings.ToLower(payload.Nickname), "irc_") ||
		strings.HasPrefix(strings.ToLower(payload.Nickname), "web_") {
		return NewBridgeError("Nickname cannot start with irc_ or web_", "RESERVED_PREFIX")
	}

	err := bl.bridge.CreatePHPUser(payload.UserID, payload.Nickname, payload.Status)
	if err != nil {
		return NewBridgeError(err.Error(), "CREATE_FAILED")
	}

	bl.server.logger.Debug("bridge", "PHP user joined:", payload.Nickname, "status", strconv.Itoa(payload.Status))

	return NewBridgeResponse(MsgTypeAuthOK, map[string]interface{}{
		"success": true,
	})
}

// handlePHPUserLeave handles a PHP user leaving
func (bl *BridgeListener) handlePHPUserLeave(req *BridgeRequest) *BridgeResponse {
	var payload PHPUserLeavePayload
	if err := ParsePayload(req.Payload, &payload); err != nil {
		return NewBridgeError("Invalid payload", "INVALID_PAYLOAD")
	}

	if payload.UserID == "" {
		return NewBridgeError("Missing user_id", "MISSING_FIELDS")
	}

	bl.bridge.RemovePHPUser(payload.UserID, "User left PHP chat")

	return NewBridgeResponse(MsgTypeAuthOK, map[string]interface{}{
		"success": true,
	})
}

// handlePHPMessage handles a message from PHP
func (bl *BridgeListener) handlePHPMessage(req *BridgeRequest) *BridgeResponse {
	var payload PHPMessagePayload
	if err := ParsePayload(req.Payload, &payload); err != nil {
		return NewBridgeError("Invalid payload", "INVALID_PAYLOAD")
	}

	if payload.UserID == "" || payload.Text == "" {
		return NewBridgeError("Missing required fields", "MISSING_FIELDS")
	}

	err := bl.bridge.SendPHPMessage(payload.UserID, payload.Text, payload.IsAction, payload.IsPM, payload.ToUser)
	if err != nil {
		return NewBridgeError(err.Error(), "SEND_FAILED")
	}

	return NewBridgeResponse(MsgTypeAuthOK, map[string]interface{}{
		"success": true,
	})
}

// handlePHPDestChange handles a PHP user changing rooms
func (bl *BridgeListener) handlePHPDestChange(req *BridgeRequest) *BridgeResponse {
	var payload PHPDestChangePayload
	if err := ParsePayload(req.Payload, &payload); err != nil {
		return NewBridgeError("Invalid payload", "INVALID_PAYLOAD")
	}

	if payload.UserID == "" || payload.ToSendto == "" {
		return NewBridgeError("Missing required fields", "MISSING_FIELDS")
	}

	err := bl.bridge.UpdatePHPUserRoom(payload.UserID, payload.ToSendto)
	if err != nil {
		return NewBridgeError(err.Error(), "UPDATE_FAILED")
	}

	return NewBridgeResponse(MsgTypeAuthOK, map[string]interface{}{
		"success": true,
	})
}

// handlePHPModAction handles a moderation action from PHP
func (bl *BridgeListener) handlePHPModAction(req *BridgeRequest) *BridgeResponse {
	var payload PHPModActionPayload
	if err := ParsePayload(req.Payload, &payload); err != nil {
		return NewBridgeError("Invalid payload", "INVALID_PAYLOAD")
	}

	// TODO: Implement moderation action handling
	bl.server.logger.Debug("bridge", "Moderation action:", payload.Action, "by", payload.ActorUserID, "on", payload.TargetUserID)

	return NewBridgeResponse(MsgTypeAuthOK, map[string]interface{}{
		"success": true,
	})
}

// handlePHPMappingUpdate handles a mapping update from PHP
func (bl *BridgeListener) handlePHPMappingUpdate(req *BridgeRequest) *BridgeResponse {
	sendto, _ := GetPayloadString(req.Payload, "sendto")
	channel, _ := GetPayloadString(req.Payload, "channel")

	if sendto == "" || channel == "" {
		return NewBridgeError("Missing sendto or channel", "MISSING_FIELDS")
	}

	err := bl.bridge.UpdateMapping(sendto, channel)
	if err != nil {
		return NewBridgeError(err.Error(), "UPDATE_FAILED")
	}

	return NewBridgeResponse(MsgTypeAuthOK, map[string]interface{}{
		"success": true,
	})
}

// handleLinkStart handles account linking start request
func (bl *BridgeListener) handleLinkStart(req *BridgeRequest) *BridgeResponse {
	var payload LinkStartPayload
	if err := ParsePayload(req.Payload, &payload); err != nil {
		return NewBridgeError("Invalid payload", "INVALID_PAYLOAD")
	}

	if payload.PHPUserID == "" || payload.IRCName == "" {
		return NewBridgeError("Missing required fields", "MISSING_FIELDS")
	}

	// Delegate to bridge linking manager (will be implemented)
	token, expiry, err := bl.bridge.StartAccountLinking(payload.PHPUserID, payload.IRCName)
	if err != nil {
		return NewBridgeError(err.Error(), "LINK_FAILED")
	}

	return NewBridgeResponse(MsgTypeLinkToken, map[string]interface{}{
		"token":   token,
		"expiry":  expiry.Unix(),
		"message": fmt.Sprintf("On IRC, run: /MSG NickServ LINK %s", token),
	})
}

// handleLinkStatus handles account linking status query
func (bl *BridgeListener) handleLinkStatus(req *BridgeRequest) *BridgeResponse {
	var payload LinkStatusPayload
	if err := ParsePayload(req.Payload, &payload); err != nil {
		return NewBridgeError("Invalid payload", "INVALID_PAYLOAD")
	}

	if payload.PHPUserID == "" {
		return NewBridgeError("Missing php_user_id", "MISSING_FIELDS")
	}

	// Check linking status (will be implemented)
	status := bl.bridge.GetLinkingStatus(payload.PHPUserID)

	return NewBridgeResponse(MsgTypeLinkComplete, map[string]interface{}{
		"status":  status,
		"success": status == "completed",
	})
}

// sendError sends an error response
func (bl *BridgeListener) sendError(conn net.Conn, message, code string) {
	response := NewBridgeError(message, code)
	data, err := response.Serialize()
	if err != nil {
		return
	}
	conn.Write(data)
}
