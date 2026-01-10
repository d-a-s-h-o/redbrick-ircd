// Copyright (c) 2026 Ergo IRC
// released under the MIT license

package irc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	BridgeProtocolVersion = "1.0"
	MaxTimestampSkew      = 5 * time.Minute // Allow 5 min clock skew
	NonceLength           = 16              // Minimum nonce length in hex
)

// Bridge protocol errors
var (
	errBridgeAuthFailed     = errors.New("Authentication failed")
	errBridgeInvalidRequest = errors.New("Invalid request format")
	errBridgeReplayAttack   = errors.New("Possible replay attack detected")
	errBridgeVersionMismatch = errors.New("Protocol version mismatch")
	errBridgeInvalidHMAC    = errors.New("Invalid HMAC signature")
	errBridgeMissingFields  = errors.New("Required fields missing")
)

// BridgeMessageType represents the type of bridge message
type BridgeMessageType string

const (
	// PHP → IRC messages
	MsgTypeAuth              BridgeMessageType = "AUTH"
	MsgTypePHPUserJoin       BridgeMessageType = "PHP_USER_JOIN"
	MsgTypePHPUserLeave      BridgeMessageType = "PHP_USER_LEAVE"
	MsgTypePHPMessage        BridgeMessageType = "PHP_MESSAGE"
	MsgTypePHPDestChange     BridgeMessageType = "PHP_DEST_CHANGE"
	MsgTypePHPModAction      BridgeMessageType = "PHP_MOD_ACTION"
	MsgTypePHPMappingUpdate  BridgeMessageType = "PHP_MAPPING_UPDATE"
	MsgTypeLinkStart         BridgeMessageType = "LINK_START"
	MsgTypeLinkStatus        BridgeMessageType = "LINK_STATUS"

	// IRC → PHP messages (responses)
	MsgTypeAuthOK            BridgeMessageType = "AUTH_OK"
	MsgTypeIRCUserJoin       BridgeMessageType = "IRC_USER_JOIN"
	MsgTypeIRCUserLeave      BridgeMessageType = "IRC_USER_LEAVE"
	MsgTypeIRCMessage        BridgeMessageType = "IRC_MESSAGE"
	MsgTypeIRCModAction      BridgeMessageType = "IRC_MOD_ACTION"
	MsgTypeIRCMappingUpdate  BridgeMessageType = "IRC_MAPPING_UPDATE"
	MsgTypeLinkToken         BridgeMessageType = "LINK_TOKEN"
	MsgTypeLinkComplete      BridgeMessageType = "LINK_COMPLETE"
	MsgTypeStaffNotesResult  BridgeMessageType = "STAFFNOTES_RESULT"
	MsgTypeError             BridgeMessageType = "ERROR"
)

// BridgeRequest represents an incoming request from PHP
type BridgeRequest struct {
	Type            BridgeMessageType      `json:"type"`
	ProtocolVersion string                 `json:"protocol_version"`
	Timestamp       int64                  `json:"ts"`
	Nonce           string                 `json:"nonce"`
	Payload         map[string]interface{} `json:"payload"`
	HMAC            string                 `json:"hmac"`
}

// BridgeResponse represents an outgoing response to PHP
type BridgeResponse struct {
	OK              bool                   `json:"ok"`
	Type            BridgeMessageType      `json:"type"`
	Payload         map[string]interface{} `json:"payload,omitempty"`
	Error           string                 `json:"error,omitempty"`
	ErrorCode       string                 `json:"error_code,omitempty"`
}

// Payload structures for specific message types

// PHPUserJoinPayload represents a PHP user joining
type PHPUserJoinPayload struct {
	UserID   string `json:"user_id"`
	Nickname string `json:"nickname"`
	Status   int    `json:"status"` // PHP status code 0-8
}

// PHPUserLeavePayload represents a PHP user leaving
type PHPUserLeavePayload struct {
	UserID   string `json:"user_id"`
	Nickname string `json:"nickname"`
}

// PHPMessagePayload represents a message from PHP
type PHPMessagePayload struct {
	UserID   string `json:"user_id"`
	Sendto   string `json:"sendto"`    // "room", "s 31", "s 48", etc.
	Text     string `json:"text"`
	IsAction bool   `json:"is_action"` // /me action
	IsPM     bool   `json:"is_pm"`
	ToUser   string `json:"to_user,omitempty"` // For PMs
}

// PHPDestChangePayload represents a PHP user changing rooms
type PHPDestChangePayload struct {
	UserID     string `json:"user_id"`
	FromSendto string `json:"from_sendto"`
	ToSendto   string `json:"to_sendto"`
}

// PHPModActionPayload represents a moderation action from PHP
type PHPModActionPayload struct {
	Action        string `json:"action"` // "kick" or "ban"
	ActorUserID   string `json:"actor_user_id"`
	TargetUserID  string `json:"target_user_id"`
	Reason        string `json:"reason"`
	ContextSendto string `json:"context_sendto"`
}

// LinkStartPayload represents a link start request
type LinkStartPayload struct {
	PHPUserID string `json:"php_user_id"`
	IRCName   string `json:"irc_name"` // IRC account to link
}

// LinkStatusPayload represents a link status request
type LinkStatusPayload struct {
	PHPUserID string `json:"php_user_id"`
}

// LinkTokenPayload represents the response with a link token
type LinkTokenPayload struct {
	Token   string `json:"token"`
	Expiry  int64  `json:"expiry"` // Unix timestamp
	Message string `json:"message"`
}

// LinkCompletePayload represents link completion notification
type LinkCompletePayload struct {
	PHPUserID   string `json:"php_user_id"`
	IRCAccount  string `json:"irc_account"`
	Success     bool   `json:"success"`
	Message     string `json:"message,omitempty"`
}

// IRCMessagePayload represents a message from IRC to PHP
type IRCMessagePayload struct {
	Nickname  string `json:"nickname"`
	Sendto    string `json:"sendto"`
	Text      string `json:"text"`
	IsAction  bool   `json:"is_action"`
	IsPM      bool   `json:"is_pm"`
	ToUser    string `json:"to_user,omitempty"`
}

// IRCUserJoinPayload represents an IRC user joining a mapped channel
type IRCUserJoinPayload struct {
	Nickname string `json:"nickname"`
	Sendto   string `json:"sendto"` // PHP destination
}

// IRCUserLeavePayload represents an IRC user leaving
type IRCUserLeavePayload struct {
	Nickname string `json:"nickname"`
	Sendto   string `json:"sendto"`
}

// ParseBridgeRequest parses and validates a bridge request
func ParseBridgeRequest(data []byte) (*BridgeRequest, error) {
	var req BridgeRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, errBridgeInvalidRequest
	}

	// Validate required fields
	if req.Type == "" || req.ProtocolVersion == "" || req.Timestamp == 0 || req.Nonce == "" || req.HMAC == "" {
		return nil, errBridgeMissingFields
	}

	// Validate protocol version
	if req.ProtocolVersion != BridgeProtocolVersion {
		return nil, errBridgeVersionMismatch
	}

	// Validate timestamp (replay attack prevention)
	reqTime := time.Unix(req.Timestamp, 0)
	now := time.Now()
	timeDiff := now.Sub(reqTime)
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > MaxTimestampSkew {
		return nil, errBridgeReplayAttack
	}

	// Validate nonce length
	if len(req.Nonce) < NonceLength {
		return nil, errBridgeInvalidRequest
	}

	return &req, nil
}

// ValidateHMAC validates the HMAC signature of a request
func ValidateHMAC(req *BridgeRequest, authKey string) error {
	// Reconstruct the signed data: type|ts|nonce|json(payload)
	payloadJSON, err := json.Marshal(req.Payload)
	if err != nil {
		return errBridgeInvalidRequest
	}

	signData := fmt.Sprintf("%s|%d|%s|%s", req.Type, req.Timestamp, req.Nonce, string(payloadJSON))

	// Compute HMAC
	h := hmac.New(sha256.New, []byte(authKey))
	h.Write([]byte(signData))
	expectedHMAC := hex.EncodeToString(h.Sum(nil))

	// Constant-time comparison
	if !hmac.Equal([]byte(req.HMAC), []byte(expectedHMAC)) {
		return errBridgeInvalidHMAC
	}

	return nil
}

// NewBridgeResponse creates a new successful response
func NewBridgeResponse(msgType BridgeMessageType, payload map[string]interface{}) *BridgeResponse {
	return &BridgeResponse{
		OK:      true,
		Type:    msgType,
		Payload: payload,
	}
}

// NewBridgeError creates a new error response
func NewBridgeError(errMsg string, errCode string) *BridgeResponse {
	return &BridgeResponse{
		OK:        false,
		Type:      MsgTypeError,
		Error:     errMsg,
		ErrorCode: errCode,
	}
}

// Serialize serializes a response to JSON
func (r *BridgeResponse) Serialize() ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	// Add newline for line-delimited protocol
	return append(data, '\n'), nil
}

// ParsePayload parses a generic payload into a specific type
func ParsePayload(payload map[string]interface{}, target interface{}) error {
	// Re-marshal to JSON and unmarshal into target
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

// GetPayloadString safely extracts a string from payload
func GetPayloadString(payload map[string]interface{}, key string) (string, bool) {
	val, ok := payload[key]
	if !ok {
		return "", false
	}
	str, ok := val.(string)
	return str, ok
}

// GetPayloadInt safely extracts an int from payload
func GetPayloadInt(payload map[string]interface{}, key string) (int, bool) {
	val, ok := payload[key]
	if !ok {
		return 0, false
	}
	// Handle both float64 (JSON numbers) and int
	switch v := val.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	default:
		return 0, false
	}
}

// GetPayloadBool safely extracts a bool from payload
func GetPayloadBool(payload map[string]interface{}, key string) (bool, bool) {
	val, ok := payload[key]
	if !ok {
		return false, false
	}
	b, ok := val.(bool)
	return b, ok
}

// IsValidPHPSendto checks if a sendto value is valid
func IsValidPHPSendto(sendto string) bool {
	if sendto == "" {
		return false
	}
	// Valid formats: "room", "s 31", "s 48", "s 56", etc.
	if sendto == "room" {
		return true
	}
	if strings.HasPrefix(sendto, "s ") {
		return true
	}
	// Room IDs or other formats
	return true // Be permissive for now
}

// SanitizeNickname sanitizes a nickname for IRC use
func SanitizeNickname(nick string) string {
	// Remove any characters that aren't allowed in IRC nicknames
	// IRC nicknames: [a-zA-Z][a-zA-Z0-9-_\[\]{}\\|]*
	if nick == "" {
		return ""
	}

	// For now, just trim spaces
	return strings.TrimSpace(nick)
}
