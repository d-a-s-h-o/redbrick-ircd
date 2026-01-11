// Copyright (c) 2026 Ergo IRC
// released under the MIT license

package irc

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"
)

// BridgeManager manages the PHP-IRC bridge
type BridgeManager struct {
	server *Server
	config atomic.Pointer[BridgeConfig]

	// State tracking
	enabled   atomic.Bool
	listener  *BridgeListener
	sessions  map[string]*BridgeSession // Session ID → Session
	sessionMu sync.RWMutex

	// User mappings
	phpToIRC        map[string]string // PHP user ID → IRC nick
	ircToPHP        map[string]string // IRC nick (casefolded) → PHP user ID
	phpUserStatus   map[string]int    // PHP user ID → PHP status (0-8)
	userChannels    map[string]string // PHP user ID → current channel
	linkedAccounts  map[string]string // PHP user ID → IRC account (casefolded)
	userMappingsMu  sync.RWMutex

	// Channel/Room mappings
	phpToChannel    map[string]string // PHP sendto → IRC channel name
	channelToPHP    map[string]string // IRC channel (casefolded) → PHP sendto
	mappingsMu      sync.RWMutex

	// Event deduplication
	seenEvents      *utils.RingBuffer // Recent event IDs
	seenEventsMu    sync.RWMutex

	// Nonce tracking (replay prevention)
	seenNonces      map[string]int64  // nonce → timestamp
	seenNoncesMu    sync.RWMutex
}

// BridgeSession represents an active PHP connection
type BridgeSession struct {
	id            string
	remoteAddr    string
	authenticated bool
	connectedAt   time.Time
	lastActivity  time.Time
}

// NewBridgeManager creates a new bridge manager
func NewBridgeManager(server *Server) *BridgeManager {
	bm := &BridgeManager{
		server:          server,
		sessions:        make(map[string]*BridgeSession),
		phpToIRC:        make(map[string]string),
		ircToPHP:        make(map[string]string),
		phpUserStatus:   make(map[string]int),
		userChannels:    make(map[string]string),
		linkedAccounts:  make(map[string]string),
		phpToChannel:    make(map[string]string),
		channelToPHP:    make(map[string]string),
		seenNonces:      make(map[string]int64),
	}

	// Initialize event deduplication ring buffer (1000 events)
	bm.seenEvents = utils.NewRingBuffer(1000)

	return bm
}

// Initialize sets up the bridge with configuration
func (bm *BridgeManager) Initialize(config *BridgeConfig) error {
	bm.config.Store(config)

	if !config.Enabled {
		bm.enabled.Store(false)
		return nil
	}

	// Initialize default mappings
	bm.mappingsMu.Lock()
	for phpSendto, ircChannel := range config.DefaultMappings {
		cfChannel, err := CasefoldChannel(ircChannel)
		if err != nil {
			bm.server.logger.Error("bridge", "Invalid default mapping channel", ircChannel, err.Error())
			continue
		}
		bm.phpToChannel[phpSendto] = ircChannel
		bm.channelToPHP[cfChannel] = phpSendto
	}
	bm.mappingsMu.Unlock()

	bm.enabled.Store(true)
	bm.server.logger.Info("bridge", "Bridge initialized successfully")

	return nil
}

// Start starts the bridge listener
func (bm *BridgeManager) Start() error {
	config := bm.config.Load()
	if config == nil || !config.Enabled {
		return nil
	}

	listener, err := NewBridgeListener(bm.server, bm, config)
	if err != nil {
		return err
	}

	bm.listener = listener
	bm.server.logger.Info("bridge", "Bridge listener started on", config.ListenAddress)
	return nil
}

// Stop stops the bridge and cleans up
func (bm *BridgeManager) Stop() {
	if bm.listener != nil {
		bm.listener.Stop()
	}

	// Disconnect all PHP users
	bm.userMappingsMu.Lock()
	phpUsers := make([]string, 0, len(bm.phpToIRC))
	for phpUserID := range bm.phpToIRC {
		phpUsers = append(phpUsers, phpUserID)
	}
	bm.userMappingsMu.Unlock()

	for _, phpUserID := range phpUsers {
		bm.RemovePHPUser(phpUserID, "Bridge shutting down")
	}

	bm.enabled.Store(false)
	bm.server.logger.Info("bridge", "Bridge stopped")
}

// IsEnabled returns whether the bridge is enabled
func (bm *BridgeManager) IsEnabled() bool {
	return bm.enabled.Load()
}

// ===== User Management =====

// CreatePHPUser creates or updates a PHP user in IRC
func (bm *BridgeManager) CreatePHPUser(phpUserID, nickname string, phpStatus int) error {
	if !bm.IsEnabled() {
		return fmt.Errorf("bridge not enabled")
	}

	// Sanitize nickname
	nickname = SanitizeNickname(nickname)
	if nickname == "" {
		return fmt.Errorf("invalid nickname")
	}

	bm.userMappingsMu.Lock()
	defer bm.userMappingsMu.Unlock()

	// Check if user already exists
	if existingNick, exists := bm.phpToIRC[phpUserID]; exists {
		// Update existing user
		bm.phpUserStatus[phpUserID] = phpStatus
		bm.server.logger.Debug("bridge", "Updated PHP user", phpUserID, "→", existingNick, "status", phpStatus)
		return nil
	}

	// Determine IRC nick
	var ircNick string
	var isLinked bool

	// Check if linked account exists
	if linkedAccount, ok := bm.linkedAccounts[phpUserID]; ok {
		ircNick = linkedAccount
		isLinked = true
	} else {
		// Create web_ prefixed user
		ircNick = "web_" + nickname
		isLinked = false
	}

	// Store mappings
	cfNick, err := Casefold(ircNick)
	if err != nil {
		return fmt.Errorf("invalid nickname: %w", err)
	}

	bm.phpToIRC[phpUserID] = ircNick
	bm.ircToPHP[cfNick] = phpUserID
	bm.phpUserStatus[phpUserID] = phpStatus

	// Create pseudo-client if not linked (linked users already have clients)
	if !isLinked {
		go bm.createPseudoClient(ircNick, phpUserID, phpStatus)
	}

	bm.server.logger.Info("bridge", "Created PHP user", phpUserID, "→", ircNick, "status", phpStatus, "linked", isLinked)
	return nil
}

// createPseudoClient creates an always-on pseudo-client for a PHP user
func (bm *BridgeManager) createPseudoClient(ircNick, phpUserID string, phpStatus int) {
	config := bm.server.Config()

	// Ensure account doesn't already exist
	cfNick, err := Casefold(ircNick)
	if err != nil {
		bm.server.logger.Error("bridge", "Invalid nickname for pseudo-client", ircNick, err.Error())
		return
	}

	// Check if client already exists
	if bm.server.clients.Get(ircNick) != nil {
		bm.server.logger.Debug("bridge", "Pseudo-client already exists", ircNick)
		return
	}

	// Create client account
	account := ClientAccount{
		Name:           ircNick,
		NameCasefolded: cfNick,
		RegisteredAt:   time.Now().UTC(),
		Verified:       true,
	}

	// Create always-on client
	realname := fmt.Sprintf("PHP User (ID: %s)", phpUserID)
	channelToStatus := make(map[string]alwaysOnChannelStatus) // Empty initially
	lastSeen := make(map[string]time.Time)
	readMarkers := make(map[string]time.Time)
	uModes := modes.Modes{}

	// Add bot mode if configured
	if config.Server.Cloaks.EnabledForAlwaysOn {
		uModes = append(uModes, modes.Bot)
	}

	bm.server.AddAlwaysOnClient(
		account,
		channelToStatus,
		lastSeen,
		readMarkers,
		uModes,
		realname,
		nil,  // push subscriptions
		nil,  // metadata
	)

	bm.server.logger.Info("bridge", "Created pseudo-client", ircNick)
}

// RemovePHPUser removes a PHP user from IRC
func (bm *BridgeManager) RemovePHPUser(phpUserID, quitMessage string) {
	if !bm.IsEnabled() {
		return
	}

	bm.userMappingsMu.Lock()
	ircNick, exists := bm.phpToIRC[phpUserID]
	if !exists {
		bm.userMappingsMu.Unlock()
		return
	}

	cfNick, _ := Casefold(ircNick)
	delete(bm.phpToIRC, phpUserID)
	delete(bm.ircToPHP, cfNick)
	delete(bm.phpUserStatus, phpUserID)
	delete(bm.userChannels, phpUserID)
	bm.userMappingsMu.Unlock()

	// Destroy pseudo-client if web_ prefixed (not linked account)
	if strings.HasPrefix(ircNick, "web_") {
		client := bm.server.clients.Get(ircNick)
		if client != nil {
			client.Quit(quitMessage, nil)
			// TODO: Properly destroy always-on client
		}
	}

	bm.server.logger.Info("bridge", "Removed PHP user", phpUserID, "←", ircNick)
}

// UpdatePHPUserRoom updates the room/channel for a PHP user
func (bm *BridgeManager) UpdatePHPUserRoom(phpUserID, sendto string) error {
	if !bm.IsEnabled() {
		return fmt.Errorf("bridge not enabled")
	}

	bm.userMappingsMu.RLock()
	ircNick, exists := bm.phpToIRC[phpUserID]
	prevChannel := bm.userChannels[phpUserID]
	bm.userMappingsMu.RUnlock()

	if !exists {
		return fmt.Errorf("user not found")
	}

	client := bm.server.clients.Get(ircNick)
	if client == nil {
		return fmt.Errorf("client not found")
	}

	// Get new channel from mapping
	bm.mappingsMu.RLock()
	newChannel, mapped := bm.phpToChannel[sendto]
	bm.mappingsMu.RUnlock()

	// Part previous channel if exists
	if prevChannel != "" && prevChannel != newChannel {
		bm.server.channels.Part(client, prevChannel, "Changing rooms", nil)
	}

	// Join new channel if mapped
	if mapped && newChannel != "" {
		rb := NewResponseBuffer(nil) // No session for pseudo-client
		bm.server.channels.Join(client, newChannel, "", true, rb)

		bm.userMappingsMu.Lock()
		bm.userChannels[phpUserID] = newChannel
		bm.userMappingsMu.Unlock()

		bm.server.logger.Debug("bridge", "User", ircNick, "moved to", newChannel)
	}

	return nil
}

// ===== Message Relay =====

// SendPHPMessage sends a message from a PHP user to IRC
func (bm *BridgeManager) SendPHPMessage(phpUserID, text string, isAction, isPM bool, targetUser string) error {
	if !bm.IsEnabled() {
		return fmt.Errorf("bridge not enabled")
	}

	bm.userMappingsMu.RLock()
	ircNick, exists := bm.phpToIRC[phpUserID]
	currentChannel := bm.userChannels[phpUserID]
	bm.userMappingsMu.RUnlock()

	if !exists {
		return fmt.Errorf("user not found")
	}

	client := bm.server.clients.Get(ircNick)
	if client == nil {
		return fmt.Errorf("client not found")
	}

	if isPM {
		// Send private message
		target := bm.server.clients.Get(targetUser)
		if target == nil {
			return fmt.Errorf("target user not found")
		}

		// TODO: Send PM
		bm.server.logger.Debug("bridge", "PHP PM", ircNick, "→", targetUser, ":", text)
		return nil
	}

	// Send to channel
	if currentChannel == "" {
		return fmt.Errorf("user not in any channel")
	}

	channel := bm.server.channels.Get(currentChannel)
	if channel == nil {
		return fmt.Errorf("channel not found")
	}

	// Format message
	messageText := text
	if isAction {
		messageText = fmt.Sprintf("\x01ACTION %s\x01", text)
	}

	message := utils.MakeMessage(messageText)

	// Broadcast to channel
	rb := NewResponseBuffer(nil)
	channel.SendSplitMessage("PRIVMSG", modes.Mode(0), nil, client, message, rb)

	bm.server.logger.Debug("bridge", "PHP message", ircNick, "→", currentChannel, ":", text)
	return nil
}

// ===== Mapping Management =====

// GetChannelMapping returns the IRC channel for a PHP sendto
func (bm *BridgeManager) GetChannelMapping(sendto string) (string, bool) {
	bm.mappingsMu.RLock()
	defer bm.mappingsMu.RUnlock()
	channel, ok := bm.phpToChannel[sendto]
	return channel, ok
}

// GetPHPMapping returns the PHP sendto for an IRC channel
func (bm *BridgeManager) GetPHPMapping(channelName string) (string, bool) {
	cfChannel, err := CasefoldChannel(channelName)
	if err != nil {
		return "", false
	}

	bm.mappingsMu.RLock()
	defer bm.mappingsMu.RUnlock()
	sendto, ok := bm.channelToPHP[cfChannel]
	return sendto, ok
}

// UpdateMapping updates a room/channel mapping
func (bm *BridgeManager) UpdateMapping(sendto, channelName string) error {
	cfChannel, err := CasefoldChannel(channelName)
	if err != nil {
		return err
	}

	bm.mappingsMu.Lock()
	defer bm.mappingsMu.Unlock()

	bm.phpToChannel[sendto] = channelName
	bm.channelToPHP[cfChannel] = sendto

	bm.server.logger.Info("bridge", "Updated mapping", sendto, "→", channelName)
	return nil
}

// ===== Authority & Moderation =====

// GetEffectiveRank returns the effective authority rank for a user
// Returns: 0-8 for PHP status, 4 for IRC operator, 1 for guest
func (bm *BridgeManager) GetEffectiveRank(nickname string) int {
	cfNick, err := Casefold(nickname)
	if err != nil {
		return 1 // Guest
	}

	// Check if PHP user
	bm.userMappingsMu.RLock()
	if phpUserID, ok := bm.ircToPHP[cfNick]; ok {
		status := bm.phpUserStatus[phpUserID]
		bm.userMappingsMu.RUnlock()
		return status
	}
	bm.userMappingsMu.RUnlock()

	// Check if IRC operator
	client := bm.server.clients.Get(nickname)
	if client != nil && client.HasMode(modes.Oper) {
		return 4 // Between PHP status 3 and 5
	}

	return 1 // Guest
}

// CheckModerationAuthority checks if actor can moderate target
// Returns: allowed, reason
func (bm *BridgeManager) CheckModerationAuthority(actorNick, targetNick string) (bool, string) {
	actorRank := bm.GetEffectiveRank(actorNick)
	targetRank := bm.GetEffectiveRank(targetNick)

	if actorRank <= targetRank {
		return false, fmt.Sprintf("Target has equal or higher authority (actor: %d, target: %d)", actorRank, targetRank)
	}

	return true, ""
}

// ===== Utility Methods =====

// IsPHPUser checks if a nickname belongs to a PHP user
func (bm *BridgeManager) IsPHPUser(nickname string) bool {
	cfNick, err := Casefold(nickname)
	if err != nil {
		return false
	}

	bm.userMappingsMu.RLock()
	defer bm.userMappingsMu.RUnlock()
	_, ok := bm.ircToPHP[cfNick]
	return ok
}

// IsEventFromBridge checks if a client's event originated from the bridge
func (bm *BridgeManager) IsEventFromBridge(client *Client) bool {
	return bm.IsPHPUser(client.Nick())
}

// HasSeenEvent checks if an event ID has been seen recently
func (bm *BridgeManager) HasSeenEvent(eventID string) bool {
	bm.seenEventsMu.RLock()
	defer bm.seenEventsMu.RUnlock()
	return bm.seenEvents.Contains(eventID)
}

// MarkEventSeen marks an event ID as seen
func (bm *BridgeManager) MarkEventSeen(eventID string) {
	bm.seenEventsMu.Lock()
	defer bm.seenEventsMu.Unlock()
	bm.seenEvents.Add(eventID)
}

// HasSeenNonce checks if a nonce has been used before
func (bm *BridgeManager) HasSeenNonce(nonce string) bool {
	bm.seenNoncesMu.RLock()
	_, seen := bm.seenNonces[nonce]
	bm.seenNoncesMu.RUnlock()
	return seen
}

// MarkNonceSeen marks a nonce as seen
func (bm *BridgeManager) MarkNonceSeen(nonce string) {
	bm.seenNoncesMu.Lock()
	bm.seenNonces[nonce] = time.Now().Unix()
	bm.seenNoncesMu.Unlock()

	// Cleanup old nonces (older than MaxTimestampSkew)
	go bm.cleanupOldNonces()
}

// cleanupOldNonces removes nonces older than the max timestamp skew
func (bm *BridgeManager) cleanupOldNonces() {
	cutoff := time.Now().Add(-MaxTimestampSkew).Unix()

	bm.seenNoncesMu.Lock()
	for nonce, ts := range bm.seenNonces {
		if ts < cutoff {
			delete(bm.seenNonces, nonce)
		}
	}
	bm.seenNoncesMu.Unlock()
}
