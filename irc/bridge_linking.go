// Copyright (c) 2026 Ergo IRC
// released under the MIT license

package irc

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// LinkToken represents a pending account link
type LinkToken struct {
	Token      string
	PHPUserID  string
	IRCName    string    // IRC account name requested (may not match final account)
	IRCAccount string    // Actual IRC account that claimed the token
	Expiry     time.Time
	Used       bool
	Completed  bool
	CreatedAt  time.Time
}

// LinkingManager manages account linking tokens
type LinkingManager struct {
	tokens   map[string]*LinkToken // token → LinkToken
	byPHPID  map[string]*LinkToken // PHP user ID → pending LinkToken
	mu       sync.RWMutex
	expiry   time.Duration
	cleanupT *time.Ticker
	stopChan chan struct{}
}

// NewLinkingManager creates a new linking manager
func NewLinkingManager(expiry time.Duration) *LinkingManager {
	lm := &LinkingManager{
		tokens:   make(map[string]*LinkToken),
		byPHPID:  make(map[string]*LinkToken),
		expiry:   expiry,
		stopChan: make(chan struct{}),
	}

	// Start cleanup goroutine
	lm.cleanupT = time.NewTicker(5 * time.Minute)
	go lm.cleanupLoop()

	return lm
}

// Stop stops the linking manager
func (lm *LinkingManager) Stop() {
	close(lm.stopChan)
	lm.cleanupT.Stop()
}

// cleanupLoop periodically removes expired tokens
func (lm *LinkingManager) cleanupLoop() {
	for {
		select {
		case <-lm.cleanupT.C:
			lm.cleanupExpired()
		case <-lm.stopChan:
			return
		}
	}
}

// cleanupExpired removes expired tokens
func (lm *LinkingManager) cleanupExpired() {
	now := time.Now()

	lm.mu.Lock()
	defer lm.mu.Unlock()

	for token, lt := range lm.tokens {
		if now.After(lt.Expiry) {
			delete(lm.tokens, token)
			if !lt.Used {
				delete(lm.byPHPID, lt.PHPUserID)
			}
		}
	}
}

// CreateToken creates a new linking token
func (lm *LinkingManager) CreateToken(phpUserID, ircName string) (token string, expiry time.Time, err error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check if there's already a pending token for this PHP user
	if existing, ok := lm.byPHPID[phpUserID]; ok {
		if !existing.Used && time.Now().Before(existing.Expiry) {
			// Return existing valid token
			return existing.Token, existing.Expiry, nil
		}
		// Clean up old token
		delete(lm.tokens, existing.Token)
		delete(lm.byPHPID, phpUserID)
	}

	// Generate secure random token
	token, err = generateLinkToken()
	if err != nil {
		return "", time.Time{}, err
	}

	expiry = time.Now().Add(lm.expiry)

	lt := &LinkToken{
		Token:     token,
		PHPUserID: phpUserID,
		IRCName:   ircName,
		Expiry:    expiry,
		Used:      false,
		Completed: false,
		CreatedAt: time.Now(),
	}

	lm.tokens[token] = lt
	lm.byPHPID[phpUserID] = lt

	return token, expiry, nil
}

// ValidateToken validates and consumes a token
func (lm *LinkingManager) ValidateToken(token, ircAccount string) (*LinkToken, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	lt, ok := lm.tokens[token]
	if !ok {
		return nil, fmt.Errorf("invalid token")
	}

	if time.Now().After(lt.Expiry) {
		return nil, fmt.Errorf("token expired")
	}

	if lt.Used {
		return nil, fmt.Errorf("token already used")
	}

	// Mark as used
	lt.Used = true
	lt.IRCAccount = ircAccount

	return lt, nil
}

// CompleteLink marks a link as completed
func (lm *LinkingManager) CompleteLink(token string, success bool) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	lt, ok := lm.tokens[token]
	if !ok {
		return fmt.Errorf("token not found")
	}

	lt.Completed = true

	// Remove from byPHPID to allow new link attempts
	delete(lm.byPHPID, lt.PHPUserID)

	// Keep the token for a while for status queries
	go func() {
		time.Sleep(1 * time.Hour)
		lm.mu.Lock()
		delete(lm.tokens, token)
		lm.mu.Unlock()
	}()

	return nil
}

// GetStatus returns the status of a link attempt for a PHP user
func (lm *LinkingManager) GetStatus(phpUserID string) (status string, token *LinkToken) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	lt, ok := lm.byPHPID[phpUserID]
	if !ok {
		// Check if there's a recently completed link
		for _, t := range lm.tokens {
			if t.PHPUserID == phpUserID && t.Completed {
				return "completed", t
			}
		}
		return "none", nil
	}

	if time.Now().After(lt.Expiry) {
		return "expired", lt
	}

	if lt.Completed {
		return "completed", lt
	}

	if lt.Used {
		return "claimed", lt
	}

	return "pending", lt
}

// generateLinkToken generates a secure random token
func generateLinkToken() (string, error) {
	// Generate 24 bytes (192 bits) of randomness
	b := make([]byte, 24)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	// Encode as URL-safe base64
	token := base64.RawURLEncoding.EncodeToString(b)
	return token, nil
}

// Add linking methods to BridgeManager

// StartAccountLinking initiates account linking
func (bm *BridgeManager) StartAccountLinking(phpUserID, ircName string) (token string, expiry time.Time, err error) {
	if bm.linkingManager == nil {
		return "", time.Time{}, fmt.Errorf("linking not enabled")
	}

	// Casefold IRC name
	cfName, err := Casefold(ircName)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("invalid IRC name: %w", err)
	}

	token, expiry, err = bm.linkingManager.CreateToken(phpUserID, cfName)
	if err != nil {
		return "", time.Time{}, err
	}

	bm.server.logger.Info("bridge", "Link token created for PHP user", phpUserID, "→ IRC", cfName, "token", token)

	return token, expiry, nil
}

// ValidateLinkToken validates a link token from IRC
func (bm *BridgeManager) ValidateLinkToken(token, ircAccount string) (*LinkToken, error) {
	if bm.linkingManager == nil {
		return nil, fmt.Errorf("linking not enabled")
	}

	// Casefold IRC account
	cfAccount, err := Casefold(ircAccount)
	if err != nil {
		return nil, fmt.Errorf("invalid IRC account: %w", err)
	}

	lt, err := bm.linkingManager.ValidateToken(token, cfAccount)
	if err != nil {
		return nil, err
	}

	return lt, nil
}

// CompleteLinking completes the linking process
func (bm *BridgeManager) CompleteLinking(phpUserID, ircAccount string) error {
	if bm.linkingManager == nil {
		return fmt.Errorf("linking not enabled")
	}

	cfAccount, err := Casefold(ircAccount)
	if err != nil {
		return fmt.Errorf("invalid IRC account: %w", err)
	}

	// Store the link
	bm.userMappingsMu.Lock()
	bm.linkedAccounts[phpUserID] = cfAccount
	bm.userMappingsMu.Unlock()

	bm.server.logger.Info("bridge", "Account linked: PHP user", phpUserID, "→ IRC account", cfAccount)

	// TODO: Persist to database

	return nil
}

// GetLinkingStatus returns the linking status for a PHP user
func (bm *BridgeManager) GetLinkingStatus(phpUserID string) string {
	// Check if already linked
	bm.userMappingsMu.RLock()
	if _, linked := bm.linkedAccounts[phpUserID]; linked {
		bm.userMappingsMu.RUnlock()
		return "linked"
	}
	bm.userMappingsMu.RUnlock()

	// Check pending link
	if bm.linkingManager != nil {
		status, _ := bm.linkingManager.GetStatus(phpUserID)
		return status
	}

	return "none"
}

// This method moved to bridge_outbound.go

// UnlinkAccount removes a link between PHP and IRC accounts
func (bm *BridgeManager) UnlinkAccount(phpUserID string) error {
	bm.userMappingsMu.Lock()
	defer bm.userMappingsMu.Unlock()

	if _, linked := bm.linkedAccounts[phpUserID]; !linked {
		return fmt.Errorf("account not linked")
	}

	delete(bm.linkedAccounts, phpUserID)

	bm.server.logger.Info("bridge", "Account unlinked: PHP user", phpUserID)

	// TODO: Persist to database

	return nil
}

// GetLinkedAccount returns the IRC account for a PHP user
func (bm *BridgeManager) GetLinkedAccount(phpUserID string) (string, bool) {
	bm.userMappingsMu.RLock()
	defer bm.userMappingsMu.RUnlock()

	account, ok := bm.linkedAccounts[phpUserID]
	return account, ok
}

// GetPHPUserForAccount returns the PHP user ID for an IRC account
func (bm *BridgeManager) GetPHPUserForAccount(ircAccount string) (string, bool) {
	cfAccount, err := Casefold(ircAccount)
	if err != nil {
		return "", false
	}

	bm.userMappingsMu.RLock()
	defer bm.userMappingsMu.RUnlock()

	for phpUserID, linkedAccount := range bm.linkedAccounts {
		if linkedAccount == cfAccount {
			return phpUserID, true
		}
	}

	return "", false
}
