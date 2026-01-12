// Copyright (c) 2026 Ergo IRC
// released under the MIT license

package irc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ergochat/ergo/irc/utils"
)

const (
	// PHP endpoints (fixed URLs from requirements)
	phpChatURL      = "https://4-0-4.io/chat/min/chat.php?bridge=1"
	phpNicerChatURL = "https://4-0-4.io/chat/min/nicer_chat.php?bridge=1"

	// HTTP timeout for outbound requests
	phpRequestTimeout = 10 * time.Second
)

// OutboundEvent represents an event being sent from IRC to PHP
type OutboundEvent struct {
	Type            BridgeMessageType      `json:"type"`
	ProtocolVersion string                 `json:"protocol_version"`
	Timestamp       int64                  `json:"ts"`
	Nonce           string                 `json:"nonce"`
	EventID         string                 `json:"event_id"`
	Origin          string                 `json:"origin"`
	RelayTag        string                 `json:"relay_tag"`
	Payload         map[string]interface{} `json:"payload"`
	HMAC            string                 `json:"hmac"`
}

// computeOutboundHMAC computes the HMAC signature for an outbound event
func computeOutboundHMAC(event *OutboundEvent, authKey string) (string, error) {
	// Serialize payload
	payloadJSON, err := json.Marshal(event.Payload)
	if err != nil {
		return "", err
	}

	// Sign: type|ts|nonce|payload
	signData := fmt.Sprintf("%s|%d|%s|%s", event.Type, event.Timestamp, event.Nonce, string(payloadJSON))

	h := hmac.New(sha256.New, []byte(authKey))
	h.Write([]byte(signData))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sendToPHP sends an event to both PHP endpoints
func (bm *BridgeManager) sendToPHP(eventType BridgeMessageType, payload map[string]interface{}) error {
	if !bm.IsEnabled() {
		return fmt.Errorf("bridge not enabled")
	}

	config := bm.config.Load()
	if config == nil {
		return fmt.Errorf("bridge config not loaded")
	}

	// Generate event ID and nonce
	eventID := fmt.Sprintf("%s", utils.GenerateUUIDv4())
	nonce := utils.GenerateSecretToken()

	// Check if we've already seen this event (loop prevention)
	if bm.HasSeenEvent(eventID) {
		bm.server.logger.Debug("bridge", "Skipping duplicate event", eventID)
		return nil
	}
	bm.MarkEventSeen(eventID)

	// Build event
	event := &OutboundEvent{
		Type:            eventType,
		ProtocolVersion: BridgeProtocolVersion,
		Timestamp:       time.Now().Unix(),
		Nonce:           nonce,
		EventID:         eventID,
		Origin:          "irc",
		RelayTag:        "ergo-bridge",
		Payload:         payload,
	}

	// Compute HMAC
	signature, err := computeOutboundHMAC(event, config.AuthKey)
	if err != nil {
		return fmt.Errorf("failed to compute HMAC: %w", err)
	}
	event.HMAC = signature

	// Serialize event
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to serialize event: %w", err)
	}

	// Send to both PHP endpoints in parallel
	errChan := make(chan error, 2)

	go func() {
		errChan <- bm.postToEndpoint(phpChatURL, eventJSON)
	}()

	go func() {
		errChan <- bm.postToEndpoint(phpNicerChatURL, eventJSON)
	}()

	// Wait for both to complete
	err1 := <-errChan
	err2 := <-errChan

	// Log errors but don't fail if one succeeds
	if err1 != nil {
		bm.server.logger.Warning("bridge", "Failed to send to chat.php:", err1.Error())
	}
	if err2 != nil {
		bm.server.logger.Warning("bridge", "Failed to send to nicer_chat.php:", err2.Error())
	}

	if err1 != nil && err2 != nil {
		return fmt.Errorf("failed to send to both PHP endpoints")
	}

	return nil
}

// postToEndpoint posts an event to a single PHP endpoint
func (bm *BridgeManager) postToEndpoint(url string, eventJSON []byte) error {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: phpRequestTimeout,
	}

	// Create request
	req, err := http.NewRequest("POST", url, bytes.NewReader(eventJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Ergo-Bridge/1.0")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PHP endpoint returned status %d", resp.StatusCode)
	}

	// Parse response
	var bridgeResp BridgeResponse
	if err := json.NewDecoder(resp.Body).Decode(&bridgeResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Check response
	if !bridgeResp.OK {
		return fmt.Errorf("PHP endpoint returned error: %s (%s)", bridgeResp.Error, bridgeResp.ErrorCode)
	}

	bm.server.logger.Debug("bridge", "Successfully sent event to", url)
	return nil
}

// NotifyPHPUserJoin notifies PHP that an IRC user joined a mapped channel
func (bm *BridgeManager) NotifyPHPUserJoin(nickname, channelName string) error {
	sendto, ok := bm.GetPHPMapping(channelName)
	if !ok {
		return fmt.Errorf("channel not mapped")
	}

	payload := map[string]interface{}{
		"nickname": nickname,
		"sendto":   sendto,
	}

	return bm.sendToPHP(MsgTypeIRCUserJoin, payload)
}

// NotifyPHPUserLeave notifies PHP that an IRC user left a mapped channel
func (bm *BridgeManager) NotifyPHPUserLeave(nickname, channelName string) error {
	sendto, ok := bm.GetPHPMapping(channelName)
	if !ok {
		return fmt.Errorf("channel not mapped")
	}

	payload := map[string]interface{}{
		"nickname": nickname,
		"sendto":   sendto,
	}

	return bm.sendToPHP(MsgTypeIRCUserLeave, payload)
}

// NotifyPHPMessage notifies PHP of a message from IRC
func (bm *BridgeManager) NotifyPHPMessage(nickname, channelName, text string, isAction, isPM bool, toUser string) error {
	var sendto string
	if !isPM {
		var ok bool
		sendto, ok = bm.GetPHPMapping(channelName)
		if !ok {
			return fmt.Errorf("channel not mapped")
		}
	}

	payload := map[string]interface{}{
		"nickname":  nickname,
		"sendto":    sendto,
		"text":      text,
		"is_action": isAction,
		"is_pm":     isPM,
	}

	if isPM && toUser != "" {
		payload["to_user"] = toUser
	}

	return bm.sendToPHP(MsgTypeIRCMessage, payload)
}

// NotifyPHPModAction notifies PHP of a moderation action
func (bm *BridgeManager) NotifyPHPModAction(action, actorNick, targetNick, channelName, reason string) error {
	sendto, ok := bm.GetPHPMapping(channelName)
	if !ok {
		return fmt.Errorf("channel not mapped")
	}

	payload := map[string]interface{}{
		"action":         action,
		"actor_nick":     actorNick,
		"target_nick":    targetNick,
		"context_sendto": sendto,
		"reason":         reason,
	}

	return bm.sendToPHP(MsgTypeIRCModAction, payload)
}

// NotifyPHPMappingUpdate notifies PHP of a mapping change
func (bm *BridgeManager) NotifyPHPMappingUpdate(sendto, channelName string) error {
	payload := map[string]interface{}{
		"sendto":  sendto,
		"channel": channelName,
	}

	return bm.sendToPHP(MsgTypeIRCMappingUpdate, payload)
}

// NotifyLinkComplete notifies PHP that account linking completed
func (bm *BridgeManager) NotifyLinkComplete(phpUserID, ircAccount string, success bool) {
	payload := map[string]interface{}{
		"php_user_id": phpUserID,
		"irc_account": ircAccount,
		"success":     success,
	}

	if success {
		payload["message"] = "Account linking completed successfully"
	} else {
		payload["message"] = "Account linking failed"
	}

	// Best-effort notification
	if err := bm.sendToPHP(MsgTypeLinkComplete, payload); err != nil {
		bm.server.logger.Warning("bridge", "Failed to notify PHP of link completion:", err.Error())
	}
}
