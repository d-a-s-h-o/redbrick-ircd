// Copyright (c) 2026 Ergo IRC
// released under the MIT license

package irc

import (
	"strings"
)

// Bridge event hooks - called from IRC handlers to notify PHP

// onChannelJoin is called when a user joins a channel
func (server *Server) onChannelJoin(client *Client, channelName string) {
	if server.bridge == nil || !server.bridge.IsEnabled() {
		return
	}

	// Skip if this is a PHP user (web_ prefix) to prevent loops
	if server.bridge.IsPHPUser(client.Nick()) {
		return
	}

	// Check if channel is mapped
	if _, mapped := server.bridge.GetPHPMapping(channelName); !mapped {
		return
	}

	// Notify PHP asynchronously
	go func() {
		nick := client.Nick()
		if err := server.bridge.NotifyPHPUserJoin(nick, channelName); err != nil {
			server.logger.Debug("bridge", "Failed to notify PHP of join:", nick, channelName, err.Error())
		}
	}()
}

// onChannelPart is called when a user parts a channel
func (server *Server) onChannelPart(client *Client, channelName string) {
	if server.bridge == nil || !server.bridge.IsEnabled() {
		return
	}

	// Skip if this is a PHP user
	if server.bridge.IsPHPUser(client.Nick()) {
		return
	}

	// Check if channel is mapped
	if _, mapped := server.bridge.GetPHPMapping(channelName); !mapped {
		return
	}

	// Notify PHP asynchronously
	go func() {
		nick := client.Nick()
		if err := server.bridge.NotifyPHPUserLeave(nick, channelName); err != nil {
			server.logger.Debug("bridge", "Failed to notify PHP of part:", nick, channelName, err.Error())
		}
	}()
}

// onChannelQuit is called when a user quits (disconnects), for each channel they were in
func (server *Server) onChannelQuit(client *Client, channelName string) {
	if server.bridge == nil || !server.bridge.IsEnabled() {
		return
	}

	// Skip if this is a PHP user
	if server.bridge.IsPHPUser(client.Nick()) {
		return
	}

	// Check if channel is mapped
	if _, mapped := server.bridge.GetPHPMapping(channelName); !mapped {
		return
	}

	// Notify PHP asynchronously
	go func() {
		nick := client.Nick()
		if err := server.bridge.NotifyPHPUserLeave(nick, channelName); err != nil {
			server.logger.Debug("bridge", "Failed to notify PHP of quit:", nick, channelName, err.Error())
		}
	}()
}

// onChannelMessage is called when a message is sent to a channel
func (server *Server) onChannelMessage(client *Client, channelName, message string, isAction bool) {
	if server.bridge == nil || !server.bridge.IsEnabled() {
		return
	}

	// Skip if this is a PHP user
	if server.bridge.IsPHPUser(client.Nick()) {
		return
	}

	// Check if channel is mapped
	if _, mapped := server.bridge.GetPHPMapping(channelName); !mapped {
		return
	}

	// Notify PHP asynchronously
	go func() {
		nick := client.Nick()
		if err := server.bridge.NotifyPHPMessage(nick, channelName, message, isAction, false, ""); err != nil {
			server.logger.Debug("bridge", "Failed to notify PHP of message:", nick, channelName, err.Error())
		}
	}()
}

// onPrivateMessage is called when a PM is sent between users
func (server *Server) onPrivateMessage(client *Client, targetNick, message string, isAction bool) {
	if server.bridge == nil || !server.bridge.IsEnabled() {
		return
	}

	// Skip if sender is a PHP user
	if server.bridge.IsPHPUser(client.Nick()) {
		return
	}

	// Only relay if target is a PHP user (web_ prefix)
	if !server.bridge.IsPHPUser(targetNick) {
		return
	}

	// Notify PHP asynchronously
	go func() {
		nick := client.Nick()
		if err := server.bridge.NotifyPHPMessage(nick, "", message, isAction, true, targetNick); err != nil {
			server.logger.Debug("bridge", "Failed to notify PHP of PM:", nick, "->", targetNick, err.Error())
		}
	}()
}

// onChannelKick is called when a user is kicked from a channel
func (server *Server) onChannelKick(kicker *Client, target *Client, channelName, reason string) {
	if server.bridge == nil || !server.bridge.IsEnabled() {
		return
	}

	// Check if channel is mapped
	if _, mapped := server.bridge.GetPHPMapping(channelName); !mapped {
		return
	}

	// Check authority precedence - don't relay if action violates precedence
	kickerNick := kicker.Nick()
	targetNick := target.Nick()

	allowed, authReason := server.bridge.CheckModerationAuthority(kickerNick, targetNick)
	if !allowed {
		server.logger.Debug("bridge", "Kick blocked by authority precedence:", authReason)
		// Still notify PHP for awareness, but mark as rejected
		return
	}

	// Notify PHP asynchronously
	go func() {
		if err := server.bridge.NotifyPHPModAction("kick", kickerNick, targetNick, channelName, reason); err != nil {
			server.logger.Debug("bridge", "Failed to notify PHP of kick:", kickerNick, "kicked", targetNick, err.Error())
		}
	}()
}

// onChannelBan is called when a ban is set on a channel
func (server *Server) onChannelBan(setter *Client, channelName, banMask string, add bool) {
	if server.bridge == nil || !server.bridge.IsEnabled() {
		return
	}

	// Check if channel is mapped
	if _, mapped := server.bridge.GetPHPMapping(channelName); !mapped {
		return
	}

	// Notify PHP asynchronously
	go func() {
		action := "ban"
		if !add {
			action = "unban"
		}
		setterNick := setter.Nick()
		if err := server.bridge.NotifyPHPModAction(action, setterNick, banMask, channelName, ""); err != nil {
			server.logger.Debug("bridge", "Failed to notify PHP of ban:", action, banMask, err.Error())
		}
	}()
}

// Helper function to detect CTCP ACTION (/me)
func isActionMessage(message string) bool {
	return strings.HasPrefix(message, "\x01ACTION ") && strings.HasSuffix(message, "\x01")
}

// Helper function to extract action text from CTCP ACTION
func extractActionText(message string) string {
	if !isActionMessage(message) {
		return message
	}
	// Remove \x01ACTION prefix and \x01 suffix
	text := strings.TrimPrefix(message, "\x01ACTION ")
	text = strings.TrimSuffix(text, "\x01")
	return text
}
