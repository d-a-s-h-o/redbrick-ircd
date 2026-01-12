# IRC-PHP Bridge Implementation Status

## Implementation Complete ✅

### Ergo IRC Server (Go)
- ✅ Bridge Manager with HMAC-SHA256 auth and replay protection
- ✅ HTTP listener on port 6666 at `/bridge` endpoint
- ✅ Outbound HTTP POST client to notify PHP scripts
- ✅ NickServ LINK command for account linking
- ✅ IRC event hooks:
  - JOIN: channel.go:850
  - PART: channel.go:1026
  - QUIT: client.go:1426
  - PRIVMSG (with CTCP ACTION detection): handlers.go:2375, 2476
  - KICK: channel.go:1555
  - BAN/UNBAN: modes.go:233, 249
- ✅ Configuration in default.yaml

### PHP Chat Scripts (chat.php & nicer_chat.php)
- ✅ Database migrations (v2118):
  - bridge_settings
  - bridge_mappings
  - account_links
  - bridge_audit
  - bridge_nonces (in-memory)
- ✅ Bridge receiver endpoint (`?bridge=1`)
- ✅ HMAC signature verification
- ✅ Replay protection (timestamp + nonce)
- ✅ Username validation (reject irc_/web_ prefixes)
- ✅ Outbound notifications to IRC:
  - User join: write_new_session() - chat.php:6608, nicer_chat.php:6765
  - User leave: kill_session() - chat.php:6702, nicer_chat.php:6859
  - Messages: write_message() - chat.php:8240-8253, nicer_chat.php:8312-8325
  - Kicks: kick_chatter() - chat.php:6738, nicer_chat.php:6892
- ✅ Bridge settings UI in send_setup() - chat.php:1370-1403
- ✅ Bridge settings save in save_setup() - chat.php:9102-9117

## Remaining Tasks

### UI Components (In Progress)
- 🔄 Add bridge settings UI to nicer_chat.php send_setup()
- 🔄 Add bridge settings save to nicer_chat.php save_setup()
- ⏳ Account linking UI in send_profile() for both scripts
- ⏳ Channel mapping UI for both scripts

### Testing & Verification
- ⏳ Enable bridge in default.yaml
- ⏳ Set matching auth keys in Ergo and PHP
- ⏳ Test IRC→PHP: join/part/message/action/kick
- ⏳ Test PHP→IRC: join/leave/message/kick
- ⏳ Test account linking via NickServ LINK
- ⏳ Test loop prevention
- ⏳ Test HMAC verification
- ⏳ Test replay protection
- ⏳ Test mapping UI
- ⏳ Verify audit logging

## Configuration Required

### Ergo (default.yaml)
```yaml
bridge:
  enabled: true
  listen-address: "127.0.0.1:6666"
  auth-key: "your-secret-key-here"  # MUST match PHP
  allowed-ips:
    - "127.0.0.1"
  default-mappings:
    "room": "#main"
    "s 31": "#members"
    "s 48": "#staff"
    "s 58": "#admin"
```

### PHP (via Admin Panel)
1. Go to Setup page
2. Scroll to "IRC Bridge Settings"
3. Enable bridge
4. Set IRC Endpoint: `http://localhost:6666/bridge`
5. Set Auth Key (must match Ergo)
6. Set Replay Window: 300 seconds

Or directly in database:
```sql
INSERT INTO bridge_settings (setting, value) VALUES
  ('enabled', '1'),
  ('irc_endpoint', 'http://localhost:6666/bridge'),
  ('auth_key', 'your-secret-key-here'),
  ('replay_window', '300');
```

## Test Plan

### 1. Basic Connectivity
- [ ] Start Ergo IRC server
- [ ] Verify bridge listener on port 6666
- [ ] Check PHP can reach IRC endpoint
- [ ] Verify HMAC auth works

### 2. IRC → PHP Events
- [ ] IRC user joins #main → Appears as `irc_username` in PHP chat
- [ ] IRC user sends message → Message appears in PHP chat
- [ ] IRC user uses `/me` → Action formatted in PHP chat
- [ ] IRC user parts channel → Session removed from PHP
- [ ] IRC operator kicks PHP user → User kicked in PHP

### 3. PHP → IRC Events
- [ ] PHP user logs in → Appears as `web_username` in IRC
- [ ] PHP user sends message → Message appears in IRC
- [ ] PHP user logs out → Parts IRC channel
- [ ] PHP moderator kicks user → User kicked in IRC

### 4. Account Linking
- [ ] Generate link token in PHP
- [ ] `/msg NickServ LINK <token>` in IRC
- [ ] Verify link stored in account_links table
- [ ] Check linking notification sent to PHP

### 5. Loop Prevention
- [ ] IRC message → PHP → Should NOT echo back to IRC
- [ ] PHP message → IRC → Should NOT echo back to PHP
- [ ] Verify event IDs tracked in seenEvents

### 6. Security
- [ ] Invalid HMAC rejected
- [ ] Expired timestamp rejected
- [ ] Duplicate nonce rejected
- [ ] Unauthorized IP rejected (if configured)

### 7. Edge Cases
- [ ] Very long messages (>512 chars for IRC)
- [ ] Special characters in nicknames
- [ ] Multiple rapid joins/parts
- [ ] Network failures/timeouts
- [ ] Bridge disabled while running

## Known Limitations

1. **Room Mapping**: Currently hardcoded to main room - needs UI to configure
2. **Private Messages**: Not fully implemented
3. **Ban Synchronization**: IRC bans don't map to PHP IP bans
4. **Status Levels**: PHP status 10 used for IRC users

## Files Modified

### Go (17 files)
- irc/config.go
- irc/server.go
- irc/bridge.go
- irc/bridge_outbound.go
- irc/bridge_hooks.go
- irc/bridge_listener.go
- irc/bridge_linking.go
- irc/nickserv.go
- irc/channel.go
- irc/client.go
- irc/handlers.go
- irc/modes.go
- irc/help.go
- irc/numerics.go
- irc/commands.go
- default.yaml
- traditional.yaml

### PHP (2 files)
- chat.php (8 sections modified)
- nicer_chat.php (8 sections modified)

## Next Steps

1. Complete UI implementation for nicer_chat.php
2. Add account linking UI to send_profile()
3. Add channel mapping UI
4. Perform manual testing
5. Document any issues found
6. Create user guide for bridge usage
