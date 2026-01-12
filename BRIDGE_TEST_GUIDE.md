# IRC-PHP Bridge Test & Verification Guide

## Pre-Test Setup

### 1. Configure Ergo IRC Server

Edit `/home/dasho/dev/ergo/default.yaml`:

```yaml
bridge:
    enabled: true
    listen-address: "127.0.0.1:6666"
    auth-key: "test-secret-key-12345"  # Use a strong secret in production
    allowed-ips:
        - "127.0.0.1"
        - "::1"
    connection-limit: 10
    request-rate-limit: 0
    link-token-expiry: 15m
    default-mappings:
        "room": "#main"
        "s 31": "#members"
        "s 48": "#staff"
        "s 58": "#admin"
```

### 2. Configure PHP Chat

**Option A: Via Admin Panel (Recommended)**
1. Access chat as admin (status >= 6)
2. Go to Setup page
3. Scroll to "IRC Bridge Settings"
4. Set:
   - Bridge Enabled: Enabled
   - IRC Endpoint: `http://localhost:6666/bridge`
   - Auth Key: `test-secret-key-12345` (must match Ergo)
   - Replay Window: 300
5. Click Apply

**Option B: Direct Database**
```sql
-- Connect to your chat database
USE your_chat_database;

-- Update bridge settings
INSERT INTO bridge_settings (setting, value) VALUES ('enabled', '1')
  ON DUPLICATE KEY UPDATE value = '1';
INSERT INTO bridge_settings (setting, value) VALUES ('irc_endpoint', 'http://localhost:6666/bridge')
  ON DUPLICATE KEY UPDATE value = 'http://localhost:6666/bridge';
INSERT INTO bridge_settings (setting, value) VALUES ('auth_key', 'test-secret-key-12345')
  ON DUPLICATE KEY UPDATE value = 'test-secret-key-12345';
INSERT INTO bridge_settings (setting, value) VALUES ('replay_window', '300')
  ON DUPLICATE KEY UPDATE value = '300';
```

### 3. Start Services

```bash
# Terminal 1: Start Ergo
cd /home/dasho/dev/ergo
./ergo run

# Terminal 2: Monitor Ergo logs
tail -f ircd.log

# Terminal 3: Monitor PHP error log
tail -f /var/log/php_errors.log  # Or wherever PHP logs are
```

## Test Cases

### Test 1: IRC → PHP Message Flow

**Objective**: Verify IRC messages appear in PHP chat

**Steps**:
1. Connect to IRC: `irc://localhost:6667`
2. Join #main: `/join #main`
3. Send message: `Hello from IRC!`
4. Open PHP chat in browser
5. Verify message appears from `irc_yournick`

**Expected Result**:
- ✅ IRC user appears as `irc_yournick` in PHP chat
- ✅ Message "Hello from IRC!" visible in PHP chat
- ✅ No errors in Ergo or PHP logs

**Troubleshooting**:
- Check Ergo log for bridge POST to PHP
- Check PHP error log for receiver endpoint
- Verify HMAC keys match
- Check bridge_audit table for event log

### Test 2: PHP → IRC Message Flow

**Objective**: Verify PHP messages appear in IRC

**Steps**:
1. Keep IRC client connected to #main
2. Log into PHP chat as regular user
3. Send message in PHP: `Hello from PHP!`
4. Check IRC client

**Expected Result**:
- ✅ PHP user appears as `web_yourname` in IRC #main
- ✅ Message "Hello from PHP!" visible in IRC
- ✅ No errors in logs

**Troubleshooting**:
- Check PHP error log for IRC POST
- Verify fsockopen() not blocked
- Check IRC bridge listener is running
- Verify destination mapping exists

### Test 3: /me Actions

**Objective**: Verify CTCP ACTION handling

**IRC Side**:
```
/me waves at everyone
```

**PHP Side**:
Type `/me` in PHP chat (if supported) or check if IRC /me appears as italic

**Expected Result**:
- ✅ IRC `/me` appears as formatted action in PHP
- ✅ PHP action appears as `/me` in IRC

### Test 4: User Join/Part Events

**Objective**: Verify presence synchronization

**Steps**:
1. Join IRC #main
2. Check PHP chat user list → Should see `irc_yournick`
3. Part IRC #main: `/part #main`
4. Check PHP chat → `irc_yournick` should disappear
5. Login to PHP chat
6. Check IRC #main → Should see `web_yourname` join
7. Logout from PHP
8. Check IRC #main → Should see `web_yourname` part

**Expected Result**:
- ✅ All join/part events synchronized
- ✅ Virtual users created/removed correctly

### Test 5: Kick/Ban Events

**Objective**: Verify moderation actions sync

**Steps**:
1. As IRC operator: `/kick #main web_testuser Spam`
2. Check PHP chat → `testuser` should be kicked
3. As PHP moderator: Kick `irc_testuser`
4. Check IRC → `irc_testuser` should be kicked from channel

**Expected Result**:
- ✅ IRC kicks affect PHP users
- ✅ PHP kicks affect IRC users
- ✅ Kick reasons preserved

### Test 6: Account Linking

**Objective**: Verify token-based linking works

**Steps**:
1. In PHP chat profile, request link token (once UI is added)
2. Note the token (e.g., `abc123`)
3. In IRC, register nick: `/msg NickServ REGISTER password email@test.com`
4. Identify: `/msg NickServ IDENTIFY password`
5. Link: `/msg NickServ LINK abc123`
6. Check database:
```sql
SELECT * FROM account_links WHERE php_user_id = YOUR_USER_ID;
```

**Expected Result**:
- ✅ Token validated successfully
- ✅ Link stored in account_links table
- ✅ Confirmation messages sent
- ✅ Link completion notification to PHP

### Test 7: Loop Prevention

**Objective**: Ensure messages don't echo infinitely

**Steps**:
1. Send message from IRC
2. Verify it appears in PHP once
3. Check it doesn't echo back to IRC
4. Send message from PHP
5. Verify it appears in IRC once
6. Check it doesn't echo back to PHP

**Expected Result**:
- ✅ Each message appears exactly once on each side
- ✅ No infinite loops
- ✅ Event IDs tracked in seenEvents

### Test 8: HMAC Authentication

**Objective**: Verify security measures work

**Test Invalid HMAC**:
```bash
# Send malformed request to PHP bridge
curl -X POST "http://localhost/chat.php?bridge=1" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "message",
    "timestamp": '$(date +%s)',
    "nonce": "test123",
    "irc_nick": "hacker",
    "message": "This should fail",
    "destination": "room",
    "hmac": "invalid_hmac_here"
  }'
```

**Expected Result**:
- ✅ Request rejected with 401 Unauthorized
- ✅ Error logged in bridge_audit table
- ✅ Message does not appear in chat

### Test 9: Replay Protection

**Objective**: Verify timestamp and nonce validation

**Test Old Timestamp**:
```bash
# Send request with timestamp from 10 minutes ago
curl -X POST "http://localhost/chat.php?bridge=1" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "message",
    "timestamp": '$(( $(date +%s) - 600 ))',
    "nonce": "test456",
    "irc_nick": "olduser",
    "message": "Old timestamp",
    "destination": "room",
    "hmac": "..."
  }'
```

**Expected Result**:
- ✅ Request rejected (timestamp too old)
- ✅ Logged as replay attempt

**Test Duplicate Nonce**:
1. Send valid request with nonce "xyz789"
2. Send same request again with same nonce
3. Second request should be rejected

**Expected Result**:
- ✅ First request succeeds
- ✅ Second request rejected (nonce already used)

### Test 10: Username Validation

**Objective**: Verify reserved prefixes are blocked

**Steps**:
1. Try to register in PHP chat with username `irc_test`
2. Try to register with username `web_test`
3. Try normal username like `alice`

**Expected Result**:
- ❌ `irc_test` rejected (reserved prefix)
- ❌ `web_test` rejected (reserved prefix)
- ✅ `alice` accepted

### Test 11: Channel Mapping

**Objective**: Verify destination↔channel mapping works

**Steps**:
1. Check default mappings in database:
```sql
SELECT * FROM bridge_mappings;
```
2. Verify messages in different destinations go to correct IRC channels
3. Test unmapped destinations are ignored

**Expected Result**:
- ✅ "room" → #main
- ✅ "s 31" → #members
- ✅ "s 48" → #staff
- ✅ "s 58" → #admin
- ✅ Unmapped destinations don't bridge

### Test 12: Long Messages

**Objective**: Test IRC 512-byte limit handling

**Steps**:
1. Send 1000-character message from PHP
2. Check how it appears in IRC (should be truncated)
3. Send 500-character message from IRC
4. Check how it appears in PHP (should be complete)

**Expected Behavior**:
- PHP→IRC: May be truncated to ~400 chars (leaving room for protocol)
- IRC→PHP: Complete message preserved

### Test 13: Special Characters

**Objective**: Verify encoding/escaping works

**Test Strings**:
- `<script>alert('xss')</script>`
- `'; DROP TABLE messages; --`
- Emoji: 🎉🚀💬
- Unicode: 你好世界
- HTML entities: `&lt;&gt;&amp;`

**Expected Result**:
- ✅ No XSS vulnerabilities
- ✅ No SQL injection
- ✅ Emoji/Unicode preserved
- ✅ HTML properly escaped

## Monitoring & Debugging

### Check Bridge Status

**Ergo Logs**:
```bash
grep -i bridge ircd.log | tail -20
```

**PHP Error Log**:
```bash
grep -i bridge /var/log/php_errors.log | tail -20
```

**Bridge Audit Log**:
```sql
SELECT * FROM bridge_audit ORDER BY timestamp DESC LIMIT 20;
```

### Verify Bridge is Running

**Check IRC Listener**:
```bash
netstat -an | grep 6666
# Should show LISTEN on 127.0.0.1:6666
```

**Test IRC Endpoint**:
```bash
curl -X POST http://localhost:6666/bridge \
  -H "Content-Type: application/json" \
  -d '{"test": "ping"}'
# Should return JSON (may be error, but should respond)
```

**Test PHP Endpoint**:
```bash
curl http://localhost/chat.php?bridge=1
# Should return JSON error (bridge disabled or missing data)
```

### Common Issues

**Issue**: Messages not appearing
- Check bridge enabled in both systems
- Verify auth keys match exactly
- Check firewalls/network connectivity
- Review logs for errors

**Issue**: "HMAC verification failed"
- Auth keys don't match
- Check for trailing whitespace in keys
- Verify JSON serialization order

**Issue**: "Duplicate nonce"
- Clock skew between systems
- Nonce cleanup not running
- Check system time on both servers

**Issue**: Loop of messages
- Event ID tracking not working
- Check IsPHPUser() and similar checks
- Verify prefix detection working

## Performance Monitoring

### Expected Performance
- Bridge adds ~5-10ms latency per message
- Async operations don't block chat
- HMAC computation < 1ms
- Nonce lookup < 1ms

### Monitor Resource Usage
```bash
# Check Ergo memory
ps aux | grep ergo

# Check PHP-FPM
ps aux | grep php-fpm

# Check database connections
mysql -e "SHOW PROCESSLIST;"
```

## Success Criteria

All tests should pass with:
- ✅ No errors in logs
- ✅ Messages appear within 1 second
- ✅ No message loss
- ✅ No infinite loops
- ✅ Security checks block invalid requests
- ✅ Resource usage reasonable

## Optional Advanced Tests

### Stress Test
- 100 users sending messages simultaneously
- Verify no message loss or loops
- Check performance degradation

### Network Failure Recovery
- Stop/start Ergo while PHP running
- Stop/start PHP while Ergo running
- Verify graceful handling

### Concurrent Operations
- Multiple users joining simultaneously
- Mass kick/ban operations
- Rapid message bursts

## Cleanup After Testing

```sql
-- Clear test data
TRUNCATE TABLE bridge_audit;
TRUNCATE TABLE bridge_nonces;
DELETE FROM sessions WHERE nickname LIKE 'irc_%';
DELETE FROM sessions WHERE nickname LIKE 'web_%';
```

```bash
# Restart services
./ergo rehash
# Restart PHP-FPM (varies by system)
```
