<?php

// Error reporting enabled
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
ini_set('log_errors', 1);
ini_set('html_errors', 1);

/*
* status codes
* 0 - Kicked/Banned
* 1 - Guest
* 2 - Applicant
* 3 - Member
* 4 - System message
* 5 - Moderator
* 6 - Chat-Admin
* 7 - Service-Admin
* 8 - System-Admin
* 9 - Private messages
* 10 - Bot
*/

// Dasho (https://dasho.dev)

/**
 * BridgeClient - Handles communication with the IRC bridge
 */
class BridgeClient {
	private $socket = null;
	private $authKey = '';
	private $connected = false;

	public function __construct() {
		if (defined('BRIDGE_AUTH_KEY')) {
			$this->authKey = BRIDGE_AUTH_KEY;
		}
	}

	public function __destruct() {
		if ($this->socket) {
			fclose($this->socket);
		}
	}

	public function connect() {
		if (!BRIDGE_ENABLED || empty($this->authKey)) {
			return false;
		}

		$this->socket = @fsockopen(BRIDGE_HOST, BRIDGE_PORT, $errno, $errstr, 5);
		if (!$this->socket) {
			error_log("Bridge connection failed: $errstr ($errno)");
			return false;
		}

		stream_set_timeout($this->socket, 5);
		return $this->authenticate();
	}

	private function authenticate() {
		$request = $this->buildRequest('AUTH', []);
		$response = $this->send($request);

		if ($response && isset($response['type']) && $response['type'] === 'AUTH_OK') {
			$this->connected = true;
			return true;
		}

		return false;
	}

	private function buildRequest($type, $payload) {
		$ts = time();
		$nonce = bin2hex(random_bytes(16));

		$data = [
			'type' => $type,
			'protocol_version' => '1.0',
			'ts' => $ts,
			'nonce' => $nonce,
			'payload' => $payload,
		];

		// HMAC: hash(key, type|ts|nonce|json(payload))
		$payloadJson = json_encode($payload);
		$signData = "$type|$ts|$nonce|$payloadJson";
		$data['hmac'] = hash_hmac('sha256', $signData, $this->authKey);

		return json_encode($data);
	}

	public function notifyUserJoin($userID, $nickname, $status) {
		if (!$this->connected) return false;

		$request = $this->buildRequest('PHP_USER_JOIN', [
			'user_id' => (string)$userID,
			'nickname' => $nickname,
			'status' => (int)$status,
		]);

		return $this->send($request);
	}

	public function notifyUserLeave($userID) {
		if (!$this->connected) return false;

		$request = $this->buildRequest('PHP_USER_LEAVE', [
			'user_id' => (string)$userID,
		]);

		return $this->send($request);
	}

	public function notifyMessage($userID, $sendto, $text, $isAction = false, $isPM = false, $toUser = null) {
		if (!$this->connected) return false;

		$request = $this->buildRequest('PHP_MESSAGE', [
			'user_id' => (string)$userID,
			'sendto' => $sendto,
			'text' => $text,
			'is_action' => $isAction,
			'is_pm' => $isPM,
			'to_user' => $toUser,
		]);

		return $this->send($request);
	}

	public function notifyDestChange($userID, $oldDest, $newDest) {
		if (!$this->connected) return false;

		$request = $this->buildRequest('PHP_DEST_CHANGE', [
			'user_id' => (string)$userID,
			'old_dest' => $oldDest,
			'new_dest' => $newDest,
		]);

		return $this->send($request);
	}

	private function send($request) {
		if (!$this->socket) return false;

		fwrite($this->socket, $request . "\n");
		$response = fgets($this->socket);

		if ($response === false) {
			return false;
		}

		return json_decode($response, true);
	}

	public function isConnected() {
		return $this->connected;
	}
}

send_headers();
// initialize and load variables/configuration
$I = []; // Translations
$L = []; // Languages
$U = []; // This user data
$db; // Database connection
$memcached; // Memcached connection
$language; // user selected language
load_config();
// set session variable to cookie if cookies are enabled
if (!isset($_REQUEST['session']) && isset($_COOKIE[COOKIENAME])) {

	//Modification that prevents users from doing unwanted things (for example unintentionally deleting their account), if someone else posts a malicious link.
	// MODIFICATION added logout to list of unwanted things
	// MODIFICATION fixed: allow setup actions when they're legitimate POST requests or have 'do' parameter (admin operations)
	if (isset($_REQUEST['action']) && ($_REQUEST['action'] === 'profile' || $_REQUEST['action'] === 'post' || $_REQUEST['action'] === 'admin' || $_REQUEST['action'] === 'logout')) {
		$_REQUEST['action'] = 'login';
	} elseif (isset($_REQUEST['action']) && $_REQUEST['action'] === 'setup' && !isset($_REQUEST['do']) && $_SERVER['REQUEST_METHOD'] !== 'POST') {
		$_REQUEST['action'] = 'login';
	}
	$_REQUEST['session'] = $_COOKIE[COOKIENAME];
}
$_REQUEST['session'] = preg_replace('/[^0-9a-zA-Z]/', '', $_REQUEST['session'] ?? '');
load_lang();
check_db();
cron();
route();

//  main program: decide what to do based on queries
function route()
{
	global $U, $db;
	if (!isset($_REQUEST['action'])) {
		send_login();
	} elseif ($_REQUEST['action'] === 'view') {
		check_session();
		//Modification chat rooms
		if (isset($_REQUEST['room'])) {
			change_room();
			check_session();
		}
		// show_rooms('true');
		send_messages();
	} elseif ($_REQUEST['action'] === 'redirect' && !empty($_REQUEST['url'])) {
		send_redirect($_REQUEST['url']);
	} elseif ($_REQUEST['action'] === 'rooms') {
		check_session();
		rooms();
	} elseif ($_REQUEST['action'] === 'wait') {
		parse_sessions();
		send_waiting_room();
	} elseif ($_REQUEST['action'] === 'post') {
		check_session();
		if (isset($_REQUEST['kick']) && isset($_REQUEST['sendto']) && $_REQUEST['sendto'] !== ('s 48' || 's 56')) {
			//Modification to allow members to kick guests, if memdel (DEL-Buttons) enabled
			if ($U['status'] >= 5 || ($U['status'] >= 3 && get_count_mods() == 0 && get_setting('memkick')) || ($U['status'] >= 3 && (int)get_setting('memdel') === 2)) {
				if (isset($_REQUEST['what']) && $_REQUEST['what'] === 'purge') {
					kick_chatter([$_REQUEST['sendto']], $_REQUEST['message'], true);
				} else {
					kick_chatter([$_REQUEST['sendto']], $_REQUEST['message'], false);
				}
			}
		} elseif (isset($_REQUEST['warn']) && isset($_REQUEST['sendto'])) {
			// Tiered warn permissions: Members->Guests, Mods->Guests+Members, Admins->Guests+Members+Mods
			try {
				error_log("Warn request: from={$U['nickname']}, status={$U['status']}, to={$_REQUEST['sendto']}");
				if ($U['status'] >= 3 && !empty($_REQUEST['sendto'])) {
					$target_nick = $_REQUEST['sendto'];
					$stmt = $db->prepare('SELECT status, style FROM ' . PREFIX . 'sessions WHERE nickname=?;');
					$stmt->execute([$target_nick]);
					$target = $stmt->fetch(PDO::FETCH_ASSOC);
					
					error_log("Target found: " . ($target ? "yes, status={$target['status']}" : "no"));
					
					if ($target) {
						// Check permission: can only warn users with lower status
						$can_warn = false;
						if ($U['status'] == 3 && $target['status'] == 1) {
							$can_warn = true; // Members can warn guests
						} elseif ($U['status'] == 5 && ($target['status'] == 1 || $target['status'] == 3)) {
							$can_warn = true; // Mods can warn guests and members
						} elseif ($U['status'] >= 6 && ($target['status'] == 1 || $target['status'] == 3 || $target['status'] == 5)) {
							$can_warn = true; // Admins can warn guests, members, and mods
						}
						
						error_log("Can warn: " . ($can_warn ? "yes" : "no"));
						
						if ($can_warn) {
							$reason = !empty($_REQUEST['message']) ? $_REQUEST['message'] : 'Warning issued';
							$target_style = $target['style'] ?? '';
							
							error_log("Issuing warning to $target_nick: $reason");
							
add_user_warning($target_nick, $reason, false, $U['nickname'], 1, 10);
						
						// Send PM notification from Dot
						send_bot_pm($target_nick, "⚠️ <strong>Warning Issued</strong><br><strong>From:</strong> " . htmlspecialchars($U['nickname']) . "<br><strong>Reason:</strong> " . htmlspecialchars($reason));
						
						// Send confirmation to moderator
						send_bot_pm($U['nickname'], "✓ Warning issued to " . htmlspecialchars($target_nick) . ": " . htmlspecialchars($reason));

						} else {
							error_log("Permission denied for warning");
							send_error("Cannot warn this user: insufficient permissions");
						}
					} else {
						error_log("Target not found in sessions");
						send_error("Target user not found: " . htmlspecialchars($target_nick));
					}
				} else {
					error_log("Invalid warn params");
					send_error("Invalid warn request: status=" . $U['status'] . ", sendto=" . htmlspecialchars($_REQUEST['sendto'] ?? 'empty'));
				}
			} catch (Exception $e) {
				error_log("Warn exception: " . $e->getMessage());
				send_error("Warn error: " . $e->getMessage() . "<br>Line: " . $e->getLine() . "<br>File: " . $e->getFile());
			}
			send_post();
		} elseif (isset($_REQUEST['message']) && isset($_REQUEST['sendto'])) {
			send_post(validate_input());
		}
		send_post();
	} elseif ($_REQUEST['action'] === 'login') {
		check_login();
		send_frameset();
	} elseif ($_REQUEST['action'] === 'controls') {
		check_session();
		send_controls();
	} elseif ($_REQUEST['action'] === 'greeting') {
		check_session();
		send_greeting();
	} elseif ($_REQUEST['action'] === 'delete') {
		check_session();
		if ($_REQUEST['what'] === 'all') {
			if (isset($_REQUEST['confirm'])) {
				del_all_messages($U['nickname'], $U['status'] == 1 ? $U['entry'] : 0);
			} else {
				send_del_confirm();
			}
		} elseif ($_REQUEST['what'] === 'last') {
			del_last_message();
		}
		send_post();
	} elseif ($_REQUEST['action'] === 'profile') {
		check_session();
		$arg = '';
		if (!isset($_REQUEST['do'])) {
		} elseif ($_REQUEST['do'] === 'save') {
			$arg = save_profile();
		} elseif ($_REQUEST['do'] === 'delete') {
			if (isset($_REQUEST['confirm'])) {
				delete_account();
			} else {
				send_delete_account();
			}
		}
		send_profile($arg);
	} elseif ($_REQUEST['action'] === 'logout') {
		kill_session();
		send_logout();
	} elseif ($_REQUEST['action'] === 'colours') {
		check_session();
		send_colours();
	} elseif ($_REQUEST['action'] === 'notes') {
		check_session();
		$sparenotesaccess = (int) get_setting('sparenotesaccess');
		if (isset($_REQUEST['do']) && $_REQUEST['do'] === 'admin' && $U['status'] > 6) {
			send_notes(0);
		} elseif (isset($_REQUEST['do']) && $_REQUEST['do'] === 'staff' && $U['status'] >= 5) {
			send_notes(1);
			// Modification Spare Notes
		} elseif (isset($_REQUEST['do']) && $_REQUEST['do'] === 'spare' && $U['status'] >= $sparenotesaccess) {
			send_notes(3);
		}
		if ($U['status'] < 3 || !get_setting('personalnotes')) {
			send_access_denied();
		}
		send_notes(2);
	} elseif ($_REQUEST['action'] === 'help') {
		check_session();
		send_help();
	} elseif ($_REQUEST['action'] === 'inbox') {
		check_session();
		if (isset($_REQUEST['do'])) {
			clean_inbox_selected();
		}
		send_inbox();
	} elseif ($_REQUEST['action'] === 'download') {
		send_download();
	} elseif ($_REQUEST['action'] === 'admin') {
		check_session();
		send_admin(route_admin());
		//MODIFICATION DEL-BUTTONS 3 Lines added to enable delete buttons in front of each message.
	} elseif ($_REQUEST['action'] === 'admin_clean_message') {
		check_session();

		//These lines allows members to use the DEL-buttons according to the memdel setting (0 = not allowed , 2 =  allowed, 1 = allowed if not mod is present and if DEL-Buttons are activated for members.)
		$memdel = (int)get_setting('memdel');
		if (($U['status'] >= 5) || ($U['status'] >= 3 && $memdel === 2) || ($U['status'] >= 3 && get_count_mods() == 0 && $memdel === 1)) {
			clean_selected($U['status'], $U['nickname']);
		} else {
			error_log("DEL permission denied: status=" . $U['status'] . ", memdel=$memdel, mods=" . get_count_mods());
		}
		send_messages();

		//MODIFICATION gallery
	} elseif ($_REQUEST['action'] === 'gallery') {
		check_session(); //to get $U['status']
		if (!isset($_REQUEST['do'])) {
			send_gallery();
		} else {
			send_gallery($_REQUEST['do']);
		}
		//MODIFICATION links page
	} elseif ($_REQUEST['action'] === 'links') {
		check_session(); //to allow links page only for logged in users.
		send_links_page();

		//Forum Button was moved to the post box (function send_post)
		/*
    }elseif($_REQUEST['action']==='forum'){
  		check_session(); //to allow link to form only for logged in users.
  		send_to_forum();	
	*/
	} elseif ($_REQUEST['action'] === 'setup') {
		route_setup();
	} else {
		send_login();
	}
}

function route_admin()
{
	global $U, $db;

	if ($U['status'] < 5) {
		send_access_denied();
	}
	//Modification chat rooms
	$roomcreateaccess = (int) get_setting('roomcreateaccess');
	if (!isset($_REQUEST['do'])) {
	} elseif ($_REQUEST['do'] === 'clean') {
		if ($_REQUEST['what'] === 'choose') {
			send_choose_messages();
		} elseif ($_REQUEST['what'] === 'selected') {
			clean_selected($U['status'], $U['nickname']);
		} elseif ($_REQUEST['what'] === 'chat') {
			clean_chat();
		} elseif ($_REQUEST['what'] === 'room') {
			clean_room();
		} elseif ($_REQUEST['what'] === 'nick') {
			$stmt = $db->prepare('SELECT null FROM ' . PREFIX . 'members WHERE nickname=? AND status>=?;');
			$stmt->execute([$_REQUEST['nickname'], $U['status']]);
			if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
				del_all_messages($_REQUEST['nickname'], 0);
			}
		}
	} elseif ($_REQUEST['do'] === 'kick') {
		if (isset($_REQUEST['name'])) {
			if (isset($_REQUEST['what']) && $_REQUEST['what'] === 'purge') {
				kick_chatter($_REQUEST['name'], $_REQUEST['kickmessage'], true);
			} else {
				kick_chatter($_REQUEST['name'], $_REQUEST['kickmessage'], false);
			}
		}
	} elseif ($_REQUEST['do'] === 'logout') {
		if (isset($_REQUEST['name'])) {
			logout_chatter($_REQUEST['name']);
		}
	} elseif ($_REQUEST['do'] === 'sessions') {
		if (isset($_REQUEST['kick']) && isset($_REQUEST['nick'])) {
			kick_chatter([$_REQUEST['nick']], '', false);
		} elseif (isset($_REQUEST['logout']) && isset($_REQUEST['nick'])) {
			logout_chatter([$_REQUEST['nick']], '', false);
		}
		send_sessions();
	} elseif ($_REQUEST['do'] === 'applicants' && $U['status'] >= 6) {
		send_applicant_queue();
	} elseif ($_REQUEST['do'] === 'applicant_action' && $U['status'] >= 6) {
		// Handle applicant approve/ban actions
		if (isset($_REQUEST['applicant_nick']) && isset($_REQUEST['applicant_action'])) {
			$nick = $_REQUEST['applicant_nick'];
			$action = $_REQUEST['applicant_action'];
			
			// Verify target is actually an applicant (status 2)
			$stmt = $db->prepare('SELECT status FROM ' . PREFIX . 'members WHERE nickname=?;');
			$stmt->execute([$nick]);
			if ($row = $stmt->fetch(PDO::FETCH_NUM)) {
				$current_status = $row[0];
				
				if ($current_status == 2) {
					if ($action === 'approve') {
						// Promote to Member (status 3) using can_promote check
						if (can_promote($U['status'], $current_status, 3)) {
							$stmt = $db->prepare('UPDATE ' . PREFIX . 'members SET status=3 WHERE nickname=?;');
							$stmt->execute([$nick]);
							$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET status=3 WHERE nickname=?;');
							$stmt->execute([$nick]);
							
							// Log to audit
							log_audit($U['nickname'], $U['status'], 'applicant_approved', $nick, 3, 'Promoted from Applicant (2) to Member (3)');
							
							// Send system message to user
							$message = "✓ <span class=\"sysmsg\">Congratulations! Your application has been approved. You are now a Member (status 3).</span>";
							$newmessage = [
								'postdate' => time(),
								'poststatus' => 9,
								'poster' => 'System',
								'recipient' => $nick,
								'text' => $message,
								'delstatus' => 9,
								'roomid' => null,
								'allrooms' => 0
							];
							write_message($newmessage);
						}
					} elseif ($action === 'ban') {
						// Ban user (status 0) using can_promote check
						if (can_promote($U['status'], $current_status, 0)) {
							$stmt = $db->prepare('UPDATE ' . PREFIX . 'members SET status=0 WHERE nickname=?;');
							$stmt->execute([$nick]);
							$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET status=0 WHERE nickname=?;');
							$stmt->execute([$nick]);
							
							// Log to audit
							log_audit($U['nickname'], $U['status'], 'applicant_banned', $nick, 0, 'Banned from Applicant (2) to Banned (0)');
							
							// Kick user
							kick_chatter([$nick], 'Application denied - account banned', false);
						}
					}
				}
			}
		}
		send_applicant_queue();
		// MODIFICATION Supermods and above can register guests to member
	} elseif ($_REQUEST['do'] === 'register' && $U['status'] >= 6) {
		return register_guest(3, $_REQUEST['name']);
	} elseif ($_REQUEST['do'] === 'superguest') {
		return register_guest(2, $_REQUEST['name']);
		// MODIFICATION Chat Admins (6+) can change status of Applicants/Members, Service Admins (7+) can change all < Service Admin, System Admins (8) can change all
	} elseif ($_REQUEST['do'] === 'status' && $U['status'] >= 6) {
		return change_status($_REQUEST['name'], $_REQUEST['set']);
		// MODIFICATION Chat Admins (6+) and above can register new members
	} elseif ($_REQUEST['do'] === 'regnew' && $U['status'] >= 6) {
		return register_new($_REQUEST['name'], $_REQUEST['pass']);
	} elseif ($_REQUEST['do'] === 'approve') {
		approve_session();
		send_approve_waiting();
	} elseif ($_REQUEST['do'] === 'guestaccess') {
		if (isset($_REQUEST['guestaccess']) && preg_match('/^[0123]$/', $_REQUEST['guestaccess'])) {
			update_setting('guestaccess', $_REQUEST['guestaccess']);
		}
		//MODIFICATION All moderators (status 5+) can view and manage filters
	} elseif ($_REQUEST['do'] === 'filter_all' && $U['status'] >= 5) {
		send_filter_all(manage_filter());
	} elseif ($_REQUEST['do'] === 'filter' && $U['status'] >= 5) {
		send_filter(manage_filter());
	} elseif ($_REQUEST['do'] === 'filter_warnings' && $U['status'] >= 5) {
		send_filter_warnings(manage_filter());
	} elseif ($_REQUEST['do'] === 'filter_kick' && $U['status'] >= 5) {
		send_filter_kick(manage_filter());
	} elseif ($_REQUEST['do'] === 'filter_commands' && $U['status'] >= 5) {
		send_filter_commands(manage_filter());
	} elseif ($_REQUEST['do'] === 'filter_staff' && $U['status'] >= 5) {
		send_filter_staff(manage_filter());
		//MODIFICATION All moderators (status 5+) can view and manage linkfilters
	} elseif ($_REQUEST['do'] === 'linkfilter' && $U['status'] >= 5) {
		send_linkfilter(manage_linkfilter());
	} elseif ($_REQUEST['do'] === 'botcommands' && $U['status'] >= 5) {
		send_botcommands(manage_botcommands());
	} elseif ($_REQUEST['do'] === 'lastlogin' && $U['status'] >= 7) {
		send_lastlogin();
	} elseif ($_REQUEST['do'] === 'topic') {
		//Modification "topic with html-code" - Supermods and above can change topic
		if (isset($_REQUEST['topic']) && $U['status'] >= 6) {
			update_setting('topic', $_REQUEST['topic']);
		}
		// MODIFICATION Supermods and above can reset passwords
	} elseif ($_REQUEST['do'] === 'passreset' && $U['status'] >= 6) {
		return passreset($_REQUEST['name'], $_REQUEST['pass']);
		//Modification chat rooms
	} elseif ($_REQUEST['do'] === 'rooms' && $U['status'] >= $roomcreateaccess) {
		send_rooms(manage_rooms());
	} elseif ($_REQUEST['do'] === 'userhistory' && $U['status'] >= 5 && moderation_tables_exist()) {
		// Handle individual log deletion
		if (isset($_REQUEST['delete_log']) && isset($_REQUEST['log_id']) && isset($_REQUEST['log_table'])) {
			$log_id = (int)$_REQUEST['log_id'];
			$log_table = $_REQUEST['log_table'];
			$can_delete = false;
			
			// Status 7+ can delete any entry
			if ($U['status'] >= 7) {
				$can_delete = true;
			} 
			// Status 5-6 can delete entries they issued
			elseif ($U['status'] >= 5) {
				if ($log_table === 'user_history') {
					$stmt = $db->prepare('SELECT actor FROM ' . PREFIX . 'user_history WHERE id=?;');
					$stmt->execute([$log_id]);
					$entry = $stmt->fetch(PDO::FETCH_ASSOC);
					if ($entry && $entry['actor'] === $U['nickname']) {
						$can_delete = true;
					}
				} elseif ($log_table === 'mod_actions') {
					$stmt = $db->prepare('SELECT moderator FROM ' . PREFIX . 'mod_actions WHERE id=?;');
					$stmt->execute([$log_id]);
					$entry = $stmt->fetch(PDO::FETCH_ASSOC);
					if ($entry && $entry['moderator'] === $U['nickname']) {
						$can_delete = true;
					}
				}
			}
			
			// Perform deletion if authorized
			if ($can_delete) {
				if ($log_table === 'user_history') {
					$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'user_history WHERE id=?;');
					$stmt->execute([$log_id]);
				} elseif ($log_table === 'mod_actions') {
					$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'mod_actions WHERE id=?;');
					$stmt->execute([$log_id]);
				}
			}
		}
		
		// Handle quick actions
		if (isset($_REQUEST['quick_action']) && isset($_REQUEST['user'])) {
			handle_quick_action($_REQUEST['user'], $_REQUEST['quick_action'], $_REQUEST);
		}
		// Handle save note
		if (isset($_REQUEST['save_note']) && isset($_REQUEST['user']) && isset($_REQUEST['note_text'])) {
			save_mod_note($_REQUEST['user'], $_REQUEST['note_text']);
		}
		// Display user history
		if (isset($_REQUEST['user'])) {
			send_user_history($_REQUEST['user']);
		} else {
			send_user_history_search();
		}
	} elseif ($_REQUEST['do'] === 'auditlog' && $U['status'] >= 5 && moderation_tables_exist()) {
		send_audit_log();
	} elseif ($_REQUEST['do'] === 'appeals' && $U['status'] >= 5 && moderation_tables_exist()) {
		if (isset($_REQUEST['review']) && isset($_REQUEST['appeal_id'])) {
			review_appeal($_REQUEST['appeal_id'], $_REQUEST['decision'], $_REQUEST['notes'] ?? '');
		}
		send_appeals_queue();
	} elseif ($_REQUEST['do'] === 'automod' && $U['status'] >= 5 && moderation_tables_exist()) {
		if (isset($_REQUEST['manage'])) {
			manage_automod_rules();
		}
		send_automod_rules();
	}
}

function route_setup()
{
	global $U;
	if (!valid_admin()) {
		send_alogin();
	}
	//MODIFICATION incognito setting only for super admin
	$C['bool_settings'] = ['suguests', 'imgembed', 'timestamps', 'trackip', 'memkick', 'forceredirect', 'sendmail', 'modfallback', 'disablepm', 'eninbox', 'enablegreeting', 'sortupdown', 'hidechatters', 'personalnotes', 'filtermodkick'];
	$C['colour_settings'] = ['colbg', 'coltxt'];
	$C['msg_settings'] = ['msgenter', 'msgexit', 'msgmemreg', 'msgsureg', 'msgkick', 'msgmultikick', 'msgallkick', 'msgclean', 'msgsendall', 'msgsendmem', 'msgsendmod', 'msgsendadm', 'msgsendprv', 'msgattache'];
	$C['number_settings'] = ['memberexpire', 'guestexpire', 'kickpenalty', 'entrywait', 'captchatime', 'messageexpire', 'messagelimit', 'maxmessage', 'maxname', 'minpass', 'defaultrefresh', 'numnotes', 'maxuploadsize', 'enfileupload'];
	$C['textarea_settings'] = ['rulestxt', 'css', 'disabletext'];
	$C['text_settings'] = ['dateformat', 'captchachars', 'redirect', 'chatname', 'mailsender', 'mailreceiver', 'nickregex', 'passregex', 'externalcss'];

	//MODIFICATION for links page. setting links and linksenabled added.
	//MODIFICATION for DEL-Buttons: setting memdel added.
	//MODIFICATION for galleryaccess: setting galleryaccess added.
	//MODIFICATION for forumbtnaccess: setting forumbtnaccess added.
	//MODIFICATION for forumbtnlink: setting forumbtnlink added.
	//MODIFICATION for frontpagetext: setting frontpagetext added.
	//MODIFICATION for adminjoinleavemsg: setting adminjoinleavemsg
	//MODIFICATION for clickablne nicknames: setting clickablenicknamesglobal
	//MODIFICATION for spare notes: setting sparenotesname, setting sparenotesaccess
	//MODIFICATION for chat rooms: setting roomcreateaccess, setting roomexpire, setting channelvisinroom
	$C['settings'] = array_merge(['guestaccess', 'englobalpass', 'globalpass', 'captcha', 'dismemcaptcha', 'topic', 'guestreg', 'defaulttz', 'links', 'linksenabled', 'memdel', 'galleryaccess', 'forumbtnaccess', 'forumbtnlink', 'frontpagetext', 'adminjoinleavemsg', 'clickablenicknamesglobal', 'sparenotesname', 'sparenotesaccess', 'roomcreateaccess', 'roomexpire', 'channelvisinroom'], $C['bool_settings'], $C['colour_settings'], $C['msg_settings'], $C['number_settings'], $C['textarea_settings'], $C['text_settings']); // All settings in the database


	//Modification Super Admin settings
	//MODIFICATION for modsdeladminmsg: Super Admin setting modsdeladminmsg added
	$C_SAdmin = $C;
	$C_SAdmin['settings'] = array_merge($C['settings'], ['modsdeladminmsg', 'incognito']);


	//Modificatoin Super Admin settings
	if (!isset($_REQUEST['do'])) {
	} elseif ($_REQUEST['do'] === 'save' && $U['status'] == 8) {
		save_setup($C_SAdmin);
	} elseif ($_REQUEST['do'] === 'save') {
		save_setup($C);
	} elseif ($_REQUEST['do'] === 'backup' && $U['status'] == 8) {
		send_backup($C);
	} elseif ($_REQUEST['do'] === 'restore' && $U['status'] == 8) {
		restore_backup($C);
		send_backup($C);
	} elseif ($_REQUEST['do'] === 'destroy' && $U['status'] == 8) {
		if (isset($_REQUEST['confirm'])) {
			destroy_chat($C);
		} else {
			send_destroy_chat();
		}
	}
	send_setup($C);
}

//  html output subs
function print_stylesheet($init = false)
{
	global $U;
	//default css
	echo '<style type="text/css">';
	echo 'body{background-color:#000000;color:#FFFFFF;font-size:14px;text-align:center;} body .rooms {background-color: transparent !important;}';
	echo 'a:visited{color:#B33CB4;} a:active{color:#FF0033;} a:link{color:#0000FF;} #messages{word-wrap:break-word;} ';
	echo 'input,select,textarea{color:#FFFFFF;background-color:#000000;} .messages a img{width:15%} .messages a:hover img{width:35%} ';
	echo '.error{color:#FF0033;text-align:left;} .delbutton{background-color:#660000;} .backbutton{background-color:#004400;} #exitbutton{background-color:#AA0000;} ';
	echo '.setup table table,.admin table table,.profile table table{width:100%;text-align:left} ';
	echo '.alogin table,.init table,.destroy_chat table,.delete_account table,.sessions table,.filter table,.linkfilter table,.botcommands table,.notes table,.approve_waiting table,.del_confirm table,.profile table,.admin table,.backup table,.setup table{margin-left:auto;margin-right:auto;} ';
	echo '.setup table table table,.admin table table table,.profile table table table{border-spacing:0px;margin-left:auto;margin-right:unset;width:unset;} ';
	echo '.setup table table td,.backup #restoresubmit,.backup #backupsubmit,.admin table table td,.profile table table td,.login td+td,.alogin td+td{text-align:right;} ';
	echo '.init td,.backup #restorecheck td,.admin #clean td,.admin #regnew td,.session td,.messages,.inbox,.approve_waiting td,.choose_messages,.greeting,.help,.login td,.alogin td{text-align:left;} ';
	echo '.messages #chatters{max-height:100px;overflow-y:auto;} .messages #chatters a{text-decoration-line:none;} .messages #chatters table{border-spacing:0px;} ';
	echo '.messages #chatters th,.messages #chatters td,.post #firstline{vertical-align:top;} ';
	echo '.approve_waiting #action td:only-child,.help #backcredit,.login td:only-child,.alogin td:only-child,.init td:only-child{text-align:center;} .sessions td,.sessions th,.approve_waiting td,.approve_waiting th{padding: 5px;} ';
	echo '.sessions td td{padding: 1px;} .messages #bottom_link{position:fixed;top:0.5em;right:0.5em;} .messages #top_link{position:fixed;bottom:0.5em;right:0.5em;} ';
	echo '.post table,.controls table,.login table{border-spacing:0px;margin-left:auto;margin-right:auto;} .login table{border:2px solid;} .controls{overflow-y:none;} ';
	echo '#manualrefresh{display:block;position:fixed;text-align:center;left:25%;width:50%;top:-200%;animation:timeout_messages ';
	if (isset($U['refresh'])) {
		echo $U['refresh'] + 20;
	} else {
		echo '160';
	}
	echo 's forwards;z-index:2;background-color:#500000;border:2px solid #ff0000;} ';
	echo '@keyframes timeout_messages{0%{top:-200%;} 99%{top:-200%;} 100%{top:0%;}} ';
	echo '.notes textarea{height:80vh;width:80%;}iframe{width:100%;height:100%;margin:0;padding:0;border:none}';
	echo '@import url("style.css");';
	echo '</style>';
	if ($init) {
		return;
	}
	$css = get_setting('css');
	$coltxt = get_setting('coltxt');
	if (!empty($U['bgcolour'])) {
		$colbg = $U['bgcolour'];
	} else {
		$colbg = get_setting('colbg');
	}
	echo "<link rel=\"shortcut icon\" href=\"https://cdn.sokka.dev/global/images/favicon.svg\">";
	//overwrite with custom css
	echo "<style type=\"text/css\">body{background-color:#$colbg;color:#$coltxt;} $css</style>";
	echo "<link rel=\"preload\" href=\"style.css\" as=\"style\"><link rel=\"stylesheet\" type=\"text/css\" href=\"style.css\">";
}

function print_end()
{
	echo '</body></html>';
	exit;
}

function credit()
{
	return '<small><br><br><a target="_blank" style="color:var(--accent); text-decoration: underline dotted var(--accent)" href="https://4-0-4.io">Project 404</a></small>';
}

function meta_html()
{
	return '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><meta http-equiv="Pragma" content="no-cache"><meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate, max-age=0"><meta http-equiv="expires" content="0"><meta name="referrer" content="no-referrer">';
}

function form($action, $do = '')
{
	global $language;
	$form = "<form action=\"/chat\" enctype=\"multipart/form-data\" method=\"post\">" . hidden('lang', $language) . hidden('nc', substr(time(), -6)) . hidden('action', $action);
	if (!empty($_REQUEST['session'])) {
		$form .= hidden('session', $_REQUEST['session']);
	}
	if ($do !== '') {
		$form .= hidden('do', $do);
	}
	return $form;
}

function form_target($target, $action, $do = '')
{
	global $language;
	$form = "<form action=\"/chat\" enctype=\"multipart/form-data\" method=\"post\" target=\"$target\">" . hidden('lang', $language) . hidden('nc', substr(time(), -6)) . hidden('action', $action);
	if (!empty($_REQUEST['session'])) {
		$form .= hidden('session', $_REQUEST['session']);
	}
	if ($do !== '') {
		$form .= hidden('do', $do);
	}
	return $form;
}

function hidden($arg1 = '', $arg2 = '')
{
	return "<input type=\"hidden\" name=\"$arg1\" value=\"$arg2\">";
}

function submit($arg1 = '', $arg2 = '')
{
	return "<input type=\"submit\" value=\"$arg1\" $arg2>";
}

function thr()
{
	echo '<tr><td><hr></td></tr>';
}

function print_start($class = '', $ref = 0, $url = '')
{
	global $I;
	if (!empty($url)) {
		$url = str_replace('&amp;', '&', $url); // Don't escape "&" in URLs here, it breaks some (older) browsers and js refresh!
		header("Refresh: $ref; URL=$url");
	}
	echo '<!DOCTYPE html><html><head>' . meta_html();
	if (!empty($url)) {
		echo "<meta http-equiv=\"Refresh\" content=\"$ref; URL=$url\">";
		$ref += 5; //only use js if browser refresh stopped working
		$ref *= 1000; //js uses milliseconds

		// MODIFICATION removed window refresh js
		/* echo "<script type=\"text/javascript\">setTimeout(function(){window.location.replace(\"$url\");}, $ref);</script>";*/
	}
	if ($class === 'init') {
		echo "<title>$I[init]</title>";
		print_stylesheet(true);
	} else {
		echo '<title>' . get_setting('chatname') . '</title>';
		print_stylesheet();
	}
	if ($class !== 'init' && ($externalcss = get_setting('externalcss')) != '') {
		//external css - in body to make it non-renderblocking
	}
	echo "<link rel=\"stylesheet\" type=\"text/css\" href=\"style.css\">";
	echo '<meta http-equiv="onion-location" content="http://4o4o4hn4hsujpnbsso7tqigujuokafxys62thulbk2k3mf46vq22qfqd.onion/chat" />';
	echo "</head><body class=\"$class\">";
}

function send_redirect($url)
{
	global $I;
	$url = trim(htmlspecialchars_decode(rawurldecode($url)));
	preg_match('~^(.*)://~u', $url, $match);
	$url = preg_replace('~^(.*)://~u', '', $url);
	$escaped = htmlspecialchars($url);
	if (isset($match[1]) && ($match[1] === 'http' || $match[1] === 'https')) {
		print_start('redirect', 0, $match[0] . $escaped);
		echo "<p>$I[redirectto] <a href=\"$match[0]$escaped\">$match[0]$escaped</a>.</p>";
	} else {
		print_start('redirect');
		if (!isset($match[0])) {
			$match[0] = '';
		}
		if (preg_match('~^(javascript|blob|data):~', $url)) {
			echo "<p>$I[dangerousnonhttp] $match[0]$escaped</p>";
		} else {
			echo "<p>$I[nonhttp] <a href=\"$match[0]$escaped\">$match[0]$escaped</a>.</p>";
		}
		echo "<p>$I[httpredir] <a href=\"http://$escaped\">http://$escaped</a>.</p>";
	}
	print_end();
}

function send_access_denied()
{
	global $I, $U;
	header('HTTP/1.1 403 Forbidden');
	print_start('access_denied');
	echo "<h1>$I[accessdenied]</h1>" . sprintf($I['loggedinas'], style_this(htmlspecialchars($U['nickname']), $U['style'])) . '<br>';
	echo form('logout');
	if (!isset($_REQUEST['session'])) {
		echo hidden('session', $U['session']);
	}
	echo submit($I['logout'], 'id="exitbutton"') . "</form>";
	print_end();
}

function send_captcha()
{
	global $I, $db, $memcached;
	$difficulty = (int) get_setting('captcha');
	if ($difficulty === 0 || !extension_loaded('gd')) {
		return;
	}
	$captchachars = get_setting('captchachars');
	$length = strlen($captchachars) - 1;
	$code = '';
	for ($i = 0; $i < 5; ++$i) {
		$code .= $captchachars[mt_rand(0, $length)];
	}
	$randid = mt_rand();
	$time = time();
	if (MEMCACHED) {
		$memcached->set(DBNAME . '-' . PREFIX . "captcha-$randid", $code, get_setting('captchatime'));
	} else {
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'captcha (id, time, code) VALUES (?, ?, ?);');
		$stmt->execute([$randid, $time, $code]);
	}
	echo "<tr id=\"captcha\"><td><span class=\"centerWrap sprite-decaptcha-logo-night\"></span> ";
	if ($difficulty === 1) {
		$im = imagecreatetruecolor(55, 24);
		$bg = imagecolorallocatealpha($im, 0, 0, 0, 127);
		$fg = imagecolorallocate($im, 255, 255, 255);
		imagefill($im, 0, 0, $bg);
		imagestring($im, 5, 5, 5, $code, $fg);
		imagesavealpha($im, true);
		echo '<img class="captchalogincbox" width="55" height="24" src="data:image/gif;base64,';
	} elseif ($difficulty === 2) {
		$im = imagecreatetruecolor(55, 24);
		$bg = imagecolorallocatealpha($im, 0, 0, 0, 0);
		$fg = imagecolorallocate($im, 255, 255, 255);
		imagefill($im, 0, 0, $bg);
		imagestring($im, 5, 5, 5, $code, $fg);
		$line = imagecolorallocate($im, 255, 255, 255);
		for ($i = 0; $i < 2; ++$i) {
			imageline($im, 0, mt_rand(0, 24), 55, mt_rand(0, 24), $line);
		}
		$dots = imagecolorallocate($im, 255, 255, 255);
		for ($i = 0; $i < 100; ++$i) {
			imagesetpixel($im, mt_rand(0, 55), mt_rand(0, 24), $dots);
		}
		echo '<img class="captchalogincbox" width="55" height="24" src="data:image/gif;base64,';
	} else {
		$im = imagecreatetruecolor(150, 200);
		$bg = imagecolorallocatealpha($im, 0, 0, 0, 0);
		$fg = imagecolorallocate($im, 255, 255, 255);
		imagefill($im, 0, 0, $bg);
		$chars = [];
		for ($i = 0; $i < 10; ++$i) {
			$found = false;
			while (!$found) {
				$x = mt_rand(10, 140);
				$y = mt_rand(10, 180);
				$found = true;
				foreach ($chars as $char) {
					if ($char['x'] >= $x && ($char['x'] - $x) < 25) {
						$found = false;
					} elseif ($char['x'] < $x && ($x - $char['x']) < 25) {
						$found = false;
					}
					if (!$found) {
						if ($char['y'] >= $y && ($char['y'] - $y) < 25) {
							break;
						} elseif ($char['y'] < $y && ($y - $char['y']) < 25) {
							break;
						} else {
							$found = true;
						}
					}
				}
			}
			$chars[] = ['x', 'y'];
			$chars[$i]['x'] = $x;
			$chars[$i]['y'] = $y;
			if ($i < 5) {
				imagechar($im, 5, $chars[$i]['x'], $chars[$i]['y'], $captchachars[mt_rand(0, $length)], $fg);
			} else {
				imagechar($im, 5, $chars[$i]['x'], $chars[$i]['y'], $code[$i - 5], $fg);
			}
		}
		$follow = imagecolorallocate($im, 200, 0, 0);
		imagearc($im, $chars[5]['x'] + 4, $chars[5]['y'] + 8, 16, 16, 0, 360, $follow);
		for ($i = 5; $i < 9; ++$i) {
			imageline($im, $chars[$i]['x'] + 4, $chars[$i]['y'] + 8, $chars[$i + 1]['x'] + 4, $chars[$i + 1]['y'] + 8, $follow);
		}
		$line = imagecolorallocate($im, 255, 255, 255);
		for ($i = 0; $i < 5; ++$i) {
			imageline($im, 0, mt_rand(0, 200), 150, mt_rand(0, 200), $line);
		}
		$dots = imagecolorallocate($im, 255, 255, 255);
		for ($i = 0; $i < 1000; ++$i) {
			imagesetpixel($im, mt_rand(0, 150), mt_rand(0, 200), $dots);
		}
		echo '<img class="captchalogincbox" width="150" height="200" src="data:image/gif;base64,';
	}
	ob_start();
	imagegif($im);
	imagedestroy($im);
	echo base64_encode(ob_get_clean()) . '">';
	echo '</td><td>' . hidden('challenge', $randid) . '<input type="text" name="captcha" size="15" autocomplete="off"></td></tr>';
}

function send_setup($C)
{
	global $I, $U;
	print_start('setup');
	echo "<h2>$I[setup]</h2>" . form('setup', 'save');
	if (!isset($_REQUEST['session'])) {
		echo hidden('session', $U['session']);
	}
	echo '<table id="guestaccess">';
	thr();
	$ga = (int) get_setting('guestaccess');
	echo "<tr><td><table><tr><th>$I[guestacc]</th><td>";
	echo '<select name="guestaccess">';
	echo '<option value="1"';
	if ($ga === 1) {
		echo ' selected';
	}
	echo ">$I[guestallow]</option>";
	echo '<option value="2"';
	if ($ga === 2) {
		echo ' selected';
	}
	echo ">$I[guestwait]</option>";
	echo '<option value="3"';
	if ($ga === 3) {
		echo ' selected';
	}
	echo ">$I[adminallow]</option>";
	echo '<option value="0"';
	if ($ga === 0) {
		echo ' selected';
	}
	echo ">$I[guestdisallow]</option>";
	echo '<option value="4"';
	if ($ga === 4) {
		echo ' selected';
	}
	echo ">$I[disablechat]</option>";
	echo '</select></td></tr></table></td></tr>';
	thr();
	$englobal = (int) get_setting('englobalpass');
	echo "<tr><td><table id=\"globalpass\"><tr><th>$I[globalloginpass]</th><td>";
	echo '<table>';
	echo '<tr><td><select name="englobalpass">';
	echo '<option value="0"';
	if ($englobal === 0) {
		echo ' selected';
	}
	echo ">$I[disabled]</option>";
	echo '<option value="1"';
	if ($englobal === 1) {
		echo ' selected';
	}
	echo ">$I[enabled]</option>";
	echo '<option value="2"';
	if ($englobal === 2) {
		echo ' selected';
	}
	echo ">$I[onlyguests]</option>";
	echo '</select></td><td>&nbsp;</td>';
	echo '<td><input type="text" name="globalpass" value="' . htmlspecialchars(get_setting('globalpass')) . '"></td></tr>';
	echo '</table></td></tr></table></td></tr>';
	thr();
	$ga = (int) get_setting('guestreg');
	echo "<tr><td><table id=\"guestreg\"><tr><th>$I[guestreg]</th><td>";
	echo '<select name="guestreg">';
	echo '<option value="0"';
	if ($ga === 0) {
		echo ' selected';
	}
	echo ">$I[disabled]</option>";
	echo '<option value="1"';
	if ($ga === 1) {
		echo ' selected';
	}
	echo ">$I[assuguest]</option>";
	echo '<option value="2"';
	if ($ga === 2) {
		echo ' selected';
	}
	echo ">$I[asmember]</option>";
	echo '</select></td></tr></table></td></tr>';
	thr();
	echo "<tr><td><table id=\"sysmessages\"><tr><th>$I[sysmessages]</th><td>";
	echo '<table>';
	foreach ($C['msg_settings'] as $setting) {
		echo "<tr><td>&nbsp;$I[$setting]</td><td>&nbsp;<input type=\"text\" name=\"$setting\" value=\"" . get_setting($setting) . '"></td></tr>';
	}
	echo '</table></td></tr></table></td></tr>';
	foreach ($C['text_settings'] as $setting) {
		thr();
		echo "<tr><td><table id=\"$setting\"><tr><th>" . $I[$setting] . '</th><td>';
		echo "<input type=\"text\" name=\"$setting\" value=\"" . htmlspecialchars(get_setting($setting)) . '">';
		echo '</td></tr></table></td></tr>';
	}
	foreach ($C['colour_settings'] as $setting) {
		thr();
		echo "<tr><td><table id=\"$setting\"><tr><th>" . $I[$setting] . '</th><td>';
		echo "<input type=\"color\" name=\"$setting\" value=\"#" . htmlspecialchars(get_setting($setting)) . '">';
		echo '</td></tr></table></td></tr>';
	}
	thr();
	echo "<tr><td><table id=\"captcha\"><tr><th>$I[captcha]</th><td>";
	echo '<table>';
	if (!extension_loaded('gd')) {
		echo "<tr><td>$I[gdextrequired]</td></tr>";
	} else {
		echo '<tr><td><select name="dismemcaptcha">';
		$dismemcaptcha = (bool) get_setting('dismemcaptcha');
		echo '<option value="0"';
		if (!$dismemcaptcha) {
			echo ' selected';
		}
		echo ">$I[enabled]</option>";
		echo '<option value="1"';
		if ($dismemcaptcha) {
			echo ' selected';
		}
		echo ">$I[onlyguests]</option>";
		echo '</select></td><td><select name="captcha">';
		$captcha = (int) get_setting('captcha');
		echo '<option value="0"';
		if ($captcha === 0) {
			echo ' selected';
		}
		echo ">$I[disabled]</option>";
		echo '<option value="1"';
		if ($captcha === 1) {
			echo ' selected';
		}
		echo ">$I[simple]</option>";
		echo '<option value="2"';
		if ($captcha === 2) {
			echo ' selected';
		}
		echo ">$I[moderate]</option>";
		echo '<option value="3"';
		if ($captcha === 3) {
			echo ' selected';
		}
		echo ">$I[extreme]</option>";
		echo '</select></td></tr>';
	}
	echo '</table></td></tr></table></td></tr>';
	thr();
	echo "<tr><td><table id=\"defaulttz\"><tr><th>$I[defaulttz]</th><td>";
	echo "<select name=\"defaulttz\">";
	$tzs = timezone_identifiers_list();
	$defaulttz = get_setting('defaulttz');
	foreach ($tzs as $tz) {
		echo "<option value=\"$tz\"";
		if ($defaulttz == $tz) {
			echo ' selected';
		}
		echo ">$tz</option>";
	}
	echo '</select>';
	echo '</td></tr></table></td></tr>';
	foreach ($C['textarea_settings'] as $setting) {
		thr();
		echo "<tr><td><table id=\"$setting\"><tr><th>" . $I[$setting] . '</th><td>';
		echo "<textarea name=\"$setting\" rows=\"4\" cols=\"60\">" . htmlspecialchars(get_setting($setting)) . '</textarea>';
		echo '</td></tr></table></td></tr>';
	}
	//MODIFICATION textarea to edit links page
	thr();
	echo "<tr><td><table id=\"links\"><tr><th>Changelog Page (html)</th><td>";
	echo "<textarea name=\"links\" rows=\"4\" cols=\"60\">" . htmlspecialchars(get_setting('links')) . '</textarea>';
	echo '</td></tr></table></td></tr>';
	//End of Modification

	//MODIFICATION frontpagetext: textarea to edit front page
	thr();
	echo "<tr><td><table id=\"frontpagetext\"><tr><th>Text on front page (html)</th><td>";
	echo "<textarea name=\"frontpagetext\" rows=\"4\" cols=\"60\">" . htmlspecialchars(get_setting('frontpagetext')) . '</textarea>';
	echo '</td></tr></table></td></tr>';
	//End of Modification

	foreach ($C['number_settings'] as $setting) {
		thr();
		echo "<tr><td><table id=\"$setting\"><tr><th>" . $I[$setting] . '</th><td>';
		echo "<input type=\"number\" name=\"$setting\" value=\"" . htmlspecialchars(get_setting($setting)) . '">';
		echo '</td></tr></table></td></tr>';
	}
	foreach ($C['bool_settings'] as $setting) {
		thr();
		echo "<tr><td><table id=\"$setting\"><tr><th>" . $I[$setting] . '</th><td>';
		echo "<select name=\"$setting\">";
		$value = (bool) get_setting($setting);
		echo '<option value="0"';
		if (!$value) {
			echo ' selected';
		}
		echo ">$I[disabled]</option>";
		echo '<option value="1"';
		if ($value) {
			echo ' selected';
		}
		echo ">$I[enabled]</option>";
		echo '</select></td></tr>';
		echo '</table></td></tr>';
	}
	//thr();

	//MODIFICATION to enable links page 
	thr();
	echo "<tr><td><table id=\"linksenabled\"><tr><th>Changelog Page</th><td>";
	echo "<select name=\"linksenabled\">";
	$value = (bool) get_setting('linksenabled');
	echo '<option value="0"';
	if (!$value) {
		echo ' selected';
	}
	echo ">$I[disabled]</option>";
	echo '<option value="1"';
	if ($value) {
		echo ' selected';
	}
	echo ">$I[enabled]</option>";
	echo '</select></td></tr>';
	echo '</table></td></tr>';
	thr();
	//End of Modification

	//MODIFICATION to enable DEL-Buttons for members (2 = always, 1 =  if no mod is present.)
	//thr();
	echo "<tr><td><table id=\"memdel\"><tr><th>Members can delete messages (DEL) and can kick</th><td>";
	echo "<select name=\"memdel\">";
	$value = (int) get_setting('memdel');
	echo '<option value="0"';
	if ($value == 0) {
		echo ' selected';
	}
	echo ">$I[disabled]</option>";

	echo '<option value="1"';
	if ($value == 1) {
		echo ' selected';
	}
	echo ">DEL-Buttons enabled, if no mod is present</option>";

	/*
	echo '</select></td></tr>';
    echo '</table></td></tr>';
    */

	echo '<option value="2"';
	if ($value == 2) {
		echo ' selected';
	}
	echo ">$I[enabled]</option>";
	echo '</select></td></tr>';
	echo '</table></td></tr>';

	thr();
	//End of Modification

	//Modification gallery access
	echo "<tr><td><table id=\"galleryaccess\"><tr><th>Gallery access</th><td>";
	echo "<select name=\"galleryaccess\">";
	$value = (int) get_setting('galleryaccess');

	$options = array(1, 2, 3, 5, 6, 7, 10);

	foreach ($options as $option) {
		echo "<option value=\"$option\"";

		if ($value == $option) {
			echo ' selected';
		}

		if ($option == 1) echo ">All</option>";
		elseif ($option == 2) echo ">Registered guests</option>";
		elseif ($option == 3) echo ">Members</option>";
		elseif ($option == 5) echo ">Moderators</option>";
		elseif ($option == 6) echo ">Super Moderators</option>";
		elseif ($option == 7) echo ">Admins</option>";
		elseif ($option == 10) echo ">Disabled</option>";
	}

	echo '</select></td></tr>';
	echo '</table></td></tr>';
	thr();
	//End of modification

	//Modification forum button visibility
	echo "<tr><td><table id=\"forumbtnaccess\"><tr><th>Forum Button visibility</th><td>";
	echo "<select name=\"forumbtnaccess\">";
	$value = (int) get_setting('forumbtnaccess');

	$options = array(1, 2, 3, 5, 6, 7, 10);

	foreach ($options as $option) {
		echo "<option value=\"$option\"";

		if ($value == $option) {
			echo ' selected';
		}

		if ($option == 1) echo ">All</option>";
		elseif ($option == 2) echo ">Registered guests</option>";
		elseif ($option == 3) echo ">Members</option>";
		elseif ($option == 5) echo ">Moderators</option>";
		elseif ($option == 6) echo ">Super Moderators</option>";
		elseif ($option == 7) echo ">Admins</option>";
		elseif ($option == 10) echo ">Disabled</option>";
	}

	echo '</select></td></tr>';
	echo '</table></td></tr>';
	thr();
	//End of modification

	//Modification forum button link

	echo "<tr><td><table id=\"forumbtnlink\"><tr><th>Forum Button link</th><td>";
	echo "<input type=\"text\" name=\"forumbtnlink\" value=\"" . htmlspecialchars(get_setting('forumbtnlink')) . '">';
	echo '</td></tr></table></td></tr>';
	thr();
	//End of modification

	//MODIFICATION adminjoinleavemsg to not create a system message if an admins arrives or leaves the chat
	echo "<tr><td><table id=\"adminjoinleavemsg\"><tr><th>Show system message if an admin joined or left the chat</th><td>";
	echo "<select name=\"adminjoinleavemsg\">";
	$value = (bool) get_setting('adminjoinleavemsg');
	echo '<option value="0"';
	if (!$value) {
		echo ' selected';
	}
	echo ">$I[disabled]</option>";
	echo '<option value="1"';
	if ($value) {
		echo ' selected';
	}
	echo ">$I[enabled]</option>";
	echo '</select></td></tr>';
	echo '</table></td></tr>';
	thr();
	//End of Modification

	//MODIFICATION clickablenicknamesglobal to enable/disable clickablenicknames, e. g. in case of errors
	echo "<tr><td><table id=\"clickablenicknamesglobal\"><tr><th>Clickable nicknames</th><td>";
	echo "<select name=\"clickablenicknamesglobal\">";
	$value = (bool) get_setting('clickablenicknamesglobal');
	echo '<option value="0"';
	if (!$value) {
		echo ' selected';
	}
	echo ">$I[disabled]</option>";
	echo '<option value="1"';
	if ($value) {
		echo ' selected';
	}
	echo ">$I[enabled]</option>";
	echo '</select></td></tr>';
	echo '</table></td></tr>';
	thr();
	//End of Modification

	// Modification Spare Notes.
	// Spare Notes name
	echo '<tr><td><table id="sparenotesname"><tr><th>Spare Notes Name</th><td>';
	echo '<input type="text" name="sparenotesname" value="' . htmlspecialchars(get_setting('sparenotesname')) . '">';
	echo '</td></tr></table></td></tr>';
	thr();
	// Spare Notes Access
	echo "<tr><td><table id=\"sparenotesaccess\"><tr><th>Spare Notes Access</th><td>";
	echo "<select name=\"sparenotesaccess\">";
	$value = (int) get_setting('sparenotesaccess');

	$options = array(3, 5, 6, 7, 10);

	foreach ($options as $option) {
		echo "<option value=\"$option\"";

		if ($value == $option) {
			echo ' selected';
		}

		if ($option == 3) echo ">Members</option>";
		elseif ($option == 5) echo ">Moderators</option>";
		elseif ($option == 6) echo ">Super Moderators</option>";
		elseif ($option == 7) echo ">Admins</option>";
		elseif ($option == 10) echo ">Disabled</option>";
	}
	// End of Modification
	echo '</select></td></tr>';
	echo '</table></td></tr>';
	thr();

	// Modificatin create chat rooms
	echo "<tr><td><table id=\"roomcreateaccess\"><tr><th>Rooms can be created by:</th><td>";
	echo "<select name=\"roomcreateaccess\">";
	$value = (int) get_setting('roomcreateaccess');

	$options = array(5, 6, 7);

	foreach ($options as $option) {
		echo "<option value=\"$option\"";

		if ($value == $option) {
			echo ' selected';
		}

		if ($option == 5) echo ">Moderators</option>";
		elseif ($option == 6) echo ">Super Moderators</option>";
		elseif ($option == 7) echo ">Admins</option>";
	}
	echo '</select></td></tr>';
	echo '</table></td></tr>';
	thr();
	echo "<tr><td><table id=\"roomexpire\"><tr><th>Room Timeout (minutes)</th><td>";
	echo "<input type=\"number\" name=\"roomexpire\" value=\"" . get_setting('roomexpire') . '">';
	echo '</td></tr></table></td></tr>';
	thr();

	echo "<tr><td><table id=\"channelvisinroom\"><tr><th>Channels visible in all rooms</th><td>";
	echo "<select name=\"channelvisinroom\">";
	$value = (int) get_setting('channelvisinroom');
	$options = array(2, 3, 5, 6, 7, 9);

	foreach ($options as $option) {
		echo "<option value=\"$option\"";

		if ($value == $option) {
			echo ' selected';
		}

		if ($option == 2) echo ">All Channels</option>";
		elseif ($option == 3) echo ">Member Channels</option>";
		elseif ($option == 5) echo ">Staff Channels</option>";
		elseif ($option == 6) echo ">SMod Channels</option>";
		elseif ($option == 7) echo ">Admin Channel</option>";
		elseif ($option == 9) echo ">No channels</option>";
	}
	echo '</select></td></tr>';
	echo '</table></td></tr>';
	thr();
	// End of Modification





	/*****************************************
	 *SETTINGS ONLY FOR SUPER ADMIN ARE BELOW
	 ******************************************/
	if ($U['status'] == 8) {

		echo '<tr><td><table>';
		echo "<font color='red'>↓ Setting(s) below can only be viewed and edited by Super Admin  ↓</font>";
		echo '</td></tr></table>';

		thr();
		//MODIFICATION modsdeladminmsg to allow mods deleting admin messages
		echo "<tr><td><table id=\"modsdeladminmsg\"><tr><th>Staff members can delete messages of higher ranked staff members</th><td>";
		echo "<select name=\"modsdeladminmsg\">";
		$value = (bool) get_setting('modsdeladminmsg');
		echo '<option value="0"';
		if (!$value) {
			echo ' selected';
		}
		echo ">$I[disabled]</option>";
		echo '<option value="1"';
		if ($value) {
			echo ' selected';
		}
		echo ">$I[enabled]</option>";
		echo '</select></td></tr>';
		echo '</table></td></tr>';
		thr();
		//End of Modification

		//MODIFICATION incognitomode setting only for super admin.
		echo "<tr><td><table id=\"incognito\"><tr><th>" . $I['incognito'] . "</th><td>";
		echo "<select name=\"incognito\">";
		$value = (bool) get_setting('incognito');
		echo '<option value="0"';
		if (!$value) {
			echo ' selected';
		}
		echo ">$I[disabled]</option>";
		echo '<option value="1"';
		if ($value) {
			echo ' selected';
		}
		echo ">$I[enabled]</option>";
		echo '</select></td></tr>';
		echo '</table></td></tr>';
		thr();
		//End of Modification

		echo '<tr><td><table>';
		echo "<font color='red'> ↑ Setting(s) above can only be viewed and edited by Super Admin ↑</font>";
		echo '</td></tr></table>';
		thr();
	} //End if

	/*****************************************
	 *SETTINGS ONLY FOR SUPER ADMIN ARE ABOVE
	 ******************************************/

	echo '<tr><td>' . submit($I['apply']) . '</td></tr></table></form><br>';
	if ($U['status'] == 8) {
		echo '<table id="actions"><tr><td>';
		echo form('setup', 'backup');
		if (!isset($_REQUEST['session'])) {
			echo hidden('session', $U['session']);
		}
		echo submit($I['backuprestore']) . '</form></td><td>';
		echo form('setup', 'destroy');
		if (!isset($_REQUEST['session'])) {
			echo hidden('session', $U['session']);
		}
		echo submit($I['destroy'], 'class="delbutton"') . '</form></td></tr></table><br>';
	}
	echo form_target('_parent', 'logout');
	if (!isset($_REQUEST['session'])) {
		echo hidden('session', $U['session']);
	}
	echo submit($I['logout'], 'id="exitbutton"') . '</form>' . credit();
	print_end();
}

function restore_backup($C)
{
	global $db, $memcached;
	if (!extension_loaded('json')) {
		return;
	}
	$code = json_decode($_REQUEST['restore'], true);
	if (isset($_REQUEST['settings'])) {
		foreach ($C['settings'] as $setting) {
			if (isset($code['settings'][$setting])) {
				update_setting($setting, $code['settings'][$setting]);
			}
		}
	}
	if (isset($_REQUEST['filter']) && (isset($code['filters']) || isset($code['linkfilters']))) {
		$db->exec('DELETE FROM ' . PREFIX . 'filter;');
		$db->exec('DELETE FROM ' . PREFIX . 'linkfilter;');
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'filter (filtermatch, filterreplace, allowinpm, regex, kick, cs) VALUES (?, ?, ?, ?, ?, ?);');
		foreach ($code['filters'] as $filter) {
			if (!isset($filter['cs'])) {
				$filter['cs'] = 0;
			}
			$stmt->execute([$filter['match'], $filter['replace'], $filter['allowinpm'], $filter['regex'], $filter['kick'], $filter['cs']]);
		}
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'linkfilter (filtermatch, filterreplace, regex) VALUES (?, ?, ?);');
		foreach ($code['linkfilters'] as $filter) {
			$stmt->execute([$filter['match'], $filter['replace'], $filter['regex']]);
		}
		if (MEMCACHED) {
			$memcached->delete(DBNAME . '-' . PREFIX . 'filter');
			$memcached->delete(DBNAME . '-' . PREFIX . 'linkfilter');
		}
	}
	if (isset($_REQUEST['members']) && isset($code['members'])) {
		$db->exec('DELETE FROM ' . PREFIX . 'inbox;');
		$db->exec('DELETE FROM ' . PREFIX . 'members;');
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'members (nickname, passhash, status, refresh, bgcolour, regedby, lastlogin, timestamps, embed, incognito, style, nocache, tz, eninbox, sortupdown, hidechatters, nocache_old) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);');
		foreach ($code['members'] as $member) {
			$new_settings = ['nocache', 'tz', 'eninbox', 'sortupdown', 'hidechatters', 'nocache_old'];
			foreach ($new_settings as $setting) {
				if (!isset($member[$setting])) {
					$member[$setting] = 0;
				}
			}
			$stmt->execute([$member['nickname'], $member['passhash'], $member['status'], $member['refresh'], $member['bgcolour'], $member['regedby'], $member['lastlogin'], $member['timestamps'], $member['embed'], $member['incognito'], $member['style'], $member['nocache'], $member['tz'], $member['eninbox'], $member['sortupdown'], $member['hidechatters'], $member['nocache_old']]);
		}
	}
	if (isset($_REQUEST['notes']) && isset($code['notes'])) {
		$db->exec('DELETE FROM ' . PREFIX . 'notes;');
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'notes (type, lastedited, editedby, text) VALUES (?, ?, ?, ?);');
		foreach ($code['notes'] as $note) {
			if ($note['type'] === 'admin') {
				$note['type'] = 0;
			} elseif ($note['type'] === 'staff') {
				$note['type'] = 1;
			}
			if (MSGENCRYPTED) {
				$note['text'] = base64_encode(sodium_crypto_aead_aes256gcm_encrypt($note['text'], '', AES_IV, ENCRYPTKEY));
			}
			$stmt->execute([$note['type'], $note['lastedited'], $note['editedby'], $note['text']]);
		}
	}
}

function send_backup($C)
{
	global $I, $db;
	$code = [];
	if ($_REQUEST['do'] === 'backup') {
		if (isset($_REQUEST['settings'])) {
			foreach ($C['settings'] as $setting) {
				$code['settings'][$setting] = get_setting($setting);
			}
		}
		if (isset($_REQUEST['filter'])) {
			$result = $db->query('SELECT * FROM ' . PREFIX . 'filter;');
			while ($filter = $result->fetch(PDO::FETCH_ASSOC)) {
				$code['filters'][] = ['match' => $filter['filtermatch'], 'replace' => $filter['filterreplace'], 'allowinpm' => $filter['allowinpm'], 'regex' => $filter['regex'], 'kick' => $filter['kick'], 'cs' => $filter['cs']];
			}
			$result = $db->query('SELECT * FROM ' . PREFIX . 'linkfilter;');
			while ($filter = $result->fetch(PDO::FETCH_ASSOC)) {
				$code['linkfilters'][] = ['match' => $filter['filtermatch'], 'replace' => $filter['filterreplace'], 'regex' => $filter['regex']];
			}
		}
		if (isset($_REQUEST['members'])) {
			$result = $db->query('SELECT * FROM ' . PREFIX . 'members;');
			while ($member = $result->fetch(PDO::FETCH_ASSOC)) {
				$code['members'][] = $member;
			}
		}
		if (isset($_REQUEST['notes'])) {
			$result = $db->query('SELECT * FROM ' . PREFIX . "notes;");
			while ($note = $result->fetch(PDO::FETCH_ASSOC)) {
				if (MSGENCRYPTED) {
					$note['text'] = sodium_crypto_aead_aes256gcm_decrypt(base64_decode($note['text']), '', AES_IV, ENCRYPTKEY);
				}
				$code['notes'][] = $note;
			}
		}
	}
	if (isset($_REQUEST['settings'])) {
		$chksettings = ' checked';
	} else {
		$chksettings = '';
	}
	if (isset($_REQUEST['filter'])) {
		$chkfilters = ' checked';
	} else {
		$chkfilters = '';
	}
	if (isset($_REQUEST['members'])) {
		$chkmembers = ' checked';
	} else {
		$chkmembers = '';
	}
	if (isset($_REQUEST['notes'])) {
		$chknotes = ' checked';
	} else {
		$chknotes = '';
	}
	print_start('backup');
	echo "<h2>$I[backuprestore]</h2><table>";
	thr();
	if (!extension_loaded('json')) {
		echo "<tr><td>$I[jsonextrequired]</td></tr>";
	} else {
		echo '<tr><td>' . form('setup', 'backup');
		echo '<table id="backup"><tr><td id="backupcheck">';
		echo "<label><input type=\"checkbox\" name=\"settings\" id=\"backupsettings\" value=\"1\"$chksettings>$I[settings]</label>";
		echo "<label><input type=\"checkbox\" name=\"filter\" id=\"backupfilter\" value=\"1\"$chkfilters>$I[filter]</label>";
		echo "<label><input type=\"checkbox\" name=\"members\" id=\"backupmembers\" value=\"1\"$chkmembers>$I[members]</label>";
		echo "<label><input type=\"checkbox\" name=\"notes\" id=\"backupnotes\" value=\"1\"$chknotes>$I[notes]</label>";
		echo '</td><td id="backupsubmit">' . submit($I['backup']) . '</td></tr></table></form></td></tr>';
		thr();
		echo '<tr><td>' . form('setup', 'restore');
		echo '<table id="restore">';
		echo "<tr><td colspan=\"2\"><textarea name=\"restore\" rows=\"4\" cols=\"60\">" . htmlspecialchars(json_encode($code)) . '</textarea></td></tr>';
		echo "<tr><td id=\"restorecheck\"><label><input type=\"checkbox\" name=\"settings\" id=\"restoresettings\" value=\"1\"$chksettings>$I[settings]</label>";
		echo "<label><input type=\"checkbox\" name=\"filter\" id=\"restorefilter\" value=\"1\"$chkfilters>$I[filter]</label>";
		echo "<label><input type=\"checkbox\" name=\"members\" id=\"restoremembers\" value=\"1\"$chkmembers>$I[members]</label>";
		echo "<label><input type=\"checkbox\" name=\"notes\" id=\"restorenotes\" value=\"1\"$chknotes>$I[notes]</label>";
		echo '</td><td id="restoresubmit">' . submit($I['restore']) . '</td></tr></table>';
		echo '</form></td></tr>';
	}
	thr();
	echo '<tr><td>' . form('setup') . submit($I['initgosetup'], 'class="backbutton"') . "</form></tr></td>";
	echo '</table>';
	print_end();
}

function send_destroy_chat()
{
	global $I;
	print_start('destroy_chat');
	echo "<table><tr><td colspan=\"2\">$I[confirm]</td></tr><tr><td>";
	echo form_target('_parent', 'setup', 'destroy') . hidden('confirm', 'yes') . submit($I['yes'], 'class="delbutton"') . '</form></td><td>';
	echo form('setup') . submit($I['no'], 'class="backbutton"') . '</form></td><tr></table>';
	print_end();
}

function send_delete_account()
{
	global $I;
	print_start('delete_account');
	echo "<table><tr><td colspan=\"2\">$I[confirm]</td></tr><tr><td>";
	echo form('profile', 'delete') . hidden('confirm', 'yes') . submit($I['yes'], 'class="delbutton"') . '</form></td><td>';
	echo form('profile') . submit($I['no'], 'class="backbutton"') . '</form></td><tr></table>';
	print_end();
}

function send_init()
{
	global $I, $L;
	print_start('init');
	echo "<h2>$I[init]</h2>";
	echo form('init') . "<table><tr><td><h3>$I[sulogin]</h3><table>";
	echo "<tr><td>$I[sunick]</td><td><input type=\"text\" name=\"sunick\" size=\"15\"></td></tr>";
	echo "<tr><td>$I[supass]</td><td><input type=\"password\" name=\"supass\" size=\"15\"></td></tr>";
	echo "<tr><td>$I[suconfirm]</td><td><input type=\"password\" name=\"supassc\" size=\"15\"></td></tr>";
	echo '</table></td></tr><tr><td><br>' . submit($I['initbtn']) . '</td></tr></table></form>';
	echo "<p id=\"changelang\">$I[changelang]";
	foreach ($L as $lang => $name) {
		echo " <a href=\"?action=setup&amp;lang=$lang\">$name</a>";
	}
	echo '</p>' . credit();
	print_end();
}

function send_update($msg)
{
	global $I;
	print_start('update');
	echo "<h2>$I[dbupdate]</h2><br>" . form('setup') . submit($I['initgosetup']) . "</form>$msg<br>" . credit();
	print_end();
}

function send_alogin()
{
	global $I, $L;
	print_start('alogin');
	echo form('setup') . '<table>';
	echo "<tr><td>$I[nick]</td><td><input type=\"text\" name=\"nick\" size=\"15\" autofocus></td></tr>";
	echo "<tr><td>$I[pass]</td><td><input type=\"password\" name=\"pass\" size=\"15\"></td></tr>";
	send_captcha();
	echo '<tr><td colspan="2">' . submit($I['login']) . '</td></tr></table></form>';
	echo "<p id=\"changelang\">$I[changelang]";
	foreach ($L as $lang => $name) {
		echo " <a href=\"?action=setup&amp;lang=$lang\">$name</a>";
	}
	echo '</p>' . credit();
	print_end();
}

function send_admin($arg = '')
{
	global $I, $U, $db;
	$ga = (int) get_setting('guestaccess');
	print_start('admin');
	$chlist = "<select name=\"name[]\" size=\"5\" multiple><option value=\"\">$I[choose]</option>";
	$chlist .= "<option value=\"s &amp;\">$I[allguests]</option>";
	$users = [];
	$stmt = $db->query('SELECT nickname, style, status FROM ' . PREFIX . 'sessions WHERE entry!=0 AND status>0 ORDER BY LOWER(nickname);');
	while ($user = $stmt->fetch(PDO::FETCH_NUM)) {
		$users[] = [htmlspecialchars($user[0]), $user[1], $user[2]];
	}
	foreach ($users as $user) {
		if ($user[2] < $U['status']) {
			$chlist .= "<option value=\"$user[0]\" style=\"$user[1]\">$user[0]</option>";
		}
	}
	$chlist .= '</select>';
	echo "<h2>$I[admfunc]</h2><i>$arg</i><table>";
	if ($U['status'] >= 7) {
		thr();
		echo '<tr><td>' . form_target('view', 'setup') . submit($I['initgosetup']) . '</form></td></tr>';
	}
	thr();
	echo "<tr><td><table id=\"clean\"><tr><th>$I[cleanmsgs]</th><td>";
	echo form('admin', 'clean');
	echo '<table><tr><td><label><input type="radio" name="what" id="room" value="chat">';
	echo ($I['chat'] ?? 'Chat') . "</label></td><td>&nbsp;</td><td><label><input type=\"radio\" name=\"what\" id=\"choose\" value=\"room\" checked>";
	echo $I['room'] . "</label></td><td>&nbsp;</td><td></tr><tr><td colspan=\"3\"><label><input type=\"radio\" name=\"what\" id=\"choose\" value=\"choose\" checked>";
	echo $I['selection'] . "</label></td><td>&nbsp;</td></tr><tr><td colspan=\"3\"><label><input type=\"radio\" name=\"what\" id=\"nick\" value=\"nick\">";
	echo $I['cleannick'] . "</label> <select name=\"nickname\" size=\"1\"><option value=\"\">$I[choose]</option>";
	$stmt = $db->prepare('SELECT poster FROM ' . PREFIX . "messages WHERE delstatus<? AND poster!='' GROUP BY poster;");
	$stmt->execute([$U['status']]);
	while ($nick = $stmt->fetch(PDO::FETCH_NUM)) {
		echo '<option value="' . htmlspecialchars($nick[0]) . '">' . htmlspecialchars($nick[0]) . '</option>';
	}
	echo '</select></td><td>';
	echo submit($I['clean'], 'class="delbutton"') . '</td></tr></table></form></td></tr></table></td></tr>';
	thr();
	echo '<tr><td><table id="kick"><tr><th>' . sprintf($I['kickchat'], get_setting('kickpenalty')) . '</th></tr><tr><td>';
	echo form('admin', 'kick');
	echo "<table><tr><td>$I[kickreason]</td><td><input type=\"text\" name=\"kickmessage\" size=\"30\"></td><td>&nbsp;</td></tr>";
	echo "<tr><td><label><input type=\"checkbox\" name=\"what\" value=\"purge\" id=\"purge\">$I[kickpurge]</label></td><td>$chlist</td><td>";
	echo submit($I['kick']) . '</td></tr></table></form></td></tr></table></td></tr>';
	thr();
	echo "<tr><td><table id=\"logout\"><tr><th>$I[logoutinact]</th><td>";
	echo form('admin', 'logout');
	echo "<table><tr><td>$chlist</td><td>";
	echo submit($I['logout']) . '</td></tr></table></form></td></tr></table></td></tr>';

	//MODIFICATION 2019-09-06 last-login table (show when members logged in the last time.
	$view_lastlogin = 'lastlogin';
	if ($U['status'] >= 5) {
		thr();
		echo "<tr><td><table id=\"$view_lastlogin\"><tr><th>" . "Last logins" . '</th><td>';
		echo form('admin', $view_lastlogin);
		echo submit($I['view']) . '</form></td></tr></table></td></tr>';
	}
	//MODIFICATION 2019-08-28 one line replaced with 6 lines of code
	//filter button and linkfilter button will only be shown to mods
	if ($U['status'] >= 5) {
		$views = ['sessions'];
	} else {
		$views = ['sessions'];
	}

	foreach ($views as $view) {
		thr();
		echo "<tr><td><table id=\"$view\"><tr><th>" . $I[$view] . '</th><td>';
		echo form('admin', $view);
		echo submit($I['view']) . '</form></td></tr></table></td></tr>';
	}
	
	// Filter Management (Mods+ 5) - Split into categories
	if ($U['status'] >= 5) {
		thr();
		echo "<tr><td><table id=\"filters\"><tr><th>Filter Management</th></tr>";
		echo "<tr><td style='padding:10px;'>";
		echo "<div style='display:grid; grid-template-columns: repeat(3, 1fr); gap:10px; max-width:600px;'>";
		echo "<div>" . form('admin', 'filter_all') . submit('All Filters') . '</form></div>';
		echo "<div>" . form('admin', 'filter') . submit('General Filters') . '</form></div>';
		echo "<div>" . form('admin', 'filter_warnings') . submit('Warning Filters') . '</form></div>';
		echo "<div>" . form('admin', 'filter_kick') . submit('Kick Filters') . '</form></div>';
		echo "<div>" . form('admin', 'filter_commands') . submit('Bot Commands') . '</form></div>';
		echo "<div>" . form('admin', 'filter_staff') . submit('Staff Filters') . '</form></div>';
		echo "<div>" . form('admin', 'linkfilter') . submit('Link Filters') . '</form></div>';
		echo "</div>";
		echo "</td></tr></table></td></tr>";
	}
	
	thr();
	//Modification chat rooms.
	$roomcreateaccess = (int) get_setting('roomcreateaccess');
	if ($U['status'] >= $roomcreateaccess) {
		echo "<tr><td><table id=\"chatrooms\"><tr><th>" . 'Chat Rooms</th><td>';
		echo form('admin', 'rooms');
		echo submit($I['view']) . '</form></td></tr></table></td></tr>';
		thr();
	}
	
	// User History Viewer (Mods+)
	if ($U['status'] >= 5) {
		echo "<tr><td><table id=\"userhistory\"><tr><th>User History Viewer</th><td>";
		echo form('admin', 'userhistory');
		echo submit($I['view']) . '</form></td></tr></table></td></tr>';
		thr();
	}
	
	// Audit Log Viewer (Mods+)
	if ($U['status'] >= 5 && moderation_tables_exist()) {
		echo "<tr><td><table id=\"auditlog\"><tr><th>Audit Log</th><td>";
		echo form('admin', 'auditlog');
		echo submit($I['view']) . '</form></td></tr></table></td></tr>';
		thr();
	}
	
	// Appeals Queue (Mods+)
	if ($U['status'] >= 5 && moderation_tables_exist()) {
		// Get pending appeal count
		$stmt = $db->query('SELECT COUNT(*) FROM ' . PREFIX . 'appeals WHERE status="pending";');
		$appeal_count = $stmt->fetch(PDO::FETCH_NUM)[0];
		
		echo "<tr><td><table id=\"appeals\"><tr><th>Appeal Queue" . ($appeal_count > 0 ? " ($appeal_count pending)" : "") . "</th><td>";
		echo form('admin', 'appeals');
		echo submit($I['view']) . '</form></td></tr></table></td></tr>';
		thr();
	}
	
	// Auto-Moderation Rules (Mods can view, Super Mods+ can manage)
	if ($U['status'] >= 5 && moderation_tables_exist()) {
		echo "<tr><td><table id=\"automod\"><tr><th>Auto-Moderation Rules</th><td>";
		echo form('admin', 'automod');
		echo submit($U['status'] >= 6 ? $I['view'] : $I['view']) . '</form></td></tr></table></td></tr>';
		thr();
	}

	//Modification "html topic" (Topic can be set by Supermods and above)
	if ($U['status'] >= 6) {

		echo "<tr><td><table id=\"topic\"><tr><th>$I[topic]</th><td>";
		echo form('admin', 'topic');
		echo '<table><tr><td><input type="text" name="topic" size="20" value="' . htmlspecialchars(get_setting('topic')) . '"></td><td>';
		echo submit($I['change']) . '</td></tr></table></form></td></tr></table></td></tr>';
		thr();
		
		// Applicant Approval Queue (Chat Admins 6+)
		$stmt_app = $db->query('SELECT COUNT(*) FROM ' . PREFIX . 'members WHERE status=2;');
		$applicant_count = $stmt_app->fetch(PDO::FETCH_NUM)[0];
		
		echo "<tr><td><table id=\"applicants\"><tr><th>Applicant Approval Queue" . ($applicant_count > 0 ? " (<span style='color:#ff6600;'>$applicant_count pending</span>)" : "") . "</th><td>";
		echo form('admin', 'applicants');
		echo submit($I['view']) . '</form></td></tr></table></td></tr>';
		thr();
	}

	echo "<tr><td><table id=\"guestaccess\"><tr><th>$I[guestacc]</th><td>";
	echo form('admin', 'guestaccess');
	echo '<table>';
	echo '<tr><td><select name="guestaccess">';
	echo '<option value="1"';
	if ($ga === 1) {
		echo ' selected';
	}
	echo ">$I[guestallow]</option>";
	echo '<option value="2"';
	if ($ga === 2) {
		echo ' selected';
	}
	echo ">$I[guestwait]</option>";
	echo '<option value="3"';
	if ($ga === 3) {
		echo ' selected';
	}
	echo ">$I[adminallow]</option>";
	echo '<option value="0"';
	if ($ga === 0) {
		echo ' selected';
	}
	echo ">$I[guestdisallow]</option>";
	if ($ga === 4) {
		echo '<option value="4" selected';
		echo ">$I[disablechat]</option>";
	}
	echo '</select></td><td>' . submit($I['change']) . '</td></tr></table></form></td></tr></table></td></tr>';
	thr();
	if ($U['status'] >= 6) {
		echo "<tr><td><table id=\"status\"><tr><th>$I[admmembers]</th><td>";
		echo form('admin', 'status');
		echo "<table><td><select name=\"name\" size=\"1\"><option value=\"\">$I[choose]</option>";
		$members = [];
		$result = $db->query('SELECT nickname, style, status FROM ' . PREFIX . 'members ORDER BY status ASC, LOWER(nickname);');
		while ($temp = $result->fetch(PDO::FETCH_NUM)) {
			$members[] = [htmlspecialchars($temp[0]), $temp[1], $temp[2]];
		}
		foreach ($members as $member) {
			echo "<option value=\"$member[0]\" style=\"$member[1]\">$member[0]";
			if ($member[2] == 0) {
				echo ' (Banned)';
			} elseif ($member[2] == 1) {
				echo ' (Guest)';
			} elseif ($member[2] == 2) {
				echo ' (Applicant)';
			} elseif ($member[2] == 3) {
				echo ' (Member)';
			} elseif ($member[2] == 5) {
				echo ' (Mod)';
			} elseif ($member[2] == 6) {
				echo ' (Chat Admin)';
			} elseif ($member[2] == 7) {
				echo ' (Service Admin)';
			} elseif ($member[2] == 8) {
				echo ' (System Admin)';
			} elseif ($member[2] == 10) {
				echo ' (Bot)';
			}
			echo '</option>';
		}
		echo "</select><select name=\"set\" size=\"1\"><option value=\"\">$I[choose]</option><option value=\"-\">$I[memdel]</option><option value=\"0\">$I[memdeny]</option>";
		if (get_setting('suguests')) {
			echo "<option value=\"2\">Applicant</option>";
		}
		echo "<option value=\"3\">Member</option>";
		if ($U['status'] >= 7) {
			echo "<option value=\"5\">Moderator</option>";
			echo "<option value=\"6\">Chat Admin</option>";
		}
		if ($U['status'] >= 8) {
			echo "<option value=\"7\">Service Admin</option>";
		}
		echo '</select></td><td>' . submit($I['change']) . '</td></tr></table></form></td></tr></table></td></tr>';
		thr();
		echo "<tr><td><table id=\"passreset\"><tr><th>$I[passreset]</th><td>";
		echo form('admin', 'passreset');
		echo "<table><td><select name=\"name\" size=\"1\"><option value=\"\">$I[choose]</option>";
		foreach ($members as $member) {
			echo "<option value=\"$member[0]\" style=\"$member[1]\">$member[0]</option>";
		}
		echo '</select></td><td><input type="password" name="pass"></td><td>' . submit($I['change']) . '</td></tr></table></form></td></tr></table></td></tr>';
		thr();
		////Modification Add Applicant (from guest)
		if (get_setting('suguests')) {
			echo "<tr><td><table id=\"suguests\"><tr><th>Register Guest as Applicant</th><td>";
			echo form('admin', 'superguest');
			echo "<table><tr><td><select name=\"name\" size=\"1\"><option value=\"\">$I[choose]</option>";
			foreach ($users as $user) {
				if ($user[2] == 1) {
					echo "<option value=\"$user[0]\" style=\"$user[1]\">$user[0]</option>";
				}
			}
			echo '</select></td><td>' . submit($I['register']) . '</td></tr></table></form></td></tr></table></td></tr>';
			thr();
		}
		////Modification Register guest/applicant as Member
		echo "<tr><td><table id=\"register\"><tr><th>Register Guest/Applicant as Member</th><td>";
		echo form('admin', 'register');
		echo "<table><tr><td><select name=\"name\" size=\"1\"><option value=\"\">$I[choose]</option>";
		foreach ($users as $user) {
			if ($user[2] == 1 || $user[2] == 2) {
				echo "<option value=\"$user[0]\" style=\"$user[1]\">$user[0]</option>";
			}
		}
		echo '</select></td><td>' . submit($I['register']) . '</td></tr></table></form></td></tr></table></td></tr>';
		thr();
		////Modification Register new Applicant
		echo "<tr><td><table id=\"regnew\"><tr><th>" . (get_setting('suguests') ? "Register new Applicant" : $I['regmem']) . "</th></tr><tr><td>";
		echo form('admin', 'regnew');
		echo "<table><tr><td>$I[nick]</td><td>&nbsp;</td><td><input type=\"text\" name=\"name\" size=\"20\"></td><td>&nbsp;</td></tr>";
		echo "<tr><td>$I[pass]</td><td>&nbsp;</td><td><input type=\"password\" name=\"pass\" size=\"20\"></td><td>";
		echo submit($I['register']) . '</td></tr></table></form></td></tr></table></td></tr>';
		thr();
	}
	echo "</table><br>";
	echo form('admin') . submit($I['reload']) . '</form>';
	print_end();
}

/**
 * Display applicant approval queue (status 2 users awaiting member approval)
 * Chat Admins (6+) can approve to Member (3), ban (0), or leave as Applicant
 */
function send_applicant_queue()
{
	global $I, $U, $db;
	
	// Only Chat Admins (6+) can access this
	if ($U['status'] < 6) {
		print_start('applicants');
		echo "<h2>Applicant Queue</h2>";
		echo "<p>You don't have permission to access this page. Chat Admins (6+) only.</p>";
		print_end();
		return;
	}
	
	print_start('applicants');
	echo "<h2>Applicant Approval Queue</h2>";
	echo "<p>Review applicants (status 2) awaiting approval. Approve to promote to Member (status 3), or Ban to set status 0.</p>";
	
	// Get all applicants (status 2) - order by id (oldest first)
	$stmt = $db->query('SELECT nickname, style, status, regedby, lastlogin FROM ' . PREFIX . 'members WHERE status=2 ORDER BY id ASC;');
	$applicants = $stmt->fetchAll(PDO::FETCH_ASSOC);
	
	if (empty($applicants)) {
		echo "<p><strong>No applicants in queue.</strong></p>";
		echo form('admin') . submit($I['reload']) . '</form>';
		print_end();
		return;
	}
	
	echo "<table border='1' cellpadding='5' cellspacing='0'>";
	echo "<tr><th>Nickname</th><th>Registered By</th><th>Last Login</th><th>Infractions</th><th>Notes</th><th>Actions</th></tr>";
	
	foreach ($applicants as $applicant) {
		$nick = htmlspecialchars($applicant['nickname']);
		$style = $applicant['style'];
		$regedby = htmlspecialchars($applicant['regedby'] ?: 'Self');
		$lastlogin = $applicant['lastlogin'] > 0 ? date('Y-m-d H:i', $applicant['lastlogin']) : 'Never';
		
		// Check for infractions (kicks, warnings)
		$stmt_infr = $db->prepare('SELECT COUNT(*) FROM ' . PREFIX . 'user_history WHERE username=? AND action_type IN (?, ?) AND expired=0;');
		$stmt_infr->execute([$applicant['nickname'], 'kick', 'warning']);
		$infraction_count = $stmt_infr->fetch(PDO::FETCH_NUM)[0];
		
		// Get notes - notes table uses type='user_nickname' format
		$note_type = 'user_' . $applicant['nickname'];
		$stmt_notes = $db->prepare('SELECT text FROM ' . PREFIX . 'notes WHERE type=? ORDER BY id DESC LIMIT 1;');
		$stmt_notes->execute([$note_type]);
		$note = $stmt_notes->fetch(PDO::FETCH_ASSOC);
		$note_preview = '';
		if ($note && !empty($note['text'])) {
			// Decrypt if encrypted
			if (MSGENCRYPTED) {
				$decrypted = sodium_crypto_aead_aes256gcm_decrypt(base64_decode($note['text']), '', AES_IV, ENCRYPTKEY);
				$note_preview = mb_substr(strip_tags($decrypted), 0, 50);
			} else {
				$note_preview = mb_substr(strip_tags($note['text']), 0, 50);
			}
			if (mb_strlen($note_preview) == 50) $note_preview .= '...';
		}
		
		echo "<tr>";
		echo "<td>" . style_this($nick, $style) . "</td>";
		echo "<td>$regedby</td>";
		echo "<td>$lastlogin</td>";
		echo "<td>" . ($infraction_count > 0 ? "<span style='color:red;'>$infraction_count</span>" : "0") . "</td>";
		echo "<td>" . ($note_preview ? htmlspecialchars($note_preview) : "<em>None</em>") . "</td>";
		echo "<td>";
		
		// Approve button (promote to Member - status 3)
		echo form('admin', 'applicant_action');
		echo hidden('applicant_nick', $applicant['nickname']);
		echo hidden('applicant_action', 'approve');
		echo submit('✓ Approve', 'style="background-color:#28a745;color:white;padding:3px 10px;"');
		echo "</form> ";
		
		// Ban button (set status 0)
		echo form('admin', 'applicant_action');
		echo hidden('applicant_nick', $applicant['nickname']);
		echo hidden('applicant_action', 'ban');
		echo submit('✗ Ban', 'style="background-color:#dc3545;color:white;padding:3px 10px;"');
		echo "</form>";
		
		echo "</td>";
		echo "</tr>";
	}
	
	echo "</table><br>";
	echo "<p><strong>Total applicants:</strong> " . count($applicants) . "</p>";
	echo form('admin') . submit($I['reload']) . '</form>';
	print_end();
}

function send_sessions()
{
	global $I, $U, $db;
	$stmt = $db->prepare('SELECT nickname, style, lastpost, status, useragent, ip FROM ' . PREFIX . 'sessions WHERE entry!=0 AND (incognito=0 OR status<? OR nickname=?) ORDER BY status DESC, lastpost DESC;');
	$stmt->execute([$U['status'], $U['nickname']]);
	if (!$lines = $stmt->fetchAll(PDO::FETCH_ASSOC)) {
		$lines = [];
	}
	print_start('sessions');
	echo "<h1>$I[sessact]</h1><table>";
	echo "<tr><th>$I[sessnick]</th><th>$I[sesstimeout]</th><th>$I[sessua]</th>";
	$trackip = (bool) get_setting('trackip');
	$memexpire = (int) get_setting('memberexpire');
	$guestexpire = (int) get_setting('guestexpire');
	if ($trackip) echo "<th>$I[sesip]</th>";
	echo "<th>$I[actions]</th></tr>";
	foreach ($lines as $temp) {
		if ($temp['status'] == 0) {
			$s = ' (Banned)';
		} elseif ($temp['status'] == 1) {
			$s = ' (Guest)';
		} elseif ($temp['status'] == 2) {
			$s = ' (Applicant)';
		} elseif ($temp['status'] == 3) {
			$s = ' (Member)';
		} elseif ($temp['status'] == 5) {
			$s = ' (Mod)';
		} elseif ($temp['status'] == 6) {
			$s = ' (Chat Admin)';
		} elseif ($temp['status'] == 7) {
			$s = ' (Service Admin)';
		} elseif ($temp['status'] == 8) {
			$s = ' (System Admin)';
		} elseif ($temp['status'] == 10) {
			$s = ' (Bot)';
		} else {
			$s = '';
		}
		echo '<tr><td class="nickname">' . style_this(htmlspecialchars($temp['nickname']) . $s, $temp['style']) . '</td><td class="timeout">';
		if ($temp['status'] > 2) {
			echo get_timeout($temp['lastpost'], $memexpire);
		} else {
			echo get_timeout($temp['lastpost'], $guestexpire);
		}
		echo '</td>';
		if ($U['status'] > $temp['status'] || $U['nickname'] === $temp['nickname']) {
			echo "<td class=\"ua\">$temp[useragent]</td>";
			if ($trackip) {
				echo "<td class=\"ip\">$temp[ip]</td>";
			}
			echo '<td class="action">';
			if ($temp['nickname'] !== $U['nickname']) {
				echo '<table><tr>';
				if ($temp['status'] != 0) {
					echo '<td>';
					echo form('admin', 'sessions');
					echo hidden('kick', '1') . hidden('nick', htmlspecialchars($temp['nickname'])) . submit($I['kick']) . '</form>';
					echo '</td>';
				}
				echo '<td>';
				echo form('admin', 'sessions');
				echo hidden('logout', '1') . hidden('nick', htmlspecialchars($temp['nickname'])) . submit($temp['status'] == 0 ? $I['unban'] : $I['logout']) . '</form>';
				echo '</td></tr></table>';
			} else {
				echo '-';
			}
			echo '</td></tr>';
		} else {
			echo '<td class="ua">-</td>';
			if ($trackip) {
				echo '<td class="ip">-</td>';
			}
			echo '<td class="action">-</td></tr>';
		}
	}
	echo "</table><br>";
	echo form('admin', 'sessions') . submit($I['reload']) . '</form>';
	print_end();
}

//MODIFICATION 2019-09-06 Featrue: last login table. function send_lastlogin() added.
function send_lastlogin()
{
	global $I, $U, $db;

	if ($U['status'] >= 7) {
		$stmt = $db->prepare('SELECT nickname, status, lastlogin, style FROM ' . PREFIX . 'members ORDER BY status DESC, lastlogin DESC');
		$stmt->execute();

		if (!$lines = $stmt->fetchAll(PDO::FETCH_ASSOC)) {
			$lines = [];
		}
		print_start('lastlogin');
		echo "<h1>Last logins</h1><table id=table_lastlogins>";

		echo "<tr><th>Nickname</th><th>Last login</th>";

		foreach ($lines as $temp) {

			if ($temp['status'] == 0) {
				$s = ' (K)';
			} elseif ($temp['status'] <= 2) {
				$s = ' (G)';
			} elseif ($temp['status'] == 3) {
				$s = '';
			} elseif ($temp['status'] == 5) {
				$s = ' (M)';
			} elseif ($temp['status'] == 6) {
				$s = ' (SM)';
			} elseif ($temp['status'] == 7) {
				$s = ' (A)';
			} else {
				$s = ' (SA)';
			}

			echo '<tr><td class="nickname">' . style_this(htmlspecialchars($temp['nickname']) . $s, $temp['style'] . '</td>');
			if ($temp['lastlogin'] === '0') {
				echo '<td class="lastlogin">unknown</td>';
			} else {
				echo '<td class="lastlogin">' . date('l jS \of F Y h:i:s A', $temp['lastlogin']) . '</td>';
			}
		}
		echo "</table><br>";
		echo form('admin', 'lastlogin') . submit($I['reload']) . '</form>';
		print_end();
	}
}

function send_gallery($site = 1)
{
	global $I, $U, $db;

	print_start('gallery');
	echo "<h1>The 404 Gallery</h1>";

	if ($U['status'] < (int)get_setting('galleryaccess')) {
		echo "<p>You are not allowed to view the gallery</p>";
		print_end();
		return;
	}

	$images = [];
	
	// 1. Get uploaded image files from database
	$stmt = $db->prepare('SELECT f.hash, f.filename, f.type, m.poster, m.postdate FROM ' . PREFIX . 'files f INNER JOIN ' . PREFIX . 'messages m ON f.postid=m.id WHERE m.poststatus<=? AND (m.roomid IN (SELECT id FROM ' . PREFIX . 'rooms WHERE access<=?) OR m.roomid IS NULL OR m.poststatus>1) AND f.type LIKE "image/%" ORDER BY m.id DESC;');
	$stmt->execute([$U['status'], $U['status']]);
	
	while ($file = $stmt->fetch(PDO::FETCH_ASSOC)) {
		$images[] = [
			'url' => '?action=download&amp;id=' . $file['hash'],
			'type' => 'upload',
			'filename' => htmlspecialchars($file['filename']),
			'poster' => htmlspecialchars($file['poster']),
			'date' => $file['postdate']
		];
	}
	
	// 2. Get external image URLs from messages
	$stmt = $db->prepare('SELECT id, text, poster, postdate FROM ' . PREFIX . 'messages WHERE poststatus<=? AND (roomid IN (SELECT id FROM ' . PREFIX . 'rooms WHERE access<=?) OR roomid IS NULL OR poststatus>1) ORDER BY id DESC;');
	$stmt->execute([$U['status'], $U['status']]);
	
	while ($message = $stmt->fetch(PDO::FETCH_ASSOC)) {
		prepare_message_print($message, true);
		
		// Extract image URLs from message text - look for common image extensions
		if (preg_match_all('/<img\s+[^>]*src=[\"\']([^\"\']+)[\"\'][^>]*>/i', $message['text'], $matches)) {
			foreach ($matches[1] as $imgUrl) {
				// Exclude local resources (emojis, icons, rank badges)
				if (!preg_match('/\/(emojis|pngs|rank|css|assets)\//i', $imgUrl) && 
				    !preg_match('/^data:image/i', $imgUrl)) {
					$images[] = [
						'url' => $imgUrl,
						'type' => 'external',
						'poster' => htmlspecialchars($message['poster']),
						'date' => $message['postdate']
					];
				}
			}
		}
		
		// Extract all links and check if they're images
		if (preg_match_all('/<a\s+[^>]*href=[\"\']([^\"\']+)[\"\'][^>]*>/i', $message['text'], $matches)) {
			foreach ($matches[1] as $imgUrl) {
				$decodedUrl = html_entity_decode($imgUrl);
				// Skip local resources and already processed download links
				if (preg_match('/\/(emojis|pngs|rank|css|assets)\//i', $decodedUrl)) {
					continue;
				}
				
				// Include if:
				// 1. URL ends with image extension
				// 2. URL contains common image hosting patterns (preview, image, img, media, etc.)
				// 3. URL is from known image hosts
				$isImageUrl = preg_match('/\.(jpg|jpeg|png|gif|bmp|webp)(\?|$)/i', $decodedUrl) ||
				              preg_match('/(\/preview\/|\/image\/|\/img\/|\/media\/|\/file\/|\/i\/|imgbox|imgur|postimg|imageban|imagebam|pixhost|4-0-4\.io)/i', $decodedUrl);
				
				if ($isImageUrl) {
					$images[] = [
						'url' => $imgUrl,
						'type' => 'link',
						'poster' => htmlspecialchars($message['poster']),
						'date' => $message['postdate']
					];
				}
			}
		}
	}	
	// Remove duplicates
	$images = array_values(array_unique($images, SORT_REGULAR));
	
	$total_images = count($images);
	$posts_per_page = 24; // Show 24 images per page (4x6 grid)
	$total_pages = max(1, ceil($total_images / $posts_per_page));
	$site = max(1, min($site, $total_pages));
	$start = ($site - 1) * $posts_per_page;
	$end = min($start + $posts_per_page, $total_images);
	
	// Add CSS for gallery
	echo '<style>
		.gallery-container { 
			max-width: 1400px; 
			margin: 0 auto; 
			padding: 20px; 
			background: var(--pri-col1, #111);
			color: var(--button-text-col, #ddd);
			font-family: var(--font, arial);
		}
		.gallery-stats { 
			text-align: center; 
			margin: 20px 0; 
			color: var(--accent-temp, #b4b0b0);
			font-size: 14px;
		}
		.pagination { 
			display: flex; 
			justify-content: center; 
			align-items: center; 
			gap: 8px; 
			margin: 20px 0; 
			flex-wrap: wrap; 
		}
		.pagination form { margin: 0; }
		.pagination input[type="submit"] { 
			padding: 8px 14px; 
			cursor: pointer;
			background: var(--pri-col2, #1a1e23);
			color: var(--button-text-col, #ddd);
			border: 1px solid var(--accent3, #000);
			border-radius: 3px;
			font-family: var(--font, arial);
			transition: all 0.2s;
		}
		.pagination input[type="submit"]:hover {
			background: var(--sec-col2, #00bfff);
			color: var(--pri-col1, #111);
		}
		.pagination .current { 
			background: var(--sec-col2, #00bfff);
			color: var(--pri-col1, #111);
			font-weight: bold;
		}
		.pagination span { 
			color: var(--accent-temp, #b4b0b0);
			padding: 0 5px;
		}
		.gallery-grid { 
			display: grid; 
			grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); 
			gap: 12px; 
			margin: 20px 0; 
		}
		.gallery-item { 
			position: relative; 
			aspect-ratio: 1; 
			overflow: hidden; 
			border: 2px solid var(--accent3, #000); 
			border-radius: 3px; 
			background: var(--sec-col1, #000);
			transition: border-color 0.2s;
		}
		.gallery-item:hover {
			border-color: var(--sec-col2, #00bfff);
		}
		.gallery-item img { 
			width: 100%; 
			height: 100%; 
			object-fit: cover; 
			cursor: pointer; 
			transition: transform 0.2s; 
		}
		.gallery-item:hover img { 
			transform: scale(1.05); 
		}
		.gallery-item-info { 
			position: absolute; 
			bottom: 0; 
			left: 0; 
			right: 0; 
			background: rgba(0,0,0,0.85); 
			color: var(--accent, #ffff80); 
			padding: 6px 8px; 
			font-size: 11px; 
			opacity: 0; 
			transition: opacity 0.2s;
			word-break: break-all;
		}
		.gallery-item:hover .gallery-item-info { 
			opacity: 1; 
		}
		.gallery-lightbox { 
			display: none; 
			position: fixed; 
			top: 0; 
			left: 0; 
			right: 0; 
			bottom: 0; 
			background: rgba(0,0,0,0.96); 
			z-index: 99999; 
			cursor: crosshair;
			overflow-y: auto;
			overflow-x: hidden;
			padding: 20px 0;
		}
		.gallery-lightbox:target { 
			display: block;
		}
		.gallery-lightbox > a {
			display: block;
			width: 100%;
			position: fixed;
			top: 0;
			left: 0;
			right: 0;
			bottom: 0;
			z-index: -1;
		}
		.gallery-lightbox-content { 
			position: relative;
			margin: 0 auto;
			width: fit-content;
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			pointer-events: none;
		}
		.gallery-lightbox img { 
			max-width: 95vw; 
			max-height: 95vh; 
			width: auto;
			height: auto;
			object-fit: contain; 
			border: 3px solid var(--sec-col2, #00bfff);
			box-shadow: 0 0 30px rgba(0,191,255,0.3);
			display: block;
		}
		.gallery-lightbox-info { 
			color: var(--accent, #ffff80); 
			text-align: center; 
			margin-top: 15px;
			padding: 0 20px;
			font-size: 13px;
			text-shadow: 0 0 5px rgba(0,0,0,0.8);
			pointer-events: auto;
			position: relative;
			z-index: 100000;
		}
		.gallery-lightbox-info a {
			color: var(--sec-col2, #00bfff);
			text-decoration: none;
			cursor: pointer;
		}
		.gallery-lightbox-info a:hover {
			text-decoration: underline;
		}
		.gallery-nav { 
			display: flex; 
			justify-content: center; 
			gap: 15px; 
			margin: 25px 0; 
		}
		.gallery-nav form { margin: 0; }
		.gallery-nav input[type="submit"] {
			padding: 10px 20px;
			background: var(--pri-col2, #1a1e23);
			color: var(--button-text-col, #ddd);
			border: 1px solid var(--accent3, #000);
			border-radius: 3px;
			cursor: pointer;
			font-family: var(--font, arial);
			transition: all 0.2s;
		}
		.gallery-nav input[type="submit"]:hover {
			background: var(--sec-col2, #00bfff);
			color: var(--pri-col1, #111);
		}
		.gallery-empty {
			text-align: center;
			color: var(--accent-temp, #b4b0b0);
			margin: 60px 0;
			font-size: 16px;
		}
	</style>';
	
	echo '<div class="gallery-container">';
	
	if ($total_images === 0) {
		echo '<p class="gallery-empty">No images found in chat history.</p>';
		echo '<div class="gallery-nav">';
		echo form_target('view', 'view') . submit('Back to chat') . '</form>';
		echo '</div>';
		echo '</div>';
		print_end();
		return;
	}
	
	echo '<div class="gallery-stats">';
	echo "Showing images " . ($start + 1) . "-$end of $total_images";
	echo '</div>';
	
	// Pagination
	if ($total_pages > 1) {
		echo '<div class="pagination">';
		if ($site > 1) {
			echo form('gallery', $site - 1) . submit('« Previous') . '</form>';
		}
		
		// Show page numbers
		for ($i = 1; $i <= $total_pages; $i++) {
			if ($i == $site) {
				echo form('gallery', $i) . submit($i, 'class="current"') . '</form>';
			} elseif ($i == 1 || $i == $total_pages || abs($i - $site) <= 2) {
				echo form('gallery', $i) . submit($i) . '</form>';
			} elseif (abs($i - $site) == 3) {
				echo '<span>...</span>';
			}
		}
		
		if ($site < $total_pages) {
			echo form('gallery', $site + 1) . submit('Next »') . '</form>';
		}
		echo '</div>';
	}
	
	// Gallery grid
	echo '<div class="gallery-grid">';
	for ($i = $start; $i < $end; $i++) {
		$img = $images[$i];
		$imgId = 'img' . $i;
		echo '<div class="gallery-item">';
		echo '<a href="#' . $imgId . '">';
		echo '<img src="' . $img['url'] . '" alt="Gallery image" loading="lazy">';
		echo '</a>';
		echo '<div class="gallery-item-info">';
		echo $img['poster'];
		if (!empty($img['filename'])) {
			echo '<br>' . $img['filename'];
		}
		echo '</div>';
		echo '</div>';
		
		// Lightbox - clicking anywhere closes it
		echo '<div id="' . $imgId . '" class="gallery-lightbox">';
		echo '<a href="#_"></a>'; // Invisible full-screen close area
		echo '<div class="gallery-lightbox-content">';
		echo '<img src="' . $img['url'] . '" alt="Gallery image">';
		echo '<div class="gallery-lightbox-info">';
		echo 'Posted by: <strong>' . $img['poster'] . '</strong>';
		if (!empty($img['filename'])) {
			echo ' | ' . $img['filename'];
		}
		echo ' | ' . date('Y-m-d H:i', $img['date']);
		echo '<br><a href="' . $img['url'] . '" target="_blank">Open in new tab</a>';
		echo '</div>';
		echo '</div>';
		echo '</div>';
	}
	echo '</div>';
	
	// Bottom navigation
	echo '<div class="gallery-nav">';
	echo form('gallery', $site) . submit($I['reload'] ?? 'Reload') . '</form>';
	echo form_target('view', 'view') . submit('Back to chat') . '</form>';
	echo '</div>';
	
	echo '</div>';
	print_end();
}

//MODIFICATION links page
function send_links_page()
{

	global $I;

	if (get_setting('linksenabled') === '1') {
		$links = get_setting('links');
		print_start('links');
		if (!empty($links)) {
			echo "<div id=\"links\"><h2>The 404 Chat Changelog (and Canary)</h2><br>$links<br>" . form_target('view', 'view') . submit('Back to chat') . "</form></div>";
		}
	} else {
		return;
	}
}

// Get current room name for display
function get_current_room_name()
{
	global $U, $db;
	if ($U['roomid'] === null) {
		return 'Main Chat';
	}
	$stmt = $db->prepare('SELECT name FROM ' . PREFIX . 'rooms WHERE id=?;');
	$stmt->execute([$U['roomid']]);
	if ($name = $stmt->fetch(PDO::FETCH_NUM)) {
		return $name[0];
	}
	return 'Unknown Room';
}

// Modification change chat rooms
function change_room()
{
	global $U, $db, $bridge;

	// Track old room before changing
	$oldRoom = $U['roomid'] !== null ? "r " . $U['roomid'] : "room";

	if ($_REQUEST['room'] === '*') {
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET roomid=NULL WHERE id=?;');
		$stmt->execute([$U['id']]);
		$newRoom = "room";
		$U['roomid'] = null;
	} else {
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET roomid=(SELECT id FROM ' . PREFIX . 'rooms WHERE id=? AND access<=?) WHERE id=?;');
		$stmt->execute([$_REQUEST['room'], $U['status'], $U['id']]);
		$newRoom = "r " . $_REQUEST['room'];
		$U['roomid'] = $_REQUEST['room'];
	}

	// Bridge integration: notify IRC of room change
	if (BRIDGE_ENABLED && $oldRoom !== $newRoom) {
		if (!isset($bridge) || !$bridge->isConnected()) {
			$bridge = new BridgeClient();
			$bridge->connect();
		}

		if ($bridge->isConnected()) {
			$bridge->notifyDestChange($U['nickname'], $oldRoom, $newRoom);
		}
	}

	// Set session flag to indicate room change for post box reload
	$_SESSION['room_changed'] = true;
}

// Modification select chat rooms
function print_rooms()
{
	global $db, $U;
	echo '<div id="roomblock">';
	echo '<div class="room-header">';
	echo '<span class="room-label">💬 Switch Room</span>';
	echo '</div>';
	echo '<div class="room-selector">';
	echo form_target('view', 'view');
	echo "<select name=\"room\" id=\"room\">";
	echo '<option value="*">[Main Chat]</option>';
	$stmt = $db->prepare('SELECT id, name FROM ' . PREFIX . 'rooms WHERE access<=? ORDER BY id ASC;');
	$stmt->execute([$U['status']]);
	if (!$rooms = $stmt->fetchAll(PDO::FETCH_ASSOC)) {
		$rooms = [];
	}
	foreach ($rooms as $room) {
		$stmt = $db->prepare('SELECT id FROM ' . PREFIX . 'sessions WHERE roomid=?;');
		$stmt->execute([$room['id']]);
		$num = count($stmt->fetchAll());
		echo "<option value=\"$room[id]\"";
		if ($U['roomid'] === $room['id']) {
			echo ' selected';
		}
		echo ">$room[name] ($num)</option>";
	}
	echo '</select>';
	echo submit('Switch');
	echo '</form>';
	echo '</div>';
	echo '</div>';
}

// Modification rooms in admin page
function send_rooms($arg = '')
{
	global $I, $U, $db;
	print_start('linkfilter');
	echo "<h2>Chat Rooms</h2><i>$arg</i><table>";
	thr();
	echo '<tr><th><table style="width:100%;"><tr>';
	echo "<td style=\"width:8em;\">Room ID:</td>";
	echo "<td style=\"width:12em;\">Name</td>";
	echo "<td style=\"width:12em;\">Access</td>";
	if ($U['status'] > 6) {
		echo "<td style=\"width:10em;\">Permanent</td>";
	}
	echo "<td style=\"width:5em;\">$I[apply]</td>";
	echo "<td style=\"width:8em;\">Expires in</td>";
	echo '</tr></table></th></tr>';
	$stmt = $db->prepare('SELECT * FROM ' . PREFIX . 'rooms WHERE access<=? ORDER BY id ASC;');
	$stmt->execute([$U['status']]);
	if (!$rooms = $stmt->fetchAll(PDO::FETCH_ASSOC)) {
		$rooms = [];
	}
	foreach ($rooms as $room) {
		if ($room['permanent'] && $U['status'] <= 6) {
			continue;
		}
		if ($room['permanent']) {
			$checkedpm = ' checked';
		} else {
			$checkedpm = '';
		}
		echo '<tr><td>';
		echo form('admin', 'rooms') . hidden('id', $room['id']);
		echo "<table style=\"width:100%;\"><tr><th style=\"width:8em;\">Room $room[id]:</th>";
		echo "<td style=\"width:12em;\"><input type=\"text\" name=\"name\" value=\"$room[name]\" size=\"20\" style=\"$U[style]\"></td>";
		echo '<td style="width:12em;">';
		echo "<select name=\"access\">";

		$options = array(1, 2, 3, 5, 6, 7, 8, 10);

		foreach ($options as $option) {
			if ($U['status'] < $option) {
				break;
			}
			echo "<option value=\"$option\"";

			if ($room['access'] == $option) {
				echo ' selected';
			}

			if ($option == 1) echo ">All</option>";
			elseif ($option == 2) echo ">Registered guests</option>";
			elseif ($option == 3) echo ">Members</option>";
			elseif ($option == 5) echo ">Moderators</option>";
			elseif ($option == 6) echo ">Super Moderators</option>";
			elseif ($option == 7) echo ">Admins</option>";
			elseif ($option == 8) echo ">Super Admins</option>";
			elseif ($option == 10) echo ">Disabled</option>";
		}

		echo '</select></td>';
		if ($U['status'] > 6) {
			echo "<td style=\"width:10em;\"><label><input type=\"checkbox\" name=\"permanent\" value=\"1\"$checkedpm>Permanent</label></td>";
		}
		echo '<td class="roomsubmit" style="width:5em;">' . submit($I['change']) . '</td>';
		$stmt = $db->prepare('SELECT null FROM ' . PREFIX . 'sessions WHERE roomid=?;');
		$stmt->execute([$room['id']]);
		if ($stmt->fetch(PDO::FETCH_NUM) || $room['permanent']) {
			echo "<th style=\"width:8em;\">--:--</th>";
		} else {
			$expire = (int) get_setting('roomexpire');
			echo "<th style=\"width:8em;\">" . get_timeout($room['time'], $expire) . '</th>';
		}
		echo "</tr></table></form></td></tr>";
	}
	echo '<tr><td>';
	echo form('admin', 'rooms') . hidden('id', '+');
	echo "<table style=\"width:100%;\"><tr><th style=\"width:8em;\">New Room</th>";
	echo "<td style=\"width:12em;\"><input type=\"text\" name=\"name\" value=\"\" size=\"20\" style=\"$U[style]\"></td>";
	echo '<td style="width:12em;">';
	echo "<select name=\"access\">";

	$options = array(1, 2, 3, 5, 6, 7, 8, 10);

	foreach ($options as $option) {
		if ($U['status'] < $option) {
			break;
		}
		echo "<option value=\"$option\"";

		if ($option == 1) echo ">All</option>";
		elseif ($option == 2) echo ">Registered guests</option>";
		elseif ($option == 3) echo ">Members</option>";
		elseif ($option == 5) echo ">Moderators</option>";
		elseif ($option == 6) echo ">Super Moderators</option>";
		elseif ($option == 7) echo ">Admins</option>";
		elseif ($option == 8) echo ">Super Admins</option>";
		elseif ($option == 10) echo ">Disabled</option>";
	}

	echo '</select></td>';
	if ($U['status'] > 6) {
		echo "<td style=\"width:10em;\"><label><input type=\"checkbox\" name=\"permanent\" value=\"1\">Permanent</label></td>";
	}
	echo '<td class="roomsubmit" style="width:5em;">' . submit($I['add']) . '</td>';
	echo "<th style=\"width:8em;\"></th>";
	echo "</tr></table></form></td></tr></table><br>";
	echo form('admin', 'rooms') . submit($I['reload']) . '</form>';
	print_end();
}

//Forum Link was moved to the post box (function send_post)
/*
function send_to_forum(){

    echo "Add redirect to forum here";

}
*/

// Modification chat rooms.
function manage_rooms()
{
	global $U, $db;
	if (!isset($_REQUEST['id']) || !isset($_REQUEST['access']) || !isset($_REQUEST['name']) || $U['status'] < $_REQUEST['access']) {
		return;
	}
	if (!preg_match('/^[A-Za-z0-9\-() ]{0,50}$/', $_REQUEST['name'])) {
		return "Invalid Name.";
	}
	if (isset($_REQUEST['permanent']) && $_REQUEST['permanent'] && $U['status'] > 6) {
		$permanent = 1;
	} else {
		$permanent = 0;
	}
	if ($_REQUEST['id'] === '+' && $_REQUEST['name'] !== '') {
		$stmt = $db->prepare('SELECT null FROM ' . PREFIX . 'rooms WHERE name=?');
		$stmt->execute([$_REQUEST['name']]);
		if ($stmt->fetch(PDO::FETCH_NUM)) {
			return;
		}
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'rooms (name, access, time, permanent) VALUES (?, ?, ?, ?);');
		$stmt->execute([$_REQUEST['name'], $_REQUEST['access'], time(), $permanent]);
	} elseif ($_REQUEST['name'] !== '') {
		$stmt = $db->prepare('SELECT null FROM ' . PREFIX . 'rooms WHERE name=? AND id!=?;');
		$stmt->execute([$_REQUEST['name'], $_REQUEST['id']]);
		if ($stmt->fetch(PDO::FETCH_NUM)) {
			return;
		}
		if ($U['status'] < 7) {
			$stmt = $db->prepare('SELECT null FROM ' . PREFIX . 'rooms WHERE id=? AND permanent=1;');
			$stmt->execute([$_REQUEST['id']]);
			if ($stmt->fetch(PDO::FETCH_NUM)) {
				return;
			}
		}
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'rooms SET name=?, access=?, permanent=? WHERE id=? AND access<=?;');
		$stmt->execute([$_REQUEST['name'], $_REQUEST['access'], $permanent, $_REQUEST['id'], $U['status']]);
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET roomid=NULL WHERE roomid=? AND status<?;');
		$stmt->execute([$_REQUEST['id'], $_REQUEST['access']]);
	} else {
		remove_room(false, $_REQUEST['id'], $U['status']);
	}
}

function remove_room($all = false, $id = '', $status = 10)
{
	global $db;
	if ($all) {
		//placeholder
	} else {
		$stmt = $db->prepare('SELECT id FROM ' . PREFIX . "rooms WHERE id=? AND access<=?;");
		$stmt->execute([$id, $status]);
		if ($room = $stmt->fetch(PDO::FETCH_ASSOC)) {
			$name = $stmt->fetch(PDO::FETCH_NUM);
			$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'rooms WHERE id=?;');
			$stmt->execute([$room['id']]);
			$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'messages WHERE roomid=?;');
			$stmt->execute([$room['id']]);
			$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET roomid=NULL WHERE roomid=?;');
			$stmt->execute([$room['id']]);
		}
	}
}


function check_filter_match(&$reg)
{
	global $I;
	$_REQUEST['match'] = htmlspecialchars($_REQUEST['match']);
	if (isset($_REQUEST['regex']) && $_REQUEST['regex'] == 1) {
		if (!valid_regex($_REQUEST['match'])) {
			return "$I[incorregex]<br>$I[prevmatch]: $_REQUEST[match]";
		}
		$reg = 1;
	} else {
		$_REQUEST['match'] = preg_replace('/([^\w\d])/u', "\\\\$1", $_REQUEST['match']);
		$reg = 0;
	}
	if (mb_strlen($_REQUEST['match']) > 255) {
		return "$I[matchtoolong]<br>$I[prevmatch]: $_REQUEST[match]";
	}
	return false;
}

function manage_filter()
{
	global $db, $memcached, $U;
	if (isset($_REQUEST['id'])) {
		$reg = 0;
		if ($tmp = check_filter_match($reg)) {
			return $tmp;
		}
		if (isset($_REQUEST['allowinpm']) && $_REQUEST['allowinpm'] == 1) {
			$pm = 1;
		} else {
			$pm = 0;
		}
		if (isset($_REQUEST['kick']) && $_REQUEST['kick'] == 1) {
			$kick = 1;
		} else {
			$kick = 0;
		}
		if (isset($_REQUEST['cs']) && $_REQUEST['cs'] == 1) {
			$cs = 1;
		} else {
			$cs = 0;
		}
		if (isset($_REQUEST['bot_reply']) && $_REQUEST['bot_reply'] == 1) {
			$bot_reply = 1;
		} else {
			$bot_reply = 0;
		}
		if (isset($_REQUEST['warn']) && $_REQUEST['warn'] == 1) {
			$warn = 1;
		} else {
			$warn = 0;
		}
		if (isset($_REQUEST['staff_only']) && $_REQUEST['staff_only'] == 1) {
			$staff_only = 1;
		} else {
			$staff_only = 0;
		}
		
		$changed_by = $U['nickname'];
		$changed_date = time();
		
		if (preg_match('/^[0-9]+$/', $_REQUEST['id'])) {
			if (empty($_REQUEST['match'])) {
				// Delete filter
				$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'filter WHERE id=?;');
				$stmt->execute([$_REQUEST['id']]);
				log_audit($U['nickname'], $U['status'], 'filter_deleted', null, null, "Deleted filter ID " . $_REQUEST['id']);
			} else {
				// Update filter
				$stmt = $db->prepare('UPDATE ' . PREFIX . 'filter SET filtermatch=?, filterreplace=?, allowinpm=?, regex=?, kick=?, cs=?, bot_reply=?, warn=?, staff_only=?, last_changed_by=?, last_changed_date=? WHERE id=?;');
				$stmt->execute([$_REQUEST['match'], $_REQUEST['replace'], $pm, $reg, $kick, $cs, $bot_reply, $warn, $staff_only, $changed_by, $changed_date, $_REQUEST['id']]);
				log_audit($U['nickname'], $U['status'], 'filter_updated', null, null, "Updated filter ID " . $_REQUEST['id'] . ": " . substr($_REQUEST['match'], 0, 30));
			}
		} elseif ($_REQUEST['id'] === '+') {
			// Insert new filter
			$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'filter (filtermatch, filterreplace, allowinpm, regex, kick, cs, bot_reply, warn, staff_only, last_changed_by, last_changed_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);');
			$stmt->execute([$_REQUEST['match'], $_REQUEST['replace'], $pm, $reg, $kick, $cs, $bot_reply, $warn, $staff_only, $changed_by, $changed_date]);
			log_audit($U['nickname'], $U['status'], 'filter_created', null, null, "Created filter: " . substr($_REQUEST['match'], 0, 30));
		}
		if (MEMCACHED) {
			$memcached->delete(DBNAME . '-' . PREFIX . 'filter');
		}
	}
}

function manage_linkfilter()
{
	global $db, $memcached;
	if (isset($_REQUEST['id'])) {
		$reg = 0;
		if ($tmp = check_filter_match($reg)) {
			return $tmp;
		}
		if (preg_match('/^[0-9]+$/', $_REQUEST['id'])) {
			if (empty($_REQUEST['match'])) {
				$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'linkfilter WHERE id=?;');
				$stmt->execute([$_REQUEST['id']]);
			} else {
				$stmt = $db->prepare('UPDATE ' . PREFIX . 'linkfilter SET filtermatch=?, filterreplace=?, regex=? WHERE id=?;');
				$stmt->execute([$_REQUEST['match'], $_REQUEST['replace'], $reg, $_REQUEST['id']]);
			}
		} elseif ($_REQUEST['id'] === '+') {
			$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'linkfilter (filtermatch, filterreplace, regex) VALUES (?, ?, ?);');
			$stmt->execute([$_REQUEST['match'], $_REQUEST['replace'], $reg]);
		}
		if (MEMCACHED) {
			$memcached->delete(DBNAME . '-' . PREFIX . 'linkfilter');
		}
	}
}

function get_filters()
{
	global $db, $memcached;
	if (MEMCACHED) {
		$filters = $memcached->get(DBNAME . '-' . PREFIX . 'filter');
	}
	if (!MEMCACHED || $memcached->getResultCode() !== Memcached::RES_SUCCESS) {
		$filters = [];
		$result = $db->query('SELECT id, filtermatch, filterreplace, allowinpm, regex, kick, cs, bot_reply, warn, staff_only, last_changed_by, last_changed_date, filter_order FROM ' . PREFIX . 'filter ORDER BY filter_order ASC, id ASC;');
		while ($filter = $result->fetch(PDO::FETCH_ASSOC)) {
			$filters[] = [
				'id' => $filter['id'], 
				'match' => $filter['filtermatch'], 
				'replace' => $filter['filterreplace'], 
				'allowinpm' => $filter['allowinpm'], 
				'regex' => $filter['regex'], 
				'kick' => $filter['kick'], 
				'cs' => $filter['cs'], 
				'bot_reply' => $filter['bot_reply'],
				'warn' => $filter['warn'] ?? 0,
				'staff_only' => $filter['staff_only'] ?? 0,
				'last_changed_by' => $filter['last_changed_by'],
				'last_changed_date' => $filter['last_changed_date'],
				'filter_order' => $filter['filter_order'] ?? 0
			];
		}
		if (MEMCACHED) {
			$memcached->set(DBNAME . '-' . PREFIX . 'filter', $filters);
		}
	}
	return $filters;
}

function get_linkfilters()
{
	global $db, $memcached;
	if (MEMCACHED) {
		$filters = $memcached->get(DBNAME . '-' . PREFIX . 'linkfilter');
	}
	if (!MEMCACHED || $memcached->getResultCode() !== Memcached::RES_SUCCESS) {
		$filters = [];
		$result = $db->query('SELECT id, filtermatch, filterreplace, regex FROM ' . PREFIX . 'linkfilter;');
		while ($filter = $result->fetch(PDO::FETCH_ASSOC)) {
			$filters[] = ['id' => $filter['id'], 'match' => $filter['filtermatch'], 'replace' => $filter['filterreplace'], 'regex' => $filter['regex']];
		}
		if (MEMCACHED) {
			$memcached->set(DBNAME . '-' . PREFIX . 'linkfilter', $filters);
		}
	}
	return $filters;
}

function get_botcommands()
{
	global $db, $memcached;
	if (MEMCACHED) {
		$commands = $memcached->get(DBNAME . '-' . PREFIX . 'botcommands');
	}
	if (!MEMCACHED || $memcached->getResultCode() !== Memcached::RES_SUCCESS) {
		$commands = [];
		try {
			$result = $db->query('SELECT id, command, response, min_status FROM ' . PREFIX . 'botcommands ORDER BY command;');
			while ($cmd = $result->fetch(PDO::FETCH_ASSOC)) {
				$commands[] = $cmd;
			}
		} catch (Exception $e) {
			// Table doesn't exist yet
		}
		if (MEMCACHED) {
			$memcached->set(DBNAME . '-' . PREFIX . 'botcommands', $commands);
		}
	}
	return $commands;
}

function get_datalist_options($roomid = null, $current_nickname = null, $user_status = 0)
{
	global $db, $U;
	$options = '';
	// Built-in commands
	$options .= "<option value=\"/me \">";
	$options .= "<option value=\"/whisper \">";
	$options .= "<option value=\"/help\">";
	$options .= "<option value=\"/afk \">";
	// Only show /back if user is currently AFK
	if (!empty($U['afk'])) {
		$options .= "<option value=\"/back\">";
	}
	$options .= "<option value=\"/locate \">";
	$options .= "<option value=\"/shrug \">";
	$options .= "<option value=\"/flip \">";
	$options .= "<option value=\"/unflip \">";
	
	// Custom bot commands - only show if user has sufficient status
	$bot_commands = get_botcommands();
	foreach ($bot_commands as $cmd) {
		if ($user_status >= $cmd['min_status']) {
			$options .= "<option value=\"." . htmlspecialchars($cmd['command']) . "\">";
		}
	}
	
	// @mentions for users in current room
	if ($roomid && $current_nickname) {
		$stmt_users = $db->prepare('SELECT nickname FROM ' . PREFIX . 'sessions WHERE roomid=? AND entry!=0 AND status>0 AND incognito=0 AND nickname!=? ORDER BY LOWER(nickname);');
		$stmt_users->execute([$roomid, $current_nickname]);
		while ($room_user = $stmt_users->fetch(PDO::FETCH_ASSOC)) {
			$options .= "<option value=\"@" . htmlspecialchars($room_user['nickname']) . " \">";
		}
	}
	
	return $options;
}

function manage_botcommands()
{
	global $db, $memcached, $U;
	if (isset($_REQUEST['id'])) {
		// Validate min_status doesn't exceed current user's status
		$min_status = isset($_REQUEST['min_status']) ? (int)$_REQUEST['min_status'] : 0;
		if ($min_status > $U['status']) {
			$min_status = $U['status']; // Cap at user's current status
		}
		
		if (preg_match('/^[0-9]+$/', $_REQUEST['id'])) {
			if (empty($_REQUEST['command'])) {
				$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'botcommands WHERE id=?;');
				$stmt->execute([$_REQUEST['id']]);
			} else {
				$stmt = $db->prepare('UPDATE ' . PREFIX . 'botcommands SET command=?, response=?, min_status=? WHERE id=?;');
				$stmt->execute([$_REQUEST['command'], $_REQUEST['response'], $min_status, $_REQUEST['id']]);
			}
		} elseif ($_REQUEST['id'] === '+') {
			$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'botcommands (command, response, min_status) VALUES (?, ?, ?);');
			$stmt->execute([$_REQUEST['command'], $_REQUEST['response'], $min_status]);
		}
		if (MEMCACHED) {
			$memcached->delete(DBNAME . '-' . PREFIX . 'botcommands');
		}
	}
}

function send_botcommands($arg = '')
{
	global $I, $U;
	print_start('botcommands');
	echo "<h2>Bot Commands</h2><i>$arg</i>";
	echo "<p style='margin:10px 0;'>Custom bot commands that users can trigger with <strong>.</strong> prefix (e.g., .help). These reply via bot PM and don't post a message.</p>";
	echo "<table>";
	thr();
	echo '<tr><th><table style="width:100%;"><tr>';
	echo "<td style=\"width:8em;\">ID</td>";
	echo "<td style=\"width:15em;\">Command</td>";
	echo "<td style=\"width:25em;\">Response</td>";
	echo "<td style=\"width:10em;\">Min Status</td>";
	echo "<td style=\"width:5em;\">Apply</td>";
	echo '</tr></table></th></tr>';
	$commands = get_botcommands();
	foreach ($commands as $cmd) {
		echo '<tr><td>';
		echo form('admin', 'botcommands') . hidden('id', $cmd['id']);
		echo "<table style=\"width:100%;\"><tr><th style=\"width:8em;\">Command $cmd[id]:</th>";
		echo "<td style=\"width:15em;\"><input type=\"text\" name=\"command\" value=\"" . htmlspecialchars($cmd['command']) . "\" size=\"20\" style=\"$U[style]\" placeholder=\"help\"></td>";
		echo '<td style="width:25em;"><input type="text" name="response" value="' . htmlspecialchars($cmd['response']) . "\" size=\"40\" style=\"$U[style]\" placeholder=\"Welcome! Here's how to use this chat...\"></td>";
		echo "<td style=\"width:10em;\"><select name=\"min_status\" style=\"$U[style]\">";
		if ($U['status'] >= 0) echo "<option value=\"0\"" . ($cmd['min_status'] == 0 ? ' selected' : '') . ">Everyone (0)</option>";
		if ($U['status'] >= 1) echo "<option value=\"1\"" . ($cmd['min_status'] == 1 ? ' selected' : '') . ">Guests (1+)</option>";
		if ($U['status'] >= 2) echo "<option value=\"2\"" . ($cmd['min_status'] == 2 ? ' selected' : '') . ">Applicants (2+)</option>";
		if ($U['status'] >= 3) echo "<option value=\"3\"" . ($cmd['min_status'] == 3 ? ' selected' : '') . ">Members (3+)</option>";
		if ($U['status'] >= 5) echo "<option value=\"5\"" . ($cmd['min_status'] == 5 ? ' selected' : '') . ">Moderators (5+)</option>";
		if ($U['status'] >= 6) echo "<option value=\"6\"" . ($cmd['min_status'] == 6 ? ' selected' : '') . ">Super-Mods (6+)</option>";
		if ($U['status'] >= 7) echo "<option value=\"7\"" . ($cmd['min_status'] == 7 ? ' selected' : '') . ">Admins (7+)</option>";
		echo "</select></td>";
		echo '<td class="filtersubmit" style="width:5em;">' . submit($I['change']) . '</td></tr></table></form></td></tr>';
	}
	echo '<tr><td>';
	echo form('admin', 'botcommands') . hidden('id', '+');
	echo "<table style=\"width:100%;\"><tr><th style=\"width:8em\">New Command</th>";
	echo "<td style=\"width:15em;\"><input type=\"text\" name=\"command\" value=\"\" size=\"20\" style=\"$U[style]\" placeholder=\"help\"></td>";
	echo "<td style=\"width:25em;\"><input type=\"text\" name=\"response\" value=\"\" size=\"40\" style=\"$U[style]\" placeholder=\"Welcome! Here's how to use this chat...\"></td>";
	echo "<td style=\"width:10em;\"><select name=\"min_status\" style=\"$U[style]\">";
	if ($U['status'] >= 0) echo "<option value=\"0\">Everyone (0)</option>";
	if ($U['status'] >= 1) echo "<option value=\"1\">Guests (1+)</option>";
	if ($U['status'] >= 2) echo "<option value=\"2\">Applicants (2+)</option>";
	if ($U['status'] >= 3) echo "<option value=\"3\">Members (3+)</option>";
	if ($U['status'] >= 5) echo "<option value=\"5\">Moderators (5+)</option>";
	if ($U['status'] >= 6) echo "<option value=\"6\">Super-Mods (6+)</option>";
	if ($U['status'] >= 7) echo "<option value=\"7\">Admins (7+)</option>";
	echo "</select></td>";
	echo '<td class="filtersubmit" style="width:5em;">' . submit($I['add']) . '</td></tr></table></form></td></tr>';
	echo "</table><br>";
	echo form('admin', 'botcommands') . submit($I['reload']) . '</form>';
	print_end();
}

function send_filter_all($arg = '')
{
	global $I, $U;
	print_start('filter');
	echo "<h2>All Filters</h2><i>$arg</i>";
	echo "<p><strong>View:</strong> All text replacement filters with complete settings</p>";
	
	echo "<table>";
	thr();
	echo '<tr><th><table style="width:100%;"><tr>';
	echo "<td style=\"width:4em;\">ID</td>";
	echo "<td style=\"width:12em;\">$I[match]</td>";
	echo "<td style=\"width:12em;\">$I[replace]</td>";
	echo "<td style=\"width:5em;\">$I[allowpm]</td>";
	echo "<td style=\"width:4em;\">$I[regex]</td>";
	echo "<td style=\"width:3em;\">$I[cs]</td>";
	echo "<td style=\"width:4em;\">Warn</td>";
	echo "<td style=\"width:4em;\">$I[kick]</td>";
	echo "<td style=\"width:4em;\">Bot PM</td>";
	echo "<td style=\"width:4em;\">Staff</td>";
	echo "<td style=\"width:8em;\">Last Changed</td>";
	echo "<td style=\"width:5em;\">$I[apply]</td>";
	echo '</tr></table></th></tr>';
	
	$filters = get_filters();
	
	foreach ($filters as $filter) {
		$check = ($filter['allowinpm'] == 1) ? ' checked' : '';
		$checked = ($filter['regex'] == 1) ? ' checked' : '';
		$checkedcs = ($filter['cs'] == 1) ? ' checked' : '';
		$checkedwarn = (!empty($filter['warn']) && $filter['warn'] == 1) ? ' checked' : '';
		$checkedk = (!empty($filter['kick']) && $filter['kick'] == 1) ? ' checked' : '';
		$checkedbot = (!empty($filter['bot_reply']) && $filter['bot_reply'] == 1) ? ' checked' : '';
		$checkedstaff = (!empty($filter['staff_only']) && $filter['staff_only'] == 1) ? ' checked' : '';
		
		if ($filter['regex'] != 1) {
			$filter['match'] = preg_replace('/(\\\\(.))/u', "$2", $filter['match']);
		}
		
		$last_changed = '';
		if (!empty($filter['last_changed_by'])) {
			$last_changed = htmlspecialchars($filter['last_changed_by']);
			if (!empty($filter['last_changed_date'])) {
				$last_changed .= '<br><small>' . date('Y-m-d', $filter['last_changed_date']) . '</small>';
			}
		}
		
		echo '<tr><td>';
		echo form('admin', 'filter_all') . hidden('id', $filter['id']) . hidden('filter_type', 'all');
		echo "<table style=\"width:100%;\"><tr><th style=\"width:4em;\">$filter[id]</th>";
		echo "<td style=\"width:12em;\"><input type=\"text\" name=\"match\" value=\"$filter[match]\" size=\"15\" style=\"$U[style]\"></td>";
		echo '<td style="width:12em;"><input type="text" name="replace" value="' . htmlspecialchars($filter['replace']) . "\" size=\"15\" style=\"$U[style]\"></td>";
		echo "<td style=\"width:5em;\"><label><input type=\"checkbox\" name=\"allowinpm\" value=\"1\"$check>PM</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"regex\" value=\"1\"$checked>RE</label></td>";
		echo "<td style=\"width:3em;\"><label><input type=\"checkbox\" name=\"cs\" value=\"1\"$checkedcs>CS</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"warn\" value=\"1\"$checkedwarn>W</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"kick\" value=\"1\"$checkedk>K</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"bot_reply\" value=\"1\"$checkedbot>Bot</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"staff_only\" value=\"1\"$checkedstaff>Staff</label></td>";
		echo "<td style=\"width:8em;\"><small>$last_changed</small></td>";
		echo '<td class="filtersubmit" style="width:5em;">' . submit($I['change']) . '</td></tr></table></form></td></tr>';
	}
	
	// Add new filter form
	echo '<tr><td>';
	echo form('admin', 'filter_all') . hidden('id', '+') . hidden('filter_type', 'all');
	echo "<table style=\"width:100%;\"><tr><th style=\"width:4em\">New</th>";
	echo "<td style=\"width:12em;\"><input type=\"text\" name=\"match\" value=\"\" size=\"15\" style=\"$U[style]\"></td>";
	echo "<td style=\"width:12em;\"><input type=\"text\" name=\"replace\" value=\"\" size=\"15\" style=\"$U[style]\"></td>";
	echo "<td style=\"width:5em;\"><label><input type=\"checkbox\" name=\"allowinpm\" id=\"allowinpm\" value=\"1\">PM</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"regex\" id=\"regex\" value=\"1\">RE</label></td>";
	echo "<td style=\"width:3em;\"><label><input type=\"checkbox\" name=\"cs\" id=\"cs\" value=\"1\">CS</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"warn\" id=\"warn\" value=\"1\">W</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"kick\" id=\"kick\" value=\"1\">K</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"bot_reply\" id=\"bot_reply\" value=\"1\">Bot</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"staff_only\" id=\"staff_only\" value=\"1\">Staff</label></td>";
	echo "<td style=\"width:8em;\"></td>";
	echo '<td class="filtersubmit" style="width:5em;">' . submit($I['add']) . '</td></tr></table></form></td></tr>';
	echo "</table><br>";
	
	echo "<p><small><strong>Legend:</strong> PM = Allow in PM | RE = Regex | CS = Case Sensitive | W = Warning | K = Kick | Bot = Bot PM Reply | Staff = Staff Only</small></p>";
	echo form('admin', 'filter_all') . submit($I['reload']) . '</form>';
	print_end();
}

function send_filter($arg = '')
{
	global $I, $U;
	print_start('filter');
	echo "<h2>General Filters</h2><i>$arg</i>";
	echo "<p><strong>Category:</strong> Standard text replacement filters (not warnings, kicks, commands, or staff-only)</p>";
	
	echo "<table>";
	thr();
	echo '<tr><th><table style="width:100%;"><tr>';
	echo "<td style=\"width:6em;\">$I[fid]</td>";
	echo "<td style=\"width:14em;\">$I[match]</td>";
	echo "<td style=\"width:14em;\">$I[replace]</td>";
	echo "<td style=\"width:7em;\">$I[allowpm]</td>";
	echo "<td style=\"width:4em;\">$I[regex]</td>";
	echo "<td style=\"width:4em;\">$I[cs]</td>";
	echo "<td style=\"width:8em;\">Last Changed</td>";
	echo "<td style=\"width:5em;\">$I[apply]</td>";
	echo '</tr></table></th></tr>';
	
	$filters = get_filters();
	
	foreach ($filters as $filter) {
		// Only show general filters (not warnings, kicks, commands, or staff-only)
		if (!empty($filter['warn']) || !empty($filter['kick']) || !empty($filter['bot_reply']) || !empty($filter['staff_only'])) {
			continue;
		}
		
		$check = ($filter['allowinpm'] == 1) ? ' checked' : '';
		$checked = ($filter['regex'] == 1) ? ' checked' : '';
		$checkedcs = ($filter['cs'] == 1) ? ' checked' : '';
		
		if ($filter['regex'] != 1) {
			$filter['match'] = preg_replace('/(\\\\(.))/u', "$2", $filter['match']);
		}
		
		$last_changed = '';
		if (!empty($filter['last_changed_by'])) {
			$last_changed = htmlspecialchars($filter['last_changed_by']);
			if (!empty($filter['last_changed_date'])) {
				$last_changed .= '<br><small>' . date('Y-m-d', $filter['last_changed_date']) . '</small>';
			}
		}
		
		echo '<tr><td>';
		echo form('admin', 'filter') . hidden('id', $filter['id']) . hidden('filter_type', 'general');
		echo "<table style=\"width:100%;\"><tr><th style=\"width:6em;\">$I[filter] $filter[id]:</th>";
		echo "<td style=\"width:14em;\"><input type=\"text\" name=\"match\" value=\"$filter[match]\" size=\"20\" style=\"$U[style]\"></td>";
		echo '<td style="width:14em;"><input type="text" name="replace" value="' . htmlspecialchars($filter['replace']) . "\" size=\"20\" style=\"$U[style]\"></td>";
		echo "<td style=\"width:7em;\"><label><input type=\"checkbox\" name=\"allowinpm\" value=\"1\"$check>$I[allowpm]</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"regex\" value=\"1\"$checked>$I[regex]</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"cs\" value=\"1\"$checkedcs>$I[cs]</label></td>";
		echo "<td style=\"width:8em;\"><small>$last_changed</small></td>";
		echo '<td class="filtersubmit" style="width:5em;">' . submit($I['change']) . '</td></tr></table></form></td></tr>';
	}
	
	// Add new filter form
	echo '<tr><td>';
	echo form('admin', 'filter') . hidden('id', '+') . hidden('filter_type', 'general');
	echo "<table style=\"width:100%;\"><tr><th style=\"width:6em\">$I[newfilter]</th>";
	echo "<td style=\"width:14em;\"><input type=\"text\" name=\"match\" value=\"\" size=\"20\" style=\"$U[style]\"></td>";
	echo "<td style=\"width:14em;\"><input type=\"text\" name=\"replace\" value=\"\" size=\"20\" style=\"$U[style]\"></td>";
	echo "<td style=\"width:7em;\"><label><input type=\"checkbox\" name=\"allowinpm\" id=\"allowinpm\" value=\"1\">$I[allowpm]</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"regex\" id=\"regex\" value=\"1\">$I[regex]</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"cs\" id=\"cs\" value=\"1\">$I[cs]</label></td>";
	echo "<td style=\"width:8em;\"></td>";
	echo '<td class="filtersubmit" style="width:5em;">' . submit($I['add']) . '</td></tr></table></form></td></tr>';
	echo "</table><br>";
	
	echo form('admin', 'filter') . submit($I['reload']) . '</form>';
	print_end();
}

function send_filter_warnings($arg = '')
{
	global $I, $U;
	print_start('filter');
	echo "<h2>Warning Filters</h2><i>$arg</i>";
	echo "<p><strong>Category:</strong> Filters that issue warnings to users on match</p>";
	
	echo "<table>";
	thr();
	echo '<tr><th><table style="width:100%;"><tr>';
	echo "<td style=\"width:6em;\">$I[fid]</td>";
	echo "<td style=\"width:14em;\">$I[match]</td>";
	echo "<td style=\"width:14em;\">$I[replace]</td>";
	echo "<td style=\"width:7em;\">$I[allowpm]</td>";
	echo "<td style=\"width:4em;\">$I[regex]</td>";
	echo "<td style=\"width:4em;\">$I[cs]</td>";
	echo "<td style=\"width:4em;\">Warn</td>";
	echo "<td style=\"width:8em;\">Last Changed</td>";
	echo "<td style=\"width:5em;\">$I[apply]</td>";
	echo '</tr></table></th></tr>';
	
	$filters = get_filters();
	
	foreach ($filters as $filter) {
		// Only show warning filters
		if (empty($filter['warn'])) {
			continue;
		}
		
		$check = ($filter['allowinpm'] == 1) ? ' checked' : '';
		$checked = ($filter['regex'] == 1) ? ' checked' : '';
		$checkedcs = ($filter['cs'] == 1) ? ' checked' : '';
		$checkedwarn = ' checked'; // Always checked for warning filters
		
		if ($filter['regex'] != 1) {
			$filter['match'] = preg_replace('/(\\\\(.))/u', "$2", $filter['match']);
		}
		
		$last_changed = '';
		if (!empty($filter['last_changed_by'])) {
			$last_changed = htmlspecialchars($filter['last_changed_by']);
			if (!empty($filter['last_changed_date'])) {
				$last_changed .= '<br><small>' . date('Y-m-d', $filter['last_changed_date']) . '</small>';
			}
		}
		
		echo '<tr><td>';
		echo form('admin', 'filter_warnings') . hidden('id', $filter['id']) . hidden('filter_type', 'warnings');
		echo "<table style=\"width:100%;\"><tr><th style=\"width:6em;\">$I[filter] $filter[id]:</th>";
		echo "<td style=\"width:14em;\"><input type=\"text\" name=\"match\" value=\"$filter[match]\" size=\"20\" style=\"$U[style]\"></td>";
		echo '<td style="width:14em;"><input type="text" name="replace" value="' . htmlspecialchars($filter['replace']) . "\" size=\"20\" style=\"$U[style]\"></td>";
		echo "<td style=\"width:7em;\"><label><input type=\"checkbox\" name=\"allowinpm\" value=\"1\"$check>$I[allowpm]</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"regex\" value=\"1\"$checked>$I[regex]</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"cs\" value=\"1\"$checkedcs>$I[cs]</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"warn\" value=\"1\"$checkedwarn>Warn</label></td>";
		echo "<td style=\"width:8em;\"><small>$last_changed</small></td>";
		echo '<td class="filtersubmit" style="width:5em;">' . submit($I['change']) . '</td></tr></table></form></td></tr>';
	}
	
	// Add new warning filter form
	echo '<tr><td>';
	echo form('admin', 'filter_warnings') . hidden('id', '+') . hidden('filter_type', 'warnings');
	echo "<table style=\"width:100%;\"><tr><th style=\"width:6em\">$I[newfilter]</th>";
	echo "<td style=\"width:14em;\"><input type=\"text\" name=\"match\" value=\"\" size=\"20\" style=\"$U[style]\"></td>";
	echo "<td style=\"width:14em;\"><input type=\"text\" name=\"replace\" value=\"\" size=\"20\" style=\"$U[style]\"></td>";
	echo "<td style=\"width:7em;\"><label><input type=\"checkbox\" name=\"allowinpm\" id=\"allowinpm\" value=\"1\">$I[allowpm]</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"regex\" id=\"regex\" value=\"1\">$I[regex]</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"cs\" id=\"cs\" value=\"1\">$I[cs]</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"warn\" id=\"warn\" value=\"1\" checked>Warn</label></td>";
	echo "<td style=\"width:8em;\"></td>";
	echo '<td class="filtersubmit" style="width:5em;">' . submit($I['add']) . '</td></tr></table></form></td></tr>';
	echo "</table><br>";
	
	echo form('admin', 'filter_warnings') . submit($I['reload']) . '</form>';
	print_end();
}

function send_filter_kick($arg = '')
{
	global $I, $U;
	print_start('filter');
	echo "<h2>Kick Filters</h2><i>$arg</i>";
	echo "<p><strong>Category:</strong> Filters that kick users on match</p>";
	
	echo "<table>";
	thr();
	echo '<tr><th><table style="width:100%;"><tr>';
	echo "<td style=\"width:6em;\">$I[fid]</td>";
	echo "<td style=\"width:14em;\">$I[match]</td>";
	echo "<td style=\"width:14em;\">$I[replace]</td>";
	echo "<td style=\"width:7em;\">$I[allowpm]</td>";
	echo "<td style=\"width:4em;\">$I[regex]</td>";
	echo "<td style=\"width:4em;\">$I[kick]</td>";
	echo "<td style=\"width:8em;\">Last Changed</td>";
	echo "<td style=\"width:5em;\">$I[apply]</td>";
	echo '</tr></table></th></tr>';
	
	$filters = get_filters();
	
	foreach ($filters as $filter) {
		// Only show kick filters
		if (empty($filter['kick'])) {
			continue;
		}
		
		$check = ($filter['allowinpm'] == 1) ? ' checked' : '';
		$checked = ($filter['regex'] == 1) ? ' checked' : '';
		$checkedk = ' checked'; // Always checked for kick filters
		
		if ($filter['regex'] != 1) {
			$filter['match'] = preg_replace('/(\\\\(.))/u', "$2", $filter['match']);
		}
		
		$last_changed = '';
		if (!empty($filter['last_changed_by'])) {
			$last_changed = htmlspecialchars($filter['last_changed_by']);
			if (!empty($filter['last_changed_date'])) {
				$last_changed .= '<br><small>' . date('Y-m-d', $filter['last_changed_date']) . '</small>';
			}
		}
		
		echo '<tr><td>';
		echo form('admin', 'filter_kick') . hidden('id', $filter['id']) . hidden('filter_type', 'kick');
		echo "<table style=\"width:100%;\"><tr><th style=\"width:6em;\">$I[filter] $filter[id]:</th>";
		echo "<td style=\"width:14em;\"><input type=\"text\" name=\"match\" value=\"$filter[match]\" size=\"20\" style=\"$U[style]\"></td>";
		echo '<td style="width:14em;"><input type="text" name="replace" value="' . htmlspecialchars($filter['replace']) . "\" size=\"20\" style=\"$U[style]\"></td>";
		echo "<td style=\"width:7em;\"><label><input type=\"checkbox\" name=\"allowinpm\" value=\"1\"$check>$I[allowpm]</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"regex\" value=\"1\"$checked>$I[regex]</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"kick\" value=\"1\"$checkedk>$I[kick]</label></td>";
		echo "<td style=\"width:8em;\"><small>$last_changed</small></td>";
		echo '<td class="filtersubmit" style="width:5em;">' . submit($I['change']) . '</td></tr></table></form></td></tr>';
	}
	
	// Add new kick filter form
	echo '<tr><td>';
	echo form('admin', 'filter_kick') . hidden('id', '+') . hidden('filter_type', 'kick');
	echo "<table style=\"width:100%;\"><tr><th style=\"width:6em\">$I[newfilter]</th>";
	echo "<td style=\"width:14em;\"><input type=\"text\" name=\"match\" value=\"\" size=\"20\" style=\"$U[style]\"></td>";
	echo "<td style=\"width:14em;\"><input type=\"text\" name=\"replace\" value=\"\" size=\"20\" style=\"$U[style]\"></td>";
	echo "<td style=\"width:7em;\"><label><input type=\"checkbox\" name=\"allowinpm\" id=\"allowinpm\" value=\"1\">$I[allowpm]</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"regex\" id=\"regex\" value=\"1\">$I[regex]</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"kick\" id=\"kick\" value=\"1\" checked>$I[kick]</label></td>";
	echo "<td style=\"width:8em;\"></td>";
	echo '<td class="filtersubmit" style="width:5em;">' . submit($I['add']) . '</td></tr></table></form></td></tr>';
	echo "</table><br>";
	
	echo form('admin', 'filter_kick') . submit($I['reload']) . '</form>';
	print_end();
}

function send_filter_commands($arg = '')
{
	global $I, $U;
	print_start('filter');
	echo "<h2>Bot Command Filters</h2><i>$arg</i>";
	echo "<p><strong>Category:</strong> Filters that trigger bot PM replies</p>";
	
	echo "<table>";
	thr();
	echo '<tr><th><table style="width:100%;"><tr>';
	echo "<td style=\"width:6em;\">$I[fid]</td>";
	echo "<td style=\"width:14em;\">$I[match]</td>";
	echo "<td style=\"width:14em;\">Bot Reply</td>";
	echo "<td style=\"width:7em;\">Bot Reply</td>";
	echo "<td style=\"width:8em;\">Last Changed</td>";
	echo "<td style=\"width:5em;\">$I[apply]</td>";
	echo '</tr></table></th></tr>';
	
	$filters = get_filters();
	
	foreach ($filters as $filter) {
		// Only show bot command filters
		if (empty($filter['bot_reply'])) {
			continue;
		}
		
		$checkedbot = ' checked'; // Always checked for command filters
		
		if ($filter['regex'] != 1) {
			$filter['match'] = preg_replace('/(\\\\(.))/u', "$2", $filter['match']);
		}
		
		$last_changed = '';
		if (!empty($filter['last_changed_by'])) {
			$last_changed = htmlspecialchars($filter['last_changed_by']);
			if (!empty($filter['last_changed_date'])) {
				$last_changed .= '<br><small>' . date('Y-m-d', $filter['last_changed_date']) . '</small>';
			}
		}
		
		echo '<tr><td>';
		echo form('admin', 'filter_commands') . hidden('id', $filter['id']) . hidden('filter_type', 'commands');
		echo "<table style=\"width:100%;\"><tr><th style=\"width:6em;\">$I[filter] $filter[id]:</th>";
		echo "<td style=\"width:14em;\"><input type=\"text\" name=\"match\" value=\"$filter[match]\" size=\"20\" style=\"$U[style]\"></td>";
		echo '<td style="width:14em;"><input type="text" name="replace" value="' . htmlspecialchars($filter['replace']) . "\" size=\"20\" style=\"$U[style]\" placeholder=\"Bot reply text\"></td>";
		echo "<td style=\"width:7em;\"><label><input type=\"checkbox\" name=\"bot_reply\" value=\"1\"$checkedbot>Bot PM</label></td>";
		echo "<td style=\"width:8em;\"><small>$last_changed</small></td>";
		echo '<td class="filtersubmit" style="width:5em;">' . submit($I['change']) . '</td></tr></table></form></td></tr>';
	}
	
	// Add new command filter form
	echo '<tr><td>';
	echo form('admin', 'filter_commands') . hidden('id', '+') . hidden('filter_type', 'commands');
	echo "<table style=\"width:100%;\"><tr><th style=\"width:6em\">$I[newfilter]</th>";
	echo "<td style=\"width:14em;\"><input type=\"text\" name=\"match\" value=\"\" size=\"20\" style=\"$U[style]\" placeholder=\"Command trigger\"></td>";
	echo "<td style=\"width:14em;\"><input type=\"text\" name=\"replace\" value=\"\" size=\"20\" style=\"$U[style]\" placeholder=\"Bot reply text\"></td>";
	echo "<td style=\"width:7em;\"><label><input type=\"checkbox\" name=\"bot_reply\" id=\"bot_reply\" value=\"1\" checked>Bot PM</label></td>";
	echo "<td style=\"width:8em;\"></td>";
	echo '<td class="filtersubmit" style="width:5em;">' . submit($I['add']) . '</td></tr></table></form></td></tr>';
	echo "</table><br>";
	
	echo form('admin', 'filter_commands') . submit($I['reload']) . '</form>';
	print_end();
}

function send_filter_staff($arg = '')
{
	global $I, $U;
	print_start('filter');
	echo "<h2>Staff-Only Filters</h2><i>$arg</i>";
	echo "<p><strong>Category:</strong> Filters visible only to staff (status 5+)</p>";
	
	echo "<table>";
	thr();
	echo '<tr><th><table style="width:100%;"><tr>';
	echo "<td style=\"width:6em;\">$I[fid]</td>";
	echo "<td style=\"width:14em;\">$I[match]</td>";
	echo "<td style=\"width:14em;\">$I[replace]</td>";
	echo "<td style=\"width:7em;\">$I[allowpm]</td>";
	echo "<td style=\"width:4em;\">$I[regex]</td>";
	echo "<td style=\"width:4em;\">$I[cs]</td>";
	echo "<td style=\"width:6em;\">Staff Only</td>";
	echo "<td style=\"width:8em;\">Last Changed</td>";
	echo "<td style=\"width:5em;\">$I[apply]</td>";
	echo '</tr></table></th></tr>';
	
	$filters = get_filters();
	
	foreach ($filters as $filter) {
		// Only show staff-only filters
		if (empty($filter['staff_only'])) {
			continue;
		}
		
		$check = ($filter['allowinpm'] == 1) ? ' checked' : '';
		$checked = ($filter['regex'] == 1) ? ' checked' : '';
		$checkedcs = ($filter['cs'] == 1) ? ' checked' : '';
		$checkedstaff = ' checked'; // Always checked for staff filters
		
		if ($filter['regex'] != 1) {
			$filter['match'] = preg_replace('/(\\\\(.))/u', "$2", $filter['match']);
		}
		
		$last_changed = '';
		if (!empty($filter['last_changed_by'])) {
			$last_changed = htmlspecialchars($filter['last_changed_by']);
			if (!empty($filter['last_changed_date'])) {
				$last_changed .= '<br><small>' . date('Y-m-d', $filter['last_changed_date']) . '</small>';
			}
		}
		
		echo '<tr><td>';
		echo form('admin', 'filter_staff') . hidden('id', $filter['id']) . hidden('filter_type', 'staff');
		echo "<table style=\"width:100%;\"><tr><th style=\"width:6em;\">$I[filter] $filter[id]:</th>";
		echo "<td style=\"width:14em;\"><input type=\"text\" name=\"match\" value=\"$filter[match]\" size=\"20\" style=\"$U[style]\"></td>";
		echo '<td style="width:14em;"><input type="text" name="replace" value="' . htmlspecialchars($filter['replace']) . "\" size=\"20\" style=\"$U[style]\"></td>";
		echo "<td style=\"width:7em;\"><label><input type=\"checkbox\" name=\"allowinpm\" value=\"1\"$check>$I[allowpm]</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"regex\" value=\"1\"$checked>$I[regex]</label></td>";
		echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"cs\" value=\"1\"$checkedcs>$I[cs]</label></td>";
		echo "<td style=\"width:6em;\"><label><input type=\"checkbox\" name=\"staff_only\" value=\"1\"$checkedstaff>Staff</label></td>";
		echo "<td style=\"width:8em;\"><small>$last_changed</small></td>";
		echo '<td class="filtersubmit" style="width:5em;">' . submit($I['change']) . '</td></tr></table></form></td></tr>';
	}
	
	// Add new staff filter form
	echo '<tr><td>';
	echo form('admin', 'filter_staff') . hidden('id', '+') . hidden('filter_type', 'staff');
	echo "<table style=\"width:100%;\"><tr><th style=\"width:6em\">$I[newfilter]</th>";
	echo "<td style=\"width:14em;\"><input type=\"text\" name=\"match\" value=\"\" size=\"20\" style=\"$U[style]\"></td>";
	echo "<td style=\"width:14em;\"><input type=\"text\" name=\"replace\" value=\"\" size=\"20\" style=\"$U[style]\"></td>";
	echo "<td style=\"width:7em;\"><label><input type=\"checkbox\" name=\"allowinpm\" id=\"allowinpm\" value=\"1\">$I[allowpm]</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"regex\" id=\"regex\" value=\"1\">$I[regex]</label></td>";
	echo "<td style=\"width:4em;\"><label><input type=\"checkbox\" name=\"cs\" id=\"cs\" value=\"1\">$I[cs]</label></td>";
	echo "<td style=\"width:6em;\"><label><input type=\"checkbox\" name=\"staff_only\" id=\"staff_only\" value=\"1\" checked>Staff</label></td>";
	echo "<td style=\"width:8em;\"></td>";
	echo '<td class="filtersubmit" style="width:5em;">' . submit($I['add']) . '</td></tr></table></form></td></tr>';
	echo "</table><br>";
	
	echo form('admin', 'filter_staff') . submit($I['reload']) . '</form>';
	print_end();
}

function send_linkfilter($arg = '')
{
	global $I, $U;
	print_start('linkfilter');
	echo "<h2>$I[linkfilter]</h2><i>$arg</i><table>";
	thr();
	echo '<tr><th><table style="width:100%;"><tr>';
	echo "<td style=\"width:8em;\">$I[fid]</td>";
	echo "<td style=\"width:12em;\">$I[match]</td>";
	echo "<td style=\"width:12em;\">$I[replace]</td>";
	echo "<td style=\"width:5em;\">$I[regex]</td>";
	echo "<td style=\"width:5em;\">$I[apply]</td>";
	echo '</tr></table></th></tr>';
	$filters = get_linkfilters();
	foreach ($filters as $filter) {
		if ($filter['regex'] == 1) {
			$checked = ' checked';
		} else {
			$checked = '';
			$filter['match'] = preg_replace('/(\\\\(.))/u', "$2", $filter['match']);
		}
		echo '<tr><td>';
		echo form('admin', 'linkfilter') . hidden('id', $filter['id']);
		echo "<table style=\"width:100%;\"><tr><th style=\"width:8em;\">$I[filter] $filter[id]:</th>";
		echo "<td style=\"width:12em;\"><input type=\"text\" name=\"match\" value=\"$filter[match]\" size=\"20\" style=\"$U[style]\"></td>";
		echo '<td style="width:12em;"><input type="text" name="replace" value="' . htmlspecialchars($filter['replace']) . "\" size=\"20\" style=\"$U[style]\"></td>";
		echo "<td style=\"width:5em;\"><label><input type=\"checkbox\" name=\"regex\" value=\"1\"$checked>$I[regex]</label></td>";
		echo '<td class="filtersubmit" style="width:5em;">' . submit($I['change']) . '</td></tr></table></form></td></tr>';
	}
	echo '<tr><td>';
	echo form('admin', 'linkfilter') . hidden('id', '+');
	echo "<table style=\"width:100%;\"><tr><th style=\"width:8em;\">$I[newfilter]</th>";
	echo "<td style=\"width:12em;\"><input type=\"text\" name=\"match\" value=\"\" size=\"20\" style=\"$U[style]\"></td>";
	echo "<td style=\"width:12em;\"><input type=\"text\" name=\"replace\" value=\"\" size=\"20\" style=\"$U[style]\"></td>";
	echo "<td style=\"width:5em;\"><label><input type=\"checkbox\" name=\"regex\" value=\"1\">$I[regex]</label></td>";
	echo '<td class="filtersubmit" style="width:5em;">' . submit($I['add']) . '</td></tr></table></form></td></tr>';
	echo "</table><br>";
	echo form('admin', 'linkfilter') . submit($I['reload']) . '</form>';
	print_end();
}

// User History Viewer Functions

function send_user_history_search() {
	global $I, $U, $db;
	print_start('userhistory');
	echo "<h2>User Infraction History</h2>";
	echo "<p>Select a user to view their moderation history and notes:</p>";
	
	// Get all users with moderation actions or all members for dropdown
	$stmt = $db->query('SELECT DISTINCT nickname FROM ' . PREFIX . 'members ORDER BY nickname;');
	$users = $stmt->fetchAll(PDO::FETCH_COLUMN);
	
	echo form('admin', 'userhistory');
	echo '<table><tr><td>Select User:</td>';
	echo '<td><select name="user" style="' . $U['style'] . '" required>';
	echo '<option value="">-- Choose User --</option>';
	foreach ($users as $username) {
		echo '<option value="' . htmlspecialchars($username) . '">' . htmlspecialchars($username) . '</option>';
	}
	echo '</select></td>';
	echo '<td>' . submit('Load History') . '</td></tr></table></form>';
	
	echo "<br><p>Or search by username:</p>";
	echo form('admin', 'userhistory');
	echo '<table><tr><td>Username:</td>';
	echo '<td><input type="text" name="user" size="30" style="' . $U['style'] . '" required></td>';
	echo '<td>' . submit('Search') . '</td></tr></table></form>';
	
	print_end();
}

function send_user_history($user) {
	global $I, $U, $db;
	
	if (!moderation_tables_exist()) {
		print_start('userhistory');
		echo "<h2>Feature Not Available</h2>";
		echo "<p>Moderation system is initializing. Please refresh in a moment.</p>";
		echo form('admin') . submit('Back') . '</form>';
		print_end();
		return;
	}
	
	// Get target user status
	$stmt = $db->prepare('SELECT status FROM ' . PREFIX . 'members WHERE nickname=?;');
	$stmt->execute([$user]);
	$target = $stmt->fetch(PDO::FETCH_ASSOC);
	
	if (!$target) {
		$stmt = $db->prepare('SELECT status FROM ' . PREFIX . 'sessions WHERE nickname=?;');
		$stmt->execute([$user]);
		$target = $stmt->fetch(PDO::FETCH_ASSOC);
	}
	
	$target_status = $target ? $target['status'] : 1;
	
	// Permission check
	if (!can_view_history($U['status'], $target_status)) {
		print_start('userhistory');
		echo "<h2>Access Denied</h2>";
		echo "<p>You don't have permission to view this user's history.</p>";
		echo form('admin', 'userhistory') . submit('Back') . '</form>';
		print_end();
		return;
	}
	
	print_start('userhistory');
	echo "<style>
	input[type='submit'], button[type='submit'] {
		background: linear-gradient(135deg, #2a2a2a 0%, #1a1a1a 100%);
		border: 1px solid #444;
		color: #fff;
		padding: 10px 18px;
		font-size: 14px;
		font-weight: 500;
		border-radius: 6px;
		cursor: pointer;
		transition: all 0.2s ease;
		box-shadow: 0 2px 4px rgba(0,0,0,0.3);
	}
	input[type='submit']:hover, button[type='submit']:hover {
		background: linear-gradient(135deg, #333 0%, #222 100%);
		border-color: #555;
		box-shadow: 0 3px 6px rgba(0,0,0,0.4);
		transform: translateY(-1px);
	}
	input[type='submit']:active, button[type='submit']:active {
		transform: translateY(0);
		box-shadow: 0 1px 2px rgba(0,0,0,0.3);
	}
	</style>";
	echo "<div style='max-width:1400px;margin:0 auto;padding:20px;background:#111;border-radius:10px;'>";
	echo "<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;'>";
	echo "<h2 style='margin:0;font-size:24px;font-weight:600;'>Moderation History: " . htmlspecialchars($user) . "</h2>";
	echo form('admin', 'userhistory') . submit('← Back to Search') . '</form>';
	echo "</div>";
	
	// Quick Actions Section (for mods+ OR members when no staff online)
	$show_quick_actions = ($U['status'] >= 5 && $target_status < $U['status']) || ($U['status'] >= 3 && !is_staff_online());
	
	if ($show_quick_actions) {
		echo "<div style='background:#0a0a0a;padding:18px;margin-bottom:20px;border-radius:8px;border:1px solid #222;'>";
		echo "<h3 style='margin:0 0 14px 0;font-size:15px;font-weight:600;'>⚡ Quick Actions</h3>";
		if ($U['status'] >= 3 && $U['status'] < 5 && !is_staff_online()) {
			echo "<div style='color:#ff9900;font-size:12px;margin-bottom:12px;padding:8px 12px;background:#1a0a00;border-radius:5px;border-left:3px solid #ff9900;'>⚠️ No staff online - Emergency moderation enabled</div>";
		}
		echo "<div style='display:grid;gap:12px;'>";
		
		// Warn button
		echo form('admin', 'userhistory');
		echo hidden('user', $user);
		echo hidden('quick_action', 'warn');
		echo '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;">';
		echo '<input type="text" name="reason" placeholder="Reason for warning..." required style="flex:1;min-width:250px;padding:10px 14px;background:#000;border:1px solid #333;color:#fff;border-radius:5px;font-size:14px;">';
		echo '<select name="severity" style="padding:10px 14px;background:#000;border:1px solid #333;color:#fff;border-radius:5px;font-size:14px;"><option value="1">Sev 1</option><option value="2">Sev 2</option><option value="3">Sev 3</option></select>';
		echo '<label style="font-size:13px;white-space:nowrap;display:flex;align-items:center;gap:5px;"><input type="checkbox" name="no_expire" value="1"> Permanent</label>';
		echo submit('⚠ Warn');
		echo '</div>';
		echo '</form>';
		
		// Mute button
		echo form('admin', 'userhistory');
		echo hidden('user', $user);
		echo hidden('quick_action', 'mute');
		echo '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;">';
		echo '<input type="number" name="duration" placeholder="Minutes" min="1" max="10080" required style="width:100px;padding:10px 14px;background:#000;border:1px solid #333;color:#fff;border-radius:5px;font-size:14px;">';
		echo '<input type="text" name="reason" placeholder="Reason..." required style="flex:1;min-width:250px;padding:10px 14px;background:#000;border:1px solid #333;color:#fff;border-radius:5px;font-size:14px;">';
		echo '<select name="severity" style="padding:10px 14px;background:#000;border:1px solid #333;color:#fff;border-radius:5px;font-size:14px;"><option value="1">Sev 1</option><option value="2" selected>Sev 2</option><option value="3">Sev 3</option></select>';
		echo submit('🔇 Mute');
		echo '</div>';
		echo '</form>';
		
		// Clear warnings button
		echo form('admin', 'userhistory');
		echo hidden('user', $user);
		echo hidden('quick_action', 'clear_warnings');
		echo submit('✓ Clear Warnings');
		echo '</form>';
		
		echo "</div></div>";
	}
	
	// Get warnings info and user stats first
	$warnings = get_user_warnings($user);
	
	// Get user stats
	$stmt_posts = $db->prepare('SELECT COUNT(*) as post_count FROM ' . PREFIX . 'messages WHERE poster=? AND delstatus=0;');
	$stmt_posts->execute([$user]);
	$post_data = $stmt_posts->fetch(PDO::FETCH_ASSOC);
	$post_count = $post_data['post_count'];
	
	$stmt_lastlogin = $db->prepare('SELECT lastlogin FROM ' . PREFIX . 'members WHERE nickname=?;');
	$stmt_lastlogin->execute([$user]);
	$login_data = $stmt_lastlogin->fetch(PDO::FETCH_ASSOC);
	$last_login = $login_data ? $login_data['lastlogin'] : 0;
	
	// Get history for stats calculation
	$stmt_history = $db->prepare('SELECT action_date, action_type, actor as moderator, details as reason, 0 as duration, COALESCE(severity, 1) as severity, 0 as auto_generated, id, "user_history" as source_table FROM ' . PREFIX . 'user_history WHERE username=? UNION ALL SELECT action_date, action_type, moderator, reason, duration, severity, auto_generated, id, "mod_actions" as source_table FROM ' . PREFIX . 'mod_actions WHERE target_user=? ORDER BY action_date DESC LIMIT 150;');
	$stmt_history->execute([$user, $user]);
	$history = $stmt_history->fetchAll(PDO::FETCH_ASSOC);
	
	// Calculate quick stats
	$warn_count = $kick_count = $mute_count = $ban_count = $admin_action_count = 0;
	$severity_counts = [1 => 0, 2 => 0, 3 => 0];
	$infraction_types = ['warning', 'kick', 'mute', 'ban'];
	foreach ($history as $entry) {
		$is_infraction = in_array($entry['action_type'], $infraction_types);
		if ($is_infraction) {
			if ($entry['action_type'] === 'warning') $warn_count++;
			if ($entry['action_type'] === 'kick') $kick_count++;
			if ($entry['action_type'] === 'mute') $mute_count++;
			if ($entry['action_type'] === 'ban') $ban_count++;
			if (isset($severity_counts[$entry['severity']])) {
				$severity_counts[$entry['severity']]++;
			}
		} else {
			$admin_action_count++;
		}
	}
	
	// Calculate standing score
	$standing_score = 100;
	$standing_score -= ($warn_count * 10);
	$standing_score -= ($kick_count * 15);
	$standing_score -= ($mute_count * 20);
	$standing_score -= ($severity_counts[2] * 5);
	$standing_score -= ($severity_counts[3] * 15);
	$standing_score = max(0, $standing_score);
	$standing_color = $standing_score >= 80 ? '#00ff00' : ($standing_score >= 50 ? '#ffdd00' : '#ff3333');
	
	// Stats Dashboard Row
	echo "<div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:15px;margin-bottom:20px;'>";
	
	echo "<div style='background:#0a0a0a;padding:16px;border-radius:8px;text-align:center;border:1px solid #222;'>";
	echo "<div style='font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;'>Standing</div>";
	echo "<div style='font-size:32px;font-weight:bold;color:$standing_color;'>$standing_score</div>";
	echo "</div>";
	
	echo "<div style='background:#0a0a0a;padding:16px;border-radius:8px;text-align:center;border:1px solid #222;'>";
	echo "<div style='font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;'>Infractions</div>";
	echo "<div style='font-size:32px;font-weight:bold;color:#ff9900;'>" . ($warn_count + $kick_count + $mute_count + $ban_count) . "</div>";
	echo "</div>";
	
	echo "<div style='background:#0a0a0a;padding:16px;border-radius:8px;text-align:center;border:1px solid #222;'>";
	echo "<div style='font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;'>Total Posts</div>";
	echo "<div style='font-size:32px;font-weight:bold;color:#4a9eff;'>$post_count</div>";
	echo "</div>";
	
	echo "<div style='background:#0a0a0a;padding:16px;border-radius:8px;text-align:center;border:1px solid #222;'>";
	echo "<div style='font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;'>Last Login</div>";
	echo "<div style='font-size:13px;font-weight:600;color:#fff;'>" . ($last_login > 0 ? date('M j, H:i', $last_login) : 'Never') . "</div>";
	echo "</div>";
	
	echo "</div>";
	
	// Active warnings banner
	if ($warnings && $warnings['warning_count'] > 0) {
		echo "<div style='background:#1a0a00;padding:14px 18px;margin-bottom:20px;border-radius:6px;border-left:4px solid #ff9900;font-size:13px;'>";
		echo "<strong>⚠ {$warnings['warning_count']} Active Warning(s)</strong> · ";
		echo "Last: " . date('M j, H:i', $warnings['last_warning']);
		if ($warnings['expires']) {
			echo " · Expires: " . date('M j, H:i', $warnings['expires']);
		}
		echo "</div>";
	}
	
	// Two-column layout for notes and breakdown
	echo "<div style='display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;'>";
	
	// Left: Moderator Notes
	echo "<div style='background:#0a0a0a;padding:18px;border-radius:8px;border:1px solid #222;'>";
	echo "<h3 style='margin:0 0 12px 0;font-size:15px;font-weight:600;'>📝 Moderator Notes</h3>";
	
	$note_type = 'user_' . $user;
	$stmt = $db->prepare('SELECT * FROM ' . PREFIX . 'notes WHERE type=? ORDER BY id DESC LIMIT 1;');
	$stmt->execute([$note_type]);
	$note = $stmt->fetch(PDO::FETCH_ASSOC);
	
	if ($note) {
		if (MSGENCRYPTED && !empty($note['text'])) {
			$note['text'] = sodium_crypto_aead_aes256gcm_decrypt(base64_decode($note['text']), null, AES_IV, ENCRYPTKEY);
		}
		$dateformat = get_setting('dateformat');
		echo "<div style='font-size:11px;color:#666;margin-bottom:8px;'><em>" . htmlspecialchars($note['editedby']) . " · " . date('M j, H:i', $note['lastedited']) . "</em></div>";
		$note_text = $note['text'];
	} else {
		$note_text = '';
	}
	
	echo form('admin', 'userhistory');
	echo hidden('user', $user);
	echo hidden('save_note', '1');
	echo '<textarea name="note_text" style="width:100%;height:120px;padding:10px;font-family:monospace;background:#000;border:1px solid #333;color:#fff;border-radius:5px;box-sizing:border-box;font-size:13px;resize:vertical;" placeholder="Moderator notes (visible to all staff)...">' . htmlspecialchars($note_text) . '</textarea>';
	echo '<div style="margin-top:10px;">' . submit('💾 Save Note') . '</div>';
	echo '</form>';
	echo "</div>";
	
	// Right: Infraction Breakdown
	echo "<div style='background:#0a0a0a;padding:18px;border-radius:8px;border:1px solid #222;'>";
	echo "<h3 style='margin:0 0 12px 0;font-size:15px;font-weight:600;'>Infraction Breakdown</h3>";
	echo "<div style='display:grid;gap:10px;'>";
	
	echo "<div style='display:flex;justify-content:space-between;padding:8px 12px;background:#000;border-radius:5px;'>";
	echo "<span style='font-size:14px;'>⚠ Warnings</span><span style='font-weight:bold;color:#ffdd00;font-size:16px;'>$warn_count</span>";
	echo "</div>";
	
	echo "<div style='display:flex;justify-content:space-between;padding:8px 12px;background:#000;border-radius:5px;'>";
	echo "<span style='font-size:14px;'>👢 Kicks</span><span style='font-weight:bold;color:#ff9900;font-size:16px;'>$kick_count</span>";
	echo "</div>";
	
	echo "<div style='display:flex;justify-content:space-between;padding:8px 12px;background:#000;border-radius:5px;'>";
	echo "<span style='font-size:14px;'>🔇 Mutes</span><span style='font-weight:bold;color:#ff3333;font-size:16px;'>$mute_count</span>";
	echo "</div>";
	
	if ($ban_count > 0) {
		echo "<div style='display:flex;justify-content:space-between;padding:8px 12px;background:#000;border-radius:5px;'>";
		echo "<span style='font-size:14px;'>🚫 Bans</span><span style='font-weight:bold;color:#ff0000;font-size:16px;'>$ban_count</span>";
		echo "</div>";
	}
	
	if ($admin_action_count > 0) {
		echo "<div style='display:flex;justify-content:space-between;padding:8px 12px;background:#000;border-radius:5px;border:1px solid #333;'>";
		echo "<span style='font-size:14px;color:#888;'>📝 Admin Actions</span><span style='font-weight:bold;color:#888;font-size:16px;'>$admin_action_count</span>";
		echo "</div>";
	}
	
	echo "<div style='margin-top:8px;padding-top:10px;border-top:1px solid #222;'>";
	echo "<div style='font-size:12px;color:#888;margin-bottom:6px;'>Severity Distribution:</div>";
	echo "<div style='display:flex;gap:15px;'>";
	echo "<span style='font-size:13px;'><span style='color:#ffdd00;'>●</span> 1: <strong>" . $severity_counts[1] . "</strong></span>";
	echo "<span style='font-size:13px;'><span style='color:#ff9900;'>●</span> 2: <strong>" . $severity_counts[2] . "</strong></span>";
	echo "<span style='font-size:13px;'><span style='color:#ff3333;'>●</span> 3: <strong>" . $severity_counts[3] . "</strong></span>";
	echo "</div>";
	echo "</div>";
	
	echo "</div>";
	echo "</div>";
	echo "</div>"; // Close two-column
	
	// History Table
	echo "<div style='background:#0a0a0a;padding:18px;border-radius:8px;border:1px solid #222;'>";
	echo "<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;'>";
	echo "<h3 style='margin:0;font-size:16px;font-weight:600;'>History Log</h3>";
	echo form('admin', 'userhistory') . hidden('user', $user) . submit('🔄 Reload') . '</form>';
	echo "</div>";
	
	if (empty($history)) {
		echo "<div style='padding:40px;text-align:center;color:#666;font-size:14px;'>No history records found</div>";
	} else {
		echo "<div style='background:#000;border-radius:6px;overflow:hidden;'>";
		echo "<table style='width:100%;border-collapse:collapse;font-size:12px;'>";
		
		// Show delete column if user can delete (status 7+ or status 5+ for own entries)
		$show_delete_col = ($U['status'] >= 5);
		
		echo "<div style='overflow-x:auto;'>";
		echo "<table style='width:100%;border-collapse:collapse;font-size:13px;'>";
		echo "<thead><tr style='background:#000;'>";
		if ($show_delete_col) {
			echo "<th style='padding:10px 8px;text-align:center;font-weight:600;border-bottom:1px solid #333;width:40px;font-size:11px;color:#888;'>DEL</th>";
		}
		echo "<th style='padding:10px 12px;text-align:left;font-weight:600;border-bottom:1px solid #333;font-size:12px;color:#888;'>DATE</th>";
		echo "<th style='padding:10px 12px;text-align:left;font-weight:600;border-bottom:1px solid #333;font-size:12px;color:#888;'>ACTION</th>";
		echo "<th style='padding:10px 12px;text-align:left;font-weight:600;border-bottom:1px solid #333;font-size:12px;color:#888;'>MODERATOR</th>";
		echo "<th style='padding:10px 12px;text-align:left;font-weight:600;border-bottom:1px solid #333;font-size:12px;color:#888;'>REASON</th>";
		echo "<th style='padding:10px 12px;text-align:center;font-weight:600;border-bottom:1px solid #333;width:70px;font-size:12px;color:#888;'>DUR</th>";
		echo "<th style='padding:10px 12px;text-align:center;font-weight:600;border-bottom:1px solid #333;width:60px;font-size:12px;color:#888;'>SEV</th>";
		echo "</tr></thead><tbody>";
		
		$infraction_types = ['warning', 'kick', 'mute', 'ban'];
		
		foreach ($history as $entry) {
			$is_infraction = in_array($entry['action_type'], $infraction_types);
			$severity_color = $entry['severity'] == 3 ? '#ff3333' : ($entry['severity'] == 2 ? '#ff9900' : '#ffdd00');
			
			// Check if user can delete this specific entry
			$can_delete = false;
			if ($U['status'] >= 7) {
				$can_delete = true;
			} elseif ($U['status'] >= 5 && $entry['moderator'] === $U['nickname']) {
				$can_delete = true;
			}
			
			echo "<tr style='background:#000;'>";
			
			// Delete button column (leftmost)
			if ($show_delete_col) {
				echo "<td style='padding:10px 8px;text-align:center;border-top:1px solid #1a1a1a;'>";
				if ($can_delete) {
					echo form('admin', 'userhistory');
					echo hidden('user', $user);
					echo hidden('delete_log', '1');
					echo hidden('log_id', $entry['id']);
					echo hidden('log_table', $entry['source_table']);
					echo '<button type="submit" style="background:#a00;border:none;color:#fff;padding:5px 9px;cursor:pointer;border-radius:4px;font-size:11px;">🗑</button>';
					echo '</form>';
				}
				echo "</td>";
			}
			
			echo "<td style='padding:10px 12px;white-space:nowrap;border-top:1px solid #1a1a1a;font-size:13px;'>" . date('M j, H:i', $entry['action_date']) . "</td>";
			echo "<td style='padding:10px 12px;border-top:1px solid #1a1a1a;font-size:13px;'><strong>" . htmlspecialchars(ucfirst($entry['action_type'])) . "</strong>" . ($entry['auto_generated'] ? ' <span style="color:#ff9900;font-size:10px;font-weight:bold;">AUTO</span>' : '') . "</td>";
			echo "<td style='padding:10px 12px;border-top:1px solid #1a1a1a;font-size:13px;'>" . htmlspecialchars($entry['moderator']) . "</td>";
			echo "<td style='padding:10px 12px;word-break:break-word;border-top:1px solid #1a1a1a;font-size:13px;'>" . htmlspecialchars($entry['reason']) . "</td>";
			echo "<td style='padding:10px 12px;text-align:center;border-top:1px solid #1a1a1a;font-size:13px;'>" . ($entry['duration'] > 0 ? $entry['duration'] . ' min' : '-') . "</td>";
			
			// Only show severity for infractions
			if ($is_infraction) {
				echo "<td style='padding:10px 12px;text-align:center;border-top:1px solid #1a1a1a;font-size:13px;'><span style='color:$severity_color;'>●</span> " . $entry['severity'] . "</td>";
			} else {
				echo "<td style='padding:10px 12px;text-align:center;border-top:1px solid #1a1a1a;font-size:13px;color:#666;'>-</td>";
			}
			echo "</tr>";
		}
		echo "</tbody></table>";
		echo "</div>";
	}
	echo "</div>"; // Close history container
	echo "</div>"; // Close max-width container
	
	echo "<br>" . form('admin', 'userhistory') . submit('Search Another User') . '</form>';
	echo " " . form('admin') . submit('Back to Admin') . '</form>';
	print_end();
}

// Audit Log Viewer Function
function send_audit_log() {
	global $I, $U, $db;
	
	if (!moderation_tables_exist()) {
		print_start('auditlog');
		echo "<h2>Feature Not Available</h2>";
		echo "<p>Audit log system is initializing. Please refresh in a moment.</p>";
		echo form('admin') . submit('Back') . '</form>';
		print_end();
		return;
	}
	
	print_start('auditlog');
	echo "<h2>Audit Log</h2>";
	echo "<p class='audit-description'>Complete log of all administrative and moderation actions.</p>";
	
	// Filter controls
	echo "<div class='audit-filters'>";
	echo form('admin', 'auditlog');
	echo "<table><tr>";
	echo "<td>Filter by Actor:</td>";
	echo "<td><input type='text' name='filter_actor' value='" . htmlspecialchars($_REQUEST['filter_actor'] ?? '') . "' size='15'></td>";
	echo "<td>Filter by Target:</td>";
	echo "<td><input type='text' name='filter_target' value='" . htmlspecialchars($_REQUEST['filter_target'] ?? '') . "' size='15'></td>";
	echo "<td>Action Type:</td>";
	echo "<td><select name='filter_action'>";
	echo "<option value=''>All Actions</option>";
	echo "<option value='warn'" . (($_REQUEST['filter_action'] ?? '') === 'warn' ? ' selected' : '') . ">Warnings</option>";
	echo "<option value='kick'" . (($_REQUEST['filter_action'] ?? '') === 'kick' ? ' selected' : '') . ">Kicks</option>";
	echo "<option value='mute'" . (($_REQUEST['filter_action'] ?? '') === 'mute' ? ' selected' : '') . ">Mutes</option>";
	echo "<option value='ban'" . (($_REQUEST['filter_action'] ?? '') === 'ban' ? ' selected' : '') . ">Bans</option>";
	echo "<option value='filter_add'" . (($_REQUEST['filter_action'] ?? '') === 'filter_add' ? ' selected' : '') . ">Filter Changes</option>";
	echo "<option value='setting_change'" . (($_REQUEST['filter_action'] ?? '') === 'setting_change' ? ' selected' : '') . ">Setting Changes</option>";
	echo "</select></td>";
	echo "<td>" . submit('Filter') . "</td>";
	echo "<td>" . form('admin', 'auditlog') . submit('Clear Filters') . "</form></td>";
	echo "</tr></table></form>";
	echo "</div>";
	
	// Build query with filters
	$where_clauses = [];
	$params = [];
	
	if (!empty($_REQUEST['filter_actor'])) {
		$where_clauses[] = "actor LIKE ?";
		$params[] = '%' . $_REQUEST['filter_actor'] . '%';
	}
	if (!empty($_REQUEST['filter_target'])) {
		$where_clauses[] = "target LIKE ?";
		$params[] = '%' . $_REQUEST['filter_target'] . '%';
	}
	if (!empty($_REQUEST['filter_action'])) {
		$where_clauses[] = "action = ?";
		$params[] = $_REQUEST['filter_action'];
	}
	
	$where_sql = !empty($where_clauses) ? 'WHERE ' . implode(' AND ', $where_clauses) : '';
	
	// Get total count
	$count_stmt = $db->prepare('SELECT COUNT(*) FROM ' . PREFIX . 'audit_log ' . $where_sql . ';');
	$count_stmt->execute($params);
	$total_entries = $count_stmt->fetch(PDO::FETCH_NUM)[0];
	
	// Pagination
	$per_page = 50;
	$page = isset($_REQUEST['page']) ? max(1, (int)$_REQUEST['page']) : 1;
	$offset = ($page - 1) * $per_page;
	$total_pages = ceil($total_entries / $per_page);
	
	// Get audit log entries
	$stmt = $db->prepare('SELECT * FROM ' . PREFIX . 'audit_log ' . $where_sql . ' ORDER BY timestamp DESC LIMIT ? OFFSET ?;');
	$params[] = $per_page;
	$params[] = $offset;
	$stmt->execute($params);
	$entries = $stmt->fetchAll(PDO::FETCH_ASSOC);
	
	echo "<p><strong>Total entries:</strong> $total_entries</p>";
	
	if (empty($entries)) {
		echo "<p>No audit log entries found.</p>";
	} else {
		echo "<table class='audit-table'>";
		echo "<tr><th>Timestamp</th><th>Actor</th><th>Status</th><th>Action</th><th>Target</th><th>T.Status</th><th>Details</th><th>IP</th></tr>";
		
		foreach ($entries as $entry) {
			$row_class = 'audit-' . strtolower(str_replace('_', '-', $entry['action']));
			echo "<tr class='$row_class'>";
			echo "<td class='audit-time'>" . date('Y-m-d H:i:s', $entry['timestamp']) . "</td>";
			echo "<td class='audit-actor'>" . htmlspecialchars($entry['actor']) . "</td>";
			echo "<td class='audit-status'>" . get_status_label($entry['actor_status']) . "</td>";
			echo "<td class='audit-action'>" . htmlspecialchars($entry['action']) . "</td>";
			echo "<td class='audit-target'>" . htmlspecialchars($entry['target'] ?? '-') . "</td>";
			echo "<td class='audit-status'>" . ($entry['target_status'] !== null ? get_status_label($entry['target_status']) : '-') . "</td>";
			echo "<td class='audit-details'>" . htmlspecialchars($entry['details'] ?? '-') . "</td>";
			echo "<td class='audit-ip'>" . htmlspecialchars($entry['ip_address'] ?? '-') . "</td>";
			echo "</tr>";
		}
		echo "</table>";
		
		// Pagination controls
		if ($total_pages > 1) {
			echo "<div class='pagination'>";
			if ($page > 1) {
				echo form('admin', 'auditlog');
				foreach ($_REQUEST as $key => $value) {
					if ($key !== 'action' && $key !== 'do' && $key !== 'page') {
						echo hidden($key, $value);
					}
				}
				echo hidden('page', $page - 1);
				echo submit('← Previous') . '</form> ';
			}
			echo "Page $page of $total_pages ";
			if ($page < $total_pages) {
				echo form('admin', 'auditlog');
				foreach ($_REQUEST as $key => $value) {
					if ($key !== 'action' && $key !== 'do' && $key !== 'page') {
						echo hidden($key, $value);
					}
				}
				echo hidden('page', $page + 1);
				echo submit('Next →') . '</form>';
			}
			echo "</div>";
		}
	}
	
	echo "<br>" . form('admin') . submit('Back to Admin') . '</form>';
	print_end();
}

function get_status_label($status) {
	switch ((int)$status) {
		case 0: return 'Banned';
		case 1: return 'Guest';
		case 2: return 'Applicant';
		case 3: return 'Member';
		case 5: return 'Mod';
		case 6: return 'Admin';
		case 7: return 'S.Admin';
		case 8: return 'Sys.Admin';
		default: return 'Unknown';
	}
}

// Appeals System Functions

function send_appeals_queue() {
	global $I, $U, $db;
	
	if (!moderation_tables_exist()) {
		print_start('appeals');
		echo "<h2>Feature Not Available</h2>";
		echo "<p>Moderation system is initializing. Please refresh in a moment.</p>";
		echo form('admin') . submit('Back') . '</form>';
		print_end();
		return;
	}
	
	print_start('appeals');
	echo "<h2>Appeal Queue</h2>";
	
	// Get pending appeals
	$stmt = $db->query('SELECT a.*, ma.action_type, ma.moderator, ma.reason as original_reason, ma.action_date 
						FROM ' . PREFIX . 'appeals a 
						JOIN ' . PREFIX . 'mod_actions ma ON a.action_id = ma.id 
						WHERE a.status = "pending" 
						ORDER BY a.submitted_date ASC;');
	$appeals = $stmt->fetchAll(PDO::FETCH_ASSOC);
	
	if (empty($appeals)) {
		echo "<p>No pending appeals.</p>";
	} else {
		foreach ($appeals as $appeal) {
			// Check if user can review this appeal
			$stmt2 = $db->prepare('SELECT status FROM ' . PREFIX . 'members WHERE nickname=?;');
			$stmt2->execute([$appeal['moderator']]);
			$mod_data = $stmt2->fetch(PDO::FETCH_ASSOC);
			$mod_status = $mod_data ? $mod_data['status'] : 5;
			
			if (!can_review_appeal($U['status'], $mod_status)) {
				continue;
			}
			
			echo "<div style='background:white;padding:15px;margin:10px 0;border:1px solid #ddd;border-radius:4px;'>";
			echo "<h3>Appeal #" . $appeal['id'] . " - " . htmlspecialchars($appeal['user']) . "</h3>";
			echo "<strong>Original Action:</strong> " . htmlspecialchars($appeal['action_type']) . " by " . htmlspecialchars($appeal['moderator']) . "<br>";
			echo "<strong>Date:</strong> " . date('Y-m-d H:i:s', $appeal['action_date']) . "<br>";
			echo "<strong>Original Reason:</strong> " . htmlspecialchars($appeal['original_reason']) . "<br>";
			echo "<strong>Appeal Reason:</strong> " . htmlspecialchars($appeal['reason']) . "<br>";
			echo "<strong>Submitted:</strong> " . date('Y-m-d H:i:s', $appeal['submitted_date']) . "<br><br>";
			
			echo form('admin', 'appeals');
			echo hidden('appeal_id', $appeal['id']);
			echo hidden('review', '1');
			echo "<textarea name='notes' placeholder='Review notes...' style='width:100%;height:60px;'></textarea><br>";
			echo "<label><input type='radio' name='decision' value='approve' required> Approve (Overturn)</label> ";
			echo "<label><input type='radio' name='decision' value='deny' required> Deny (Uphold)</label><br>";
			echo submit('Submit Review') . '</form>';
			echo "</div>";
		}
	}
	
	// Show recently reviewed appeals
	echo "<h3>Recently Reviewed</h3>";
	$stmt = $db->query('SELECT a.*, ma.action_type, ma.moderator 
						FROM ' . PREFIX . 'appeals a 
						JOIN ' . PREFIX . 'mod_actions ma ON a.action_id = ma.id 
						WHERE a.status != "pending" 
						ORDER BY a.review_date DESC 
						LIMIT 20;');
	$reviewed = $stmt->fetchAll(PDO::FETCH_ASSOC);
	
	if (!empty($reviewed)) {
		echo "<table style='width:100%;border-collapse:collapse;'>";
		echo "<tr style='background:#f0f0f0;'><th>User</th><th>Action</th><th>Status</th><th>Reviewed By</th><th>Date</th></tr>";
		foreach ($reviewed as $r) {
			$status_color = $r['status'] === 'approved' ? '#28a745' : '#dc3545';
			echo "<tr style='border-bottom:1px solid #ddd;'>";
			echo "<td style='padding:8px;'>" . htmlspecialchars($r['user']) . "</td>";
			echo "<td style='padding:8px;'>" . htmlspecialchars($r['action_type']) . "</td>";
			echo "<td style='padding:8px;'><span style='color:{$status_color};font-weight:bold;'>" . strtoupper($r['status']) . "</span></td>";
			echo "<td style='padding:8px;'>" . htmlspecialchars($r['reviewed_by']) . "</td>";
			echo "<td style='padding:8px;'>" . date('Y-m-d H:i', $r['review_date']) . "</td>";
			echo "</tr>";
		}
		echo "</table>";
	}
	
	echo "<br>" . form('admin') . submit('Back to Admin') . '</form>';
	print_end();
}

function handle_quick_action($user, $action, $data) {
	global $U, $db;
	
	if (!moderation_tables_exist()) {
		return;
	}
	
	// Get target status for permission check
	$stmt = $db->prepare('SELECT status FROM ' . PREFIX . 'members WHERE nickname=?;');
	$stmt->execute([$user]);
	$target = $stmt->fetch(PDO::FETCH_ASSOC);
	if (!$target) {
		$stmt = $db->prepare('SELECT status FROM ' . PREFIX . 'sessions WHERE nickname=?;');
		$stmt->execute([$user]);
		$target = $stmt->fetch(PDO::FETCH_ASSOC);
	}
	$target_status = $target ? $target['status'] : 1;
	
	// Check permissions: Must be higher rank OR (status 3+ with no staff online)
	$has_permission = false;
	if ($U['status'] > $target_status) {
		$has_permission = true;
	} elseif ($U['status'] >= 3 && !is_staff_online()) {
		$has_permission = true;
	}
	
	if (!$has_permission) {
		return;
	}
	
	switch ($action) {
		case 'warn':
			if (isset($data['reason']) && !empty($data['reason'])) {
				$severity = isset($data['severity']) ? (int)$data['severity'] : 1;
				$severity = max(1, min(3, $severity)); // Clamp between 1-3
				$expiry_days = isset($data['no_expire']) ? 0 : 10;
				
				$warning_count = add_user_warning($user, $data['reason'], false, $U['nickname'], $severity, $expiry_days);
				
				// Send PM notification
				send_bot_pm($user, "⚠️ <strong>Warning Issued</strong><br><strong>From:</strong> " . htmlspecialchars($U['nickname']) . "<br><strong>Reason:</strong> " . htmlspecialchars($data['reason']) . "<br><strong>Severity:</strong> $severity/3" . ($expiry_days > 0 ? "<br><strong>Expires in:</strong> $expiry_days days" : "<br><strong>Permanent warning</strong>"));
			}
			break;
			
		case 'mute':
			if (isset($data['duration']) && isset($data['reason']) && !empty($data['reason'])) {
				$duration = (int)$data['duration'];
				if ($duration > 0 && $duration <= 10080) { // Max 1 week
					$severity = isset($data['severity']) ? (int)$data['severity'] : 2;
					$severity = max(1, min(3, $severity)); // Clamp between 1-3
					
					mute_user($user, $duration, $data['reason']);
					
					// Log mute with severity
					$details = $data['reason'] . " [Severity: $severity] [Duration: $duration min]";
					log_user_action($user, 'mute', $U['nickname'], $details, $duration * 60);
					
					// Send PM notification
					send_bot_pm($user, "🔇 <strong>You have been muted</strong><br><strong>By:</strong> " . htmlspecialchars($U['nickname']) . "<br><strong>Duration:</strong> $duration minutes<br><strong>Reason:</strong> " . htmlspecialchars($data['reason']) . "<br><strong>Severity:</strong> $severity/3");
				}
			}
			break;
			
		case 'clear_warnings':
			if ($U['status'] >= 5) { // Mods+ can clear warnings
				// Delete from user_warnings table
				$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'user_warnings WHERE user=?;');
				$stmt->execute([$user]);
				
				// Delete warning entries from user_history
				$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'user_history WHERE username=? AND action_type="warning";');
				$stmt->execute([$user]);
				
				// Delete warning entries from mod_actions
				$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'mod_actions WHERE target_user=? AND action_type="warning";');
				$stmt->execute([$user]);
			}
			break;
	}
}

function save_mod_note($user, $note_text) {
	global $U, $db;
	
	$note_type = 'user_' . $user;
	$note_text = trim($note_text);
	
	if (MSGENCRYPTED && !empty($note_text)) {
		$note_text = base64_encode(sodium_crypto_aead_aes256gcm_encrypt($note_text, '', AES_IV, ENCRYPTKEY));
	}
	
	$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'notes (type, text, editedby, lastedited) VALUES (?, ?, ?, ?);');
	$stmt->execute([$note_type, $note_text, $U['nickname'], time()]);
}

function review_appeal($appeal_id, $decision, $notes) {
	global $U, $db;
	
	if (!moderation_tables_exist()) {
		return;
	}
	
	$stmt = $db->prepare('SELECT * FROM ' . PREFIX . 'appeals WHERE id=?;');
	$stmt->execute([$appeal_id]);
	$appeal = $stmt->fetch(PDO::FETCH_ASSOC);
	
	if (!$appeal) {
		return;
	}
	
	$status = $decision === 'approve' ? 'approved' : 'denied';
	
	$stmt = $db->prepare('UPDATE ' . PREFIX . 'appeals SET status=?, reviewed_by=?, review_date=?, decision=? WHERE id=?;');
	$stmt->execute([$status, $U['nickname'], time(), $notes, $appeal_id]);
	
	// If approved, reverse the action
	if ($decision === 'approve') {
		$stmt = $db->prepare('SELECT * FROM ' . PREFIX . 'mod_actions WHERE id=?;');
		$stmt->execute([$appeal['action_id']]);
		$action = $stmt->fetch(PDO::FETCH_ASSOC);
		
		if ($action && $action['action_type'] === 'kick') {
			// Unban user
			$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET status=1 WHERE nickname=? AND status=0;');
			$stmt->execute([$appeal['user']]);
		}
		
		log_mod_action('appeal_approved', $appeal['user'], "Appeal #{$appeal_id} approved: {$notes}", 0, false);
	} else {
		log_mod_action('appeal_denied', $appeal['user'], "Appeal #{$appeal_id} denied: {$notes}", 0, false);
	}
}

// Auto-Moderation Functions

function send_automod_rules() {
	global $I, $U, $db;
	
	if (!moderation_tables_exist()) {
		print_start('automod');
		echo "<h2>Feature Not Available</h2>";
		echo "<p>Moderation system is initializing. Please refresh in a moment.</p>";
		echo form('admin') . submit('Back') . '</form>';
		print_end();
		return;
	}
	
	if (!can_modify_rules($U['status'], 'view')) {
		send_access_denied();
		return;
	}
	
	print_start('automod');
	echo "<h2>Auto-Moderation Rules</h2>";
	
	$enabled = (bool)get_setting('automod_enabled');
	echo "<div style='background:" . ($enabled ? '#d4edda' : '#f8d7da') . ";padding:10px;margin:10px 0;border-radius:4px;'>";
	echo "<strong>System Status:</strong> " . ($enabled ? 'ENABLED' : 'DISABLED');
	if ($U['status'] >= 7) {
		echo " | " . form('admin', 'automod') . hidden('manage', 'toggle_system') . submit($enabled ? 'Disable System' : 'Enable System') . '</form>';
	}
	echo "</div>";
	
	// Get rules
	$rules = $db->query('SELECT * FROM ' . PREFIX . 'automod_rules ORDER BY id;')->fetchAll(PDO::FETCH_ASSOC);
	
	if (empty($rules)) {
		echo "<p>No auto-moderation rules configured.</p>";
	} else {
		echo "<table style='width:100%;border-collapse:collapse;background:white;'>";
		echo "<tr style='background:#f0f0f0;'><th>ID</th><th>Rule Name</th><th>Type</th><th>Threshold</th><th>Action</th><th>Duration</th><th>Escalate</th><th>Status</th><th>Actions</th></tr>";
		
		foreach ($rules as $rule) {
			$status_color = $rule['enabled'] ? '#28a745' : '#6c757d';
			echo "<tr style='border-bottom:1px solid #ddd;'>";
			echo "<td style='padding:8px;'>" . $rule['id'] . "</td>";
			echo "<td style='padding:8px;'>" . htmlspecialchars($rule['rule_name']) . "</td>";
			echo "<td style='padding:8px;'>" . htmlspecialchars($rule['rule_type']) . "</td>";
			echo "<td style='padding:8px;'>" . $rule['threshold'] . "</td>";
			echo "<td style='padding:8px;'>" . htmlspecialchars($rule['action']) . "</td>";
			echo "<td style='padding:8px;'>" . ($rule['duration'] > 0 ? $rule['duration'] . ' min' : '-') . "</td>";
			echo "<td style='padding:8px;'>" . ($rule['escalate'] ? 'Yes' : 'No') . "</td>";
			echo "<td style='padding:8px;'><span style='color:{$status_color};font-weight:bold;'>" . ($rule['enabled'] ? 'Active' : 'Disabled') . "</span></td>";
			echo "<td style='padding:8px;'>";
			
			if (can_modify_rules($U['status'], 'toggle')) {
				echo form('admin', 'automod') . hidden('manage', 'toggle') . hidden('rule_id', $rule['id']) . submit($rule['enabled'] ? 'Disable' : 'Enable') . '</form>';
			}
			
			if (can_modify_rules($U['status'], 'modify')) {
				echo " " . form('admin', 'automod') . hidden('manage', 'delete') . hidden('rule_id', $rule['id']) . submit('Delete') . '</form>';
			}
			
			echo "</td></tr>";
		}
		echo "</table>";
	}
	
	// Add new rule form (Admin only)
	if (can_modify_rules($U['status'], 'create')) {
		echo "<br><h3>Create New Rule</h3>";
		echo "<div style='background:white;padding:15px;border:1px solid #ddd;border-radius:4px;'>";
		echo form('admin', 'automod') . hidden('manage', 'create');
		echo "<table>";
		echo "<tr><td>Rule Name:</td><td><input type='text' name='rule_name' required style='{$U['style']}'></td></tr>";
		echo "<tr><td>Type:</td><td><select name='rule_type' required>";
		echo "<option value='spam_duplicate'>Spam (Duplicate Messages)</option>";
		echo "<option value='flood_rate'>Flooding (Message Rate)</option>";
		echo "<option value='caps_excessive'>Excessive Caps</option>";
		echo "</select></td></tr>";
		echo "<tr><td>Threshold:</td><td><input type='number' name='threshold' required min='1' style='{$U['style']}'></td></tr>";
		echo "<tr><td>Action:</td><td><select name='action' required>";
		echo "<option value='warn'>Warning</option>";
		echo "<option value='mute'>Mute</option>";
		echo "<option value='kick'>Kick</option>";
		echo "<option value='delete'>Delete Message</option>";
		echo "</select></td></tr>";
		echo "<tr><td>Duration (minutes):</td><td><input type='number' name='duration' value='5' min='0' style='{$U['style']}'></td></tr>";
		echo "<tr><td>Enable Escalation:</td><td><label><input type='checkbox' name='escalate' value='1'> Escalate on repeat offenses</label></td></tr>";
		echo "<tr><td>Warning Message:</td><td><input type='text' name='warn_message' placeholder='Optional warning to display' style='{$U['style']};width:300px;'></td></tr>";
		echo "</table>";
		echo submit('Create Rule') . '</form>';
		echo "</div>";
	}
	
	echo "<br>" . form('admin') . submit('Back to Admin') . '</form>';
	print_end();
}

function manage_automod_rules() {
	global $U, $db;
	
	if (!moderation_tables_exist()) {
		return;
	}
	
	$action = $_REQUEST['manage'];
	
	if ($action === 'toggle_system' && can_modify_rules($U['status'], 'create')) {
		$current = (bool)get_setting('automod_enabled');
		update_setting('automod_enabled', $current ? '0' : '1');
		return;
	}
	
	if ($action === 'toggle' && can_modify_rules($U['status'], 'toggle') && isset($_REQUEST['rule_id'])) {
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'automod_rules SET enabled = 1 - enabled WHERE id=?;');
		$stmt->execute([$_REQUEST['rule_id']]);
		return;
	}
	
	if ($action === 'delete' && can_modify_rules($U['status'], 'modify') && isset($_REQUEST['rule_id'])) {
		$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'automod_rules WHERE id=?;');
		$stmt->execute([$_REQUEST['rule_id']]);
		return;
	}
	
	if ($action === 'create' && can_modify_rules($U['status'], 'create')) {
		$escalate = isset($_REQUEST['escalate']) ? 1 : 0;
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'automod_rules (rule_name, rule_type, threshold, action, duration, enabled, created_by, created_date, escalate, warn_message) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?);');
		$stmt->execute([
			$_REQUEST['rule_name'],
			$_REQUEST['rule_type'],
			$_REQUEST['threshold'],
			$_REQUEST['action'],
			$_REQUEST['duration'],
			$U['nickname'],
			time(),
			$escalate,
			$_REQUEST['warn_message'] ?? null
		]);
		return;
	}
}

function send_frameset()
{
	global $I, $U, $db, $language;
	echo '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd"><html><head>' . meta_html();
	echo '<title>' . get_setting('chatname') . '</title>';
	print_stylesheet();
	echo '</head><body>';
	if (isset($_REQUEST['sort'])) {
		if ($_REQUEST['sort'] == 1) {
			$U['sortupdown'] = 0;
			$tmp = $U['nocache'];
			$U['nocache'] = $U['nocache_old'];
			$U['nocache_old'] = $tmp;
		} else {
			$U['sortupdown'] = 0;
			$tmp = $U['nocache'];
			$U['nocache'] = $U['nocache_old'];
			$U['nocache_old'] = $tmp;
		}
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET sortupdown=?, nocache=?, nocache_old=? WHERE nickname=?;');
		$stmt->execute([$U['sortupdown'], $U['nocache'], $U['nocache_old'], $U['nickname']]);
		if ($U['status'] > 1) {
			$stmt = $db->prepare('UPDATE ' . PREFIX . 'members SET sortupdown=?, nocache=?, nocache_old=? WHERE nickname=?;');
			$stmt->execute([$U['sortupdown'], $U['nocache'], $U['nocache_old'], $U['nickname']]);
		}
	}
	if (($U['status'] >= 5 || ($U['status'] > 2 && get_count_mods() == 0) || $U['status'] > 2 && get_setting('memkick') == 1) && get_setting('enfileupload') > 0 && get_setting('enfileupload') <= $U['status']) {
		$postheight = '120px';
	} else {
		$postheight = '100px';
	}
	$bottom = '';
	if (get_setting('enablegreeting')) {
		$action_mid = 'greeting';
	} else {
		if ($U['sortupdown']) {
			$bottom = '#bottom';
		}
		$action_mid = 'view';
	}
	// if ((!isset($_REQUEST['sort']) && !$U['sortupdown']) || (isset($_REQUEST['sort']) && $_REQUEST['sort'] == 0)) {
		$action_top = 'post';
		$action_bot = 'controls';
		$sort_bot = '&sort=1';
		$frameset_mid_style = "position:fixed;top:$postheight;bottom:45px;left:0;right:0;margin:0;padding:0;overflow:hidden;";
		$frameset_top_style = "position:fixed;top:0;left:0;right:0;height:$postheight;margin:0;padding:0;overflow:hidden;border-bottom: 1px solid;";
		$frameset_bot_style = "position:fixed;bottom:0;left:0;right:0;height:45px;margin:0;padding:0;overflow:hidden;border-top:1px solid;";
		$noscroll_bot = "scrolling=\"yes\" style=\"overflow-y:hidden !important;\"";
		$noscroll_top = "";
	// } else {
	// 	$action_top = 'controls';
	// 	$action_bot = 'post';
	// 	$sort_bot = '';
	// 	$frameset_mid_style = "position:fixed;top:45px;bottom:$postheight;left:0;right:0;margin:0;padding:0;overflow:hidden;";
	// 	$frameset_top_style = "position:fixed;top:0;left:0;right:0;height:45px;margin:0;padding:0;overflow:hidden;border-bottom:1px solid;";
	// 	$frameset_bot_style = "position:fixed;bottom:0;left:0;right:0;height:$postheight;margin:0;padding:0;overflow:hidden;border-top:1px solid;";
	// 	$noscroll_top = "scrolling=\"yes\" style=\"overflow-y:hidden !important;\"";
	// 	$noscroll_bot = "";
	// }
	echo "<div id=\"frameset-mid\" style=\"$frameset_mid_style\"><iframe name=\"view\" src=\"?action=$action_mid&session=$U[session]&lang=$language$bottom\">" . noframe_html() . "</iframe></div>";
	echo "<div id=\"frameset-top\" style=\"$frameset_top_style\"><iframe $noscroll_top name=\"$action_top\" src=\"?action=$action_top&session=$U[session]&lang=$language\">" . noframe_html() . "</iframe></div>";
	echo "<div id=\"frameset-bot\" style=\"$frameset_bot_style\"><iframe $noscroll_bot name=\"$action_bot\" src=\"?action=$action_bot&session=$U[session]&lang=$language$sort_bot\">" . noframe_html() . "</iframe></div>";
	echo '</body></html>';
	exit;
}

function rooms()
{
	print_start('rooms');
	// if(show_rooms()){
	print_rooms();
	//}
	print_end();
}

function show_rooms($true = "false")
{
	$handle = curl_init();
	curl_setopt_array($handle, array(
		CURLOPT_URL => $url,
		CURLOPT_RETURNTRANSFER => 0,
		CURLOPT_POST => true,
		CURLOPT_POSTFIELDS => $postData,
	));
	curl_exec($handle);
	if ($true) {
		return true;
	} else {
		return false;
	}
}
function noframe_html(): string
{
	global $I;
	return "$I[noframes]" . form_target('_parent', '') . submit($I['backtologin'], 'class="backbutton"') . '</form>';
}

function send_messages()
{
	global $I, $U, $language;
	if ($U['nocache']) {
		$nocache = '';
	} else {
		$nocache = '';
	}
	if ($U['sortupdown']) {
		$sort = '#bottom';
	} else {
		$sort = '';
	}
	$modroom = "";
	if (isset($_REQUEST['modroom']) && $_REQUEST['modroom']) {
		$modroom = '&modroom=1';
	}
	print_start('messages', $U['refresh'], "?action=view&session=$U[session]&lang=$language$nocache$sort$modroom");
	echo '<a id="top"></a>';
	echo "<a id=\"bottom_link\" href=\"#bottom\">$I[bottom]</a>";
	//MODIFICATION We don't like the manual refresh box.
	//echo "<div id=\"manualrefresh\"><br>$I[manualrefresh]<br>".form('view').submit($I['reload']).'</form><br></div>';
	//Modification for mod room for rooms
	/*if(isset($_REQUEST['modroom']) && $_REQUEST['modroom']=1 && $U['status']>=5){
		echo '<div id="modroomreload">';
		echo form('view').hidden('modroom','1').submit($I['reload']).'</form>';
		echo '</div>';
		print_messages(0,1);
		
	}else{*/
	if (!$U['sortupdown']) {
		echo '<div id="topic">';
		echo get_setting('topic');
		echo '</div>';
		echo '<div style="text-align: center; color: #888; font-size: 0.9em; margin: 0.5em 0;">Room: ' . htmlspecialchars(get_current_room_name()) . '</div>';
		print_chatters();
		print_notifications();
		print_messages();
	} else {
		print_messages();
		print_notifications();
		print_chatters();
		echo '<div id="topic">';
		echo get_setting('topic');
		echo '</div>';
		echo '<div style="text-align: center; color: #888; font-size: 0.9em; margin: 0.5em 0;">Room: ' . htmlspecialchars(get_current_room_name()) . '</div>';
	}
	//}
	echo "<a id=\"bottom\"></a><a id=\"top_link\" href=\"#top\">$I[top]</a>";
	print_end();
}

function send_inbox()
{
	global $I, $U, $db;
	print_start('inbox');
	echo form('inbox', 'clean') . submit($I['delselmes'], 'class="delbutton"') . '<br><br>';
	$dateformat = get_setting('dateformat');
	if (!$U['embed'] && get_setting('imgembed')) {
		$removeEmbed = true;
	} else {
		$removeEmbed = false;
	}
	if ($U['timestamps'] && !empty($dateformat)) {
		$timestamps = true;
	} else {
		$timestamps = false;
	}
	if ($U['sortupdown']) {
		$direction = 'DESC';
	} else {
		$direction = 'DESC';
	}
	$stmt = $db->prepare('SELECT id, postdate, text FROM ' . PREFIX . "inbox WHERE recipient=? ORDER BY id $direction;");
	$stmt->execute([$U['nickname']]);
	while ($message = $stmt->fetch(PDO::FETCH_ASSOC)) {
		prepare_message_print($message, $removeEmbed);
		echo "<div class=\"msg\"><label><input type=\"checkbox\" name=\"mid[]\" value=\"$message[id]\">";
		if ($timestamps) {
			echo ' <small>' . date($dateformat, $message['postdate']) . ' - </small>';
		}
		echo " $message[text]</label></div>";
	}
	echo '</form><br>' . form('view') . submit($I['backtochat'], 'class="backbutton"') . '</form>';
	print_end();
}

// Modification type 3 is spare notes

function send_notes($type)
{
	global $I, $U, $db;
	print_start('notes');
	$personalnotes = (bool) get_setting('personalnotes');
	$sparenotesaccess = (int) get_setting('sparenotesaccess');
	// Modification Spare notes
	if (($U['status'] >= 5 && ($personalnotes || $U['status'] > 6)) || ($personalnotes && $U['status'] >= $sparenotesaccess)) {
		echo '<table><tr>';
		if ($U['status'] > 6) {
			echo '<td>' . form_target('view', 'notes', 'admin') . submit($I['admnotes']) . '</form></td>';
		}
		if ($U['status'] >= 5) {
			echo '<td>' . form_target('view', 'notes', 'staff') . submit($I['staffnotes']) . '</form></td>';
		}
		if ($personalnotes) {
			echo '<td>' . form_target('view', 'notes') . submit($I['personalnotes']) . '</form></td>';
		}
		if ($U['status'] >= $sparenotesaccess) {
			echo '<td>' . form_target('view', 'notes', 'spare') . submit(get_setting('sparenotesname')) . '</form></td>';
		}
		echo '</tr></table>';
	}
	if ($type === 1) {
		echo "<h2>$I[staffnotes]</h2><p>";
		$hiddendo = hidden('do', 'staff');
	} elseif ($type === 0) {
		echo "<h2>$I[adminnotes]</h2><p>";
		$hiddendo = hidden('do', 'admin');
		// Modification spare notes
	} elseif ($type === 3) {
		echo '<h2>' . get_setting('sparenotesname') . '</h2><p>';
		$hiddendo = hidden('do', 'spare');
	} else {
		echo "<h2>$I[personalnotes]</h2><p>";
		$hiddendo = '';
	}
	if (isset($_REQUEST['text'])) {
		if (MSGENCRYPTED) {
			$_REQUEST['text'] = base64_encode(sodium_crypto_aead_aes256gcm_encrypt($_REQUEST['text'], '', AES_IV, ENCRYPTKEY));
		}
		$time = time();
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'notes (type, lastedited, editedby, text) VALUES (?, ?, ?, ?);');
		$stmt->execute([$type, $time, $U['nickname'], $_REQUEST['text']]);
		echo "<b>$I[notessaved]</b> ";
	}
	$dateformat = get_setting('dateformat');
	if ($type !== 2) {
		$stmt = $db->prepare('SELECT COUNT(*) FROM ' . PREFIX . 'notes WHERE type=?;');
		$stmt->execute([$type]);
	} else {
		$stmt = $db->prepare('SELECT COUNT(*) FROM ' . PREFIX . 'notes WHERE type=? AND editedby=?;');
		$stmt->execute([$type, $U['nickname']]);
	}
	$num = $stmt->fetch(PDO::FETCH_NUM);
	if (!empty($_REQUEST['revision'])) {
		$revision = intval($_REQUEST['revision']);
	} else {
		$revision = 0;
	}
	if ($type !== 2) {
		$stmt = $db->prepare('SELECT * FROM ' . PREFIX . "notes WHERE type=? ORDER BY id DESC LIMIT 1 OFFSET $revision;");
		$stmt->execute([$type]);
	} else {
		$stmt = $db->prepare('SELECT * FROM ' . PREFIX . "notes WHERE type=? AND editedby=? ORDER BY id DESC LIMIT 1 OFFSET $revision;");
		$stmt->execute([$type, $U['nickname']]);
	}
	if ($note = $stmt->fetch(PDO::FETCH_ASSOC)) {
		printf($I['lastedited'], htmlspecialchars($note['editedby']), date($dateformat, $note['lastedited']));
	} else {
		$note = ['text' => ''];
	}
	if (MSGENCRYPTED && !empty($note['text'])) {
		$note['text'] = sodium_crypto_aead_aes256gcm_decrypt(base64_decode($note['text']), null, AES_IV, ENCRYPTKEY);
	}
	echo "</p>" . form('notes');
	echo "$hiddendo<textarea name=\"text\">" . htmlspecialchars($note['text']) . '</textarea><br>';
	echo submit($I['savenotes']) . '</form><br>';
	if ($num[0] > 1) {
		echo "<br><table><tr><td>$I[revisions]</td>";
		if ($revision < $num[0] - 1) {
			echo '<td>' . form('notes') . hidden('revision', $revision + 1);
			echo $hiddendo . submit($I['older']) . '</form></td>';
		}
		if ($revision > 0) {
			echo '<td>' . form('notes') . hidden('revision', $revision - 1);
			echo $hiddendo . submit($I['newer']) . '</form></td>';
		}
		echo '</tr></table>';
	}
	print_end();
}

function send_approve_waiting()
{
	global $I, $db;
	print_start('approve_waiting');
	echo "<h2>$I[waitingroom]</h2>";
	$result = $db->query('SELECT * FROM ' . PREFIX . 'sessions WHERE entry=0 AND status=1 ORDER BY id LIMIT 100;');
	if ($tmp = $result->fetchAll(PDO::FETCH_ASSOC)) {
		echo form('admin', 'approve');
		echo '<table>';
		echo "<tr><th>$I[sessnick]</th><th>$I[sessua]</th></tr>";
		foreach ($tmp as $temp) {
			echo '<tr>' . hidden('alls[]', htmlspecialchars($temp['nickname']));
			echo '<td><label><input type="checkbox" name="csid[]" value="' . htmlspecialchars($temp['nickname']) . '">';
			echo style_this(htmlspecialchars($temp['nickname']), $temp['style']) . '</label></td>';
			echo "<td>$temp[useragent]</td></tr>";
		}
		echo "</table><br><table id=\"action\"><tr><td><label><input type=\"radio\" name=\"what\" value=\"allowchecked\" id=\"allowchecked\" checked>$I[allowchecked]</label></td>";
		echo "<td><label><input type=\"radio\" name=\"what\" value=\"allowall\" id=\"allowall\">$I[allowall]</label></td>";
		echo "<td><label><input type=\"radio\" name=\"what\" value=\"denychecked\" id=\"denychecked\">$I[denychecked]</label></td>";
		echo "<td><label><input type=\"radio\" name=\"what\" value=\"denyall\" id=\"denyall\">$I[denyall]</label></td></tr><tr><td colspan=\"8\">$I[denymessage] <input type=\"text\" name=\"kickmessage\" size=\"45\"></td>";
		echo '</tr><tr><td colspan="8">' . submit($I['butallowdeny']) . '</td></tr></table></form>';
	} else {
		echo "$I[waitempty]<br>";
	}
	echo '<br>' . form('admin', 'approve');
	echo submit($I['reload']) . '</form>';
	echo '<br>' . form('view') . submit($I['backtochat'], 'class="backbutton"') . '</form>';
	print_end();
}

function send_waiting_room()
{
	global $I, $U, $db, $language;
	$ga = (int) get_setting('guestaccess');
	if ($ga === 3 && (get_count_mods() > 0 || !get_setting('modfallback'))) {
		$wait = false;
	} else {
		$wait = true;
	}
	check_expired();
	check_kicked();
	$timeleft = get_setting('entrywait') - (time() - $U['lastpost']);
	if ($wait && ($timeleft <= 0 || $ga === 1)) {
		$U['entry'] = $U['lastpost'];
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET entry=lastpost WHERE session=?;');
		$stmt->execute([$U['session']]);
		send_frameset();
	} elseif (!$wait && $U['entry'] != 0) {
		send_frameset();
	} else {
		$refresh = (int) get_setting('defaultrefresh');
		print_start('waitingroom', $refresh, "?action=wait&session=$U[session]&lang=$language&nc=" . substr(time(), -6));
		echo "<h2>$I[waitingroom]</h2><p>";
		if ($wait) {
			printf($I['waittext'], style_this(htmlspecialchars($U['nickname']), $U['style']), $timeleft);
		} else {
			printf($I['admwaittext'], style_this(htmlspecialchars($U['nickname']), $U['style']));
		}
		echo '</p><br><p>';
		printf($I['waitreload'], $refresh);
		echo '</p><br><br>';
		echo '<hr>' . form('wait');
		if (!isset($_REQUEST['session'])) {
			echo hidden('session', $U['session']);
		}
		echo submit($I['reload']) . '</form><br>';
		echo form('logout');
		if (!isset($_REQUEST['session'])) {
			echo hidden('session', $U['session']);
		}
		echo submit($I['exit'], 'id="exitbutton"') . '</form>';
		$rulestxt = get_setting('rulestxt');
		if (!empty($rulestxt)) {
			echo "<div id=\"rules\"><h2>$I[rules]</h2><b>$rulestxt</b></div>";
		}
		print_end();
	}
}

function send_choose_messages()
{
	global $I, $U;
	print_start('choose_messages');
	echo form('admin', 'clean');
	echo hidden('what', 'selected') . submit($I['delselmes'], 'class="delbutton"') . '<br><br>';
	print_messages($U['status']);
	echo '<br>' . submit($I['delselmes'], 'class="delbutton"') . "</form>";
	print_end();
}

function send_del_confirm()
{
	global $I;
	print_start('del_confirm');
	echo "<table><tr><td colspan=\"2\">$I[confirm]</td></tr><tr><td>" . form('delete');
	if (isset($_REQUEST['multi'])) {
		echo hidden('multi', 'on');
	}
	if (isset($_REQUEST['sendto'])) {
		echo hidden('sendto', $_REQUEST['sendto']);
	}
	echo hidden('confirm', 'yes') . hidden('what', $_REQUEST['what']) . submit($I['yes'], 'class="delbutton"') . '</form></td><td>' . form('post');
	if (isset($_REQUEST['multi'])) {
		echo hidden('multi', 'on');
	}
	if (isset($_REQUEST['sendto'])) {
		echo hidden('sendto', $_REQUEST['sendto']);
	}
	echo submit($I['no'], 'class="backbutton"') . '</form></td><tr></table>';
	print_end();
}



function send_post($rejected = '')
{
	global $I, $U, $db;
	print_start('post');

	if (!isset($_REQUEST['sendto'])) {
		$_REQUEST['sendto'] = '';
	}
	echo '<table><tr><td>' . form('post');
	echo hidden('postid', substr(time(), -6));
	if (isset($_REQUEST['multi'])) {
		echo hidden('multi', 'on');
	}
	echo '<table><tr><td><table><tr id="firstline"><td>' . style_this(htmlspecialchars($U['nickname']), $U['style']) . '</td><td>:</td>';
	if (isset($_REQUEST['multi'])) {
		echo "<td><textarea name=\"message\" rows=\"3\" cols=\"40\" style=\"$U[style]\" list=\"commands\" autofocus>$rejected</textarea>";
		echo "<datalist id=\"commands\">";
		echo get_datalist_options($U['roomid'], $U['nickname'], $U['status']);
		echo "</datalist></td>";
	} else {
		//some lines changed for clickable nicknames that select username in the text box
		if (($rejected === '') && (!empty($_REQUEST['nickname']))) {
			echo "<td><input type=\"text\" name=\"message\" value=\"" . $_REQUEST['nickname'] . "\" size=\"40\" style=\"$U[style]\" list=\"commands\" autofocus>";
			echo "<datalist id=\"commands\">";
			echo get_datalist_options($U['roomid'], $U['nickname'], $U['status']);
			echo "</datalist></td>";
		} else {
			echo "<td><input type=\"text\" name=\"message\" value=\"$rejected\" size=\"40\" style=\"$U[style]\" list=\"commands\" autofocus>";
			echo "<datalist id=\"commands\">";
			echo get_datalist_options($U['roomid'], $U['nickname'], $U['status']);
			echo "</datalist></td>";
		}
	}
	echo '<td>' . submit($I['talkto']) . '</td><td><select name="sendto" size="1">';
	
	// This Room - default for everyone (status 1+)
	echo '<option ';
	if (!isset($_REQUEST['sendto']) || $_REQUEST['sendto'] === 'room' || $_REQUEST['sendto'] === '') {
		echo 'selected ';
	}
	echo 'value="room">This Room</option>';
	
	// Members channel [M] - status 3+
	if ($U['status'] >= 3) {
		echo '<option ';
		if ($_REQUEST['sendto'] === 's 31') {
			echo 'selected ';
		}
		echo 'value="s 31">[M] Members</option>';
	}
	
	// Staff channel [Staff] - status 5+
	if ($U['status'] >= 5) {
		echo '<option ';
		if ($_REQUEST['sendto'] === 's 48') {
			echo 'selected ';
		}
		echo 'value="s 48">[Staff] Staff</option>';
	}
	
	// Admin channel [Admin] - status 6+
	if ($U['status'] >= 6) {
		echo '<option ';
		if ($_REQUEST['sendto'] === 's 56') {
			echo 'selected ';
		}
		echo 'value="s 56">[Admin] Admins</option>';
	}
	
	// All (broadcast to everyone in all rooms) - status 5+
	if ($U['status'] >= 5) {
		echo '<option ';
		if ($_REQUEST['sendto'] === 's 17') {
			echo 'selected ';
		}
		echo 'value="s 17">All (Broadcast)</option>';
	}
	
	// System Message channel (backward compatibility) - status 5+
	if ($U['status'] >= 5) {
		echo '<option ';
		if ($_REQUEST['sendto'] === 's 50') {
			echo 'selected ';
		}
		echo 'value="s 50">System Message</option>';
	}

	//MODIFICATION 7 lines added for the new admin channel (option to admins only)
	// if ($U['status'] >= 7) {
	// 	echo '<option ';
	// 	if ($_REQUEST['sendto'] === 's 65') {
	// 		echo 'selected ';
	// 	}
	// 	echo "value=\"s 65\">- Gods -</option>";
	// }
	$disablepm = (bool) get_setting('disablepm');
	if (!$disablepm) {
		$users = [];
		
		// Add Dot bot first (always available)
		$bot_style = 'color:#4a90e2;font-weight:bold;';
		$users[] = ['Dot 🤖', $bot_style, 'Dot'];
		
		$stmt = $db->prepare('SELECT * FROM (SELECT nickname, style, 0 AS offline FROM ' . PREFIX . 'sessions WHERE entry!=0 AND status>0 AND incognito=0 UNION SELECT nickname, style, 1 AS offline FROM ' . PREFIX . 'members WHERE eninbox!=0 AND eninbox<=? AND nickname NOT IN (SELECT nickname FROM ' . PREFIX . 'sessions WHERE incognito=0)) AS t WHERE nickname NOT IN (SELECT ign FROM ' . PREFIX . 'ignored WHERE ignby=? UNION SELECT ignby FROM ' . PREFIX . 'ignored WHERE ign=?) ORDER BY LOWER(nickname);');
		$stmt->execute([$U['status'], $U['nickname'], $U['nickname']]);
		while ($tmp = $stmt->fetch(PDO::FETCH_ASSOC)) {
			if ($tmp['offline']) {
				$users[] = ["$tmp[nickname] $I[offline]", $tmp['style'], $tmp['nickname']];
			} else {
				$users[] = [$tmp['nickname'], $tmp['style'], $tmp['nickname']];
			}
		}
		foreach ($users as $user) {
			if ($U['nickname'] !== $user[2]) {
				echo '<option ';
				if ($_REQUEST['sendto'] == $user[2]) {
					echo 'selected ';
				}
				echo 'value="' . htmlspecialchars($user[2]) . "\" style=\"$user[1]\">" . htmlspecialchars($user[0]) . '</option>';
			}
		}
	}
	echo '</select></td>';
	if (get_setting('enfileupload') > 0 && get_setting('enfileupload') <= $U['status']) {
		echo '</tr></table><table><tr id="secondline">';
		printf("<td><input type=\"file\" name=\"file\"><small>$I[maxsize]</small></td>", get_setting('maxuploadsize'));
	}

	//Modification to enable kick function, if memdel hast value 2
	if (!$disablepm && ($U['status'] >= 5 || ($U['status'] >= 3 && get_count_mods() == 0 && get_setting('memkick')) || ($U['status'] >= 3  && (int)get_setting('memdel') === 2))) {
		echo "<td><label><input type=\"checkbox\" name=\"kick\" id=\"kick\" value=\"kick\">$I[kick]</label></td>";
		echo "<td><label><input type=\"checkbox\" name=\"what\" id=\"what\" value=\"purge\" checked>$I[alsopurge]</label></td>";
	}
	
	// Warn checkbox for status 3+ (members, mods, admins)
	if (!$disablepm && $U['status'] >= 3) {
		echo "<td><label><input type=\"checkbox\" name=\"warn\" id=\"warn\" value=\"1\">Warn</label></td>";
	}
	echo '</tr></table></td></tr></table></form></td></tr><tr><td><table><tr id="thirdline"><td>' . form('delete');
	if (isset($_REQUEST['multi'])) {
		echo hidden('multi', 'on');
	}
	echo hidden('sendto', $_REQUEST['sendto']) . hidden('what', 'last');
	echo submit($I['dellast'], 'class="delbutton"') . '</form></td><td>' . form('delete');
	if (isset($_REQUEST['multi'])) {
		echo hidden('multi', 'on');
	}
	echo hidden('sendto', $_REQUEST['sendto']) . hidden('what', 'all');
	echo submit($I['delall'], 'class="delbutton"') . '</form></td><td style="width:10px;"></td><td>' . form('post');
	if (isset($_REQUEST['multi'])) {
		echo submit($I['switchsingle']);
	} else {
		echo hidden('multi', 'on') . submit($I['switchmulti']);
	}
	echo hidden('sendto', $_REQUEST['sendto']) . '</form></td>';
	echo '</tr></table></td></tr></table>';

	//External Links section start
	//div left for links section
	echo "<div align='left'>";
	//one line added (emoji-link with id for css)
	echo "<a id='emoji_link' target='view' rel='noopener noreferrer' href='emojis.html'>Emojis</a>";
	echo "&nbsp";


	//modification forum button 
	if ($U['status'] >= (int)get_setting('forumbtnaccess')) {
		echo "<a id='forum_link' target='_blank' href='" . get_setting('forumbtnlink') . "'>Forum</a>";
	}
	echo "<div style=\"position: absolute; bottom: 10%; right: 4%; width: 220px; height: auto; overflow-y: hidden\">";
	print_rooms();
	echo "</div>";
	//echo "</div>";
	//External Links section end

	print_end();
}

function send_greeting()
{
	global $I, $U, $language;
	print_start('greeting', $U['refresh'], "?action=view&session=$U[session]&lang=$language");
	printf("<h1>$I[greetingmsg]</h1>", style_this(htmlspecialchars($U['nickname']), $U['style']));
	printf("<hr><small>$I[entryhelp]</small>", $U['refresh']);
	$rulestxt = get_setting('rulestxt');
	if (!empty($rulestxt)) {
		echo "<hr><div id=\"rules\"><h2>$I[rules]</h2>$rulestxt</div>";
	}
	print_end();
}

function send_help()
{
	global $I, $U, $db;
	print_start('help');
	$rulestxt = get_setting('rulestxt');
	if (!empty($rulestxt)) {
		echo "<div id=\"rules\"><h2>$I[rules]</h2>$rulestxt<br></div><hr>";
	}
	
	echo "<h2>$I[help]</h2>";
	
	// Basic chat usage
	echo "<h3>Getting Started</h3>";
	echo "<p>$I[helpguest]</p>";
	
	// Image embedding
	if (get_setting('imgembed')) {
		echo "<p>$I[helpembed]</p>";
	}
	
	// Chat Rooms
	echo "<h3>Chat Rooms</h3>";
	echo "<p>You can switch between different chat rooms using the room selector. ";
	echo "Messages sent in a room are only visible to users in that room, unless you use a channel command (see below).</p>";
	echo "<p><strong>Current room display:</strong> Your current room is shown below the topic at the top of the chat.</p>";
	
	// Channels - visible to all users
	echo "<h3>Channels (Message Visibility)</h3>";
	echo "<p>Control who sees your messages using the channel dropdown:</p>";
	echo "<ul>";
	echo "<li><strong>This Room</strong> (default) - Visible only in your current room</li>";
	if ($U['status'] >= 3) {
		echo "<li><strong>[M] Members</strong> - Visible to all members (status 3+) across all rooms</li>";
	}
	if ($U['status'] >= 5) {
		echo "<li><strong>[Staff] Staff</strong> - Visible to all staff (status 5+) across all rooms</li>";
	}
	if ($U['status'] >= 6) {
		echo "<li><strong>[Admin] Admins</strong> - Visible to admins (status 6+) across all rooms</li>";
	}
	if ($U['status'] >= 5) {
		echo "<li><strong>All (Broadcast)</strong> - Visible to everyone across all rooms (staff 5+ only)</li>";
	}
	echo "</ul>";
	echo "<p>Select a channel from the <strong>Send to</strong> dropdown in the postbox. Room-specific messages only appear in your current room, while channel messages broadcast to all rooms.</p>";
	
	// Clickable nicknames
	if ((bool) get_setting('clickablenicknamesglobal')) {
		echo "<h3>Clickable Usernames</h3>";
		echo "<p>Usernames in messages are clickable! Click on a username to:</p>";
		echo "<ul>";
		echo "<li><strong>In private messages:</strong> Opens a PM window to that user</li>";
		echo "<li><strong>In channel/public messages:</strong> Pre-fills the postbox with @username so you can reply</li>";
		echo "</ul>";
	}
	
	// Chat commands
	echo "<h3>Chat Commands</h3>";
	echo "<p>Type these commands in the message box:</p>";
	echo "<ul>";
	echo "<li><strong>/me [action]</strong> - Display an action (e.g., '/me waves hello' shows as <em>YourName waves hello</em>)</li>";
	echo "<li><strong>/whisper [message]</strong> - Send a whispered message (appears in gray/muted text)</li>";
	echo "<li><strong>/help</strong> - Show this help information via PM from Dot bot</li>";
	echo "<li><strong>/afk [reason]</strong> - Mark yourself as away from keyboard (adds [AFK] to your name)</li>";
	echo "<li><strong>/locate [username]</strong> - Find which room a user is currently in</li>";
	echo "<li><strong>/shrug [message]</strong> - Adds ¯\\_(ツ)_/¯ to your message</li>";
	echo "<li><strong>/flip [message]</strong> - Adds (╯°□°)╯︵ ┻━┻ to your message</li>";
	echo "<li><strong>/unflip [message]</strong> - Adds (ヘ･_･)ヘ┳━┳ to your message</li>";
	echo "</ul>";
	
	// Bot commands
	$stmt = $db->prepare('SELECT command, response, min_status FROM ' . PREFIX . 'botcommands WHERE min_status <= ? ORDER BY command;');
	$stmt->execute([$U['status']]);
	$bot_commands = $stmt->fetchAll(PDO::FETCH_ASSOC);
	
	if (!empty($bot_commands)) {
		echo "<h3>Custom Bot Commands</h3>";
		echo "<p>Send these commands to Dot bot via private message (they won't post publicly):</p>";
		echo "<ul>";
		foreach ($bot_commands as $cmd) {
			echo "<li><strong>." . htmlspecialchars($cmd['command']) . "</strong>";
			if ($cmd['min_status'] > 0) {
				$levels = ['Guest', 'Guest', 'Applicant', 'Member', 'Member+', 'Moderator', 'Chat Admin', 'Service Admin', 'System Admin'];
				echo " <em>(Requires: " . $levels[$cmd['min_status']] . "+)</em>";
			}
			echo "</li>";
		}
		echo "</ul>";
	}
	
	// Profile and settings
	echo "<h3>Profile & Settings</h3>";
	echo "<p>Use the <strong>Profile</strong> tab to customize your experience:</p>";
	echo "<ul>";
	echo "<li>Adjust refresh rate (how often the chat updates)</li>";
	echo "<li>Change your font color</li>";
	echo "<li>Ignore/unignore other users</li>";
	echo "<li>Enable/disable timestamps</li>";
	echo "<li>Toggle image embedding</li>";
	echo "<li>Set your timezone</li>";
	echo "</ul>";
	
	// Member-specific features
	if ($U['status'] >= 3) {
		echo "<h3>Member Features</h3>";
		echo "<p>$I[helpmem]</p>";
		echo "<ul>";
		echo "<li>Access to Members channel ([M])</li>";
		echo "<li>Customize font style and appearance</li>";
		echo "<li>Change password anytime</li>";
		echo "<li>Delete your account</li>";
		echo "<li>Access to member-only rooms (if available)</li>";
		echo "</ul>";
	}
	
	// Moderator features
	if ($U['status'] >= 5) {
		echo "<h3>Moderator Features</h3>";
		echo "<p>$I[helpmod]</p>";
		echo "<p><strong>Admin Page Tools:</strong></p>";
		echo "<ul>";
		echo "<li><strong>Clean Messages</strong> - Delete messages (marks as deleted; admins can still see them)</li>";
		echo "<li><strong>Kick Users</strong> - Kick users from chat with optional purge (delete all their messages)</li>";
		echo "<li><strong>Logout Inactive</strong> - Force logout specific users</li>";
		echo "<li><strong>View Sessions</strong> - See all active users and their details</li>";
		echo "<li><strong>Filter Management</strong> - Add/edit word filters and auto-responses</li>";
		echo "<li><strong>Link Filters</strong> - Manage URL filtering and replacements</li>";
		echo "<li><strong>Bot Commands</strong> - Create custom . commands that Dot responds to</li>";
		echo "<li><strong>User History</strong> - View user action history and warnings</li>";
		echo "<li><strong>Appeal Queue</strong> - Review and respond to user appeals</li>";
		echo "<li><strong>Last Logins</strong> - Check when members last logged in</li>";
		echo "</ul>";
		echo "<p><strong>Message Deletion:</strong> Use DEL buttons in the message frame to delete individual messages. ";
		echo "Deleted messages are hidden from regular users but visible to admins with a red background and (deleted) marker.</p>";
		if ((bool) get_setting('memdel')) {
			echo "<p><strong>Note:</strong> Member deletion is enabled - members can delete messages when mods are present or absent (depending on settings).</p>";
		}
	}
	
	// Admin features
	if ($U['status'] >= 7) {
		echo "<h3>Admin Features</h3>";
		echo "<p>$I[helpadm]</p>";
		echo "<p><strong>Additional Admin Tools:</strong></p>";
		echo "<ul>";
		echo "<li><strong>Setup Page</strong> - Configure all chat settings, appearance, permissions, and features</li>";
		echo "<li><strong>Register Members</strong> - Create new member accounts</li>";
		echo "<li><strong>Edit Members</strong> - Modify member accounts, change status levels</li>";
		echo "<li><strong>Chat Rooms Management</strong> - Create/edit/delete chat rooms</li>";
		echo "<li><strong>View Deleted Messages</strong> - See all messages marked as deleted (shown with red background)</li>";
		echo "<li><strong>System Configuration</strong> - Access to all global settings and chat behavior</li>";
		echo "</ul>";
		echo "<p><strong>Room Management:</strong> Create rooms with custom access levels. Set rooms as permanent to prevent auto-expiry.</p>";
		echo "<p><strong>Moderation System:</strong> Configure auto-moderation rules, warning systems, and automated actions.</p>";
	}
	
	// Private messages
	echo "<h3>Private Messages</h3>";
	echo "<p>Send private messages by selecting a username from the <strong>Send to</strong> dropdown. ";
	echo "Private messages only appear to you and the recipient.</p>";
	if ($U['status'] >= 1) {
		echo "<p>Check your <strong>Inbox</strong> tab for received private messages.</p>";
	}
	
	// Deleted messages visibility
	if ($U['status'] >= 7) {
		echo "<h3>Deleted Messages (Admin View)</h3>";
		echo "<p>As an admin, you can see deleted messages with:</p>";
		echo "<ul>";
		echo "<li>Dark red background (#4d0000)</li>";
		echo "<li>'(deleted)' marker at the end</li>";
		echo "<li>Regular users (status &lt; 7) cannot see these messages at all</li>";
		echo "</ul>";
		echo "<p>Only room clearing permanently deletes messages from the database.</p>";
	}
	
	// MODIFICATION removed script version.
	echo '<br><hr><div id="backcredit">' . form('view') . submit($I['backtochat'], 'class="backbutton"') . '</form>'/*.credit()*/ . '</div>';
	print_end();
}

function send_profile($arg = '')
{
	global $I, $L, $U, $db, $language;
	print_start('profile');
	echo form('profile', 'save') . "<h2>$I[profile]</h2><i>$arg</i><table>";
	thr();
	$ignored = [];
	$stmt = $db->prepare('SELECT ign FROM ' . PREFIX . 'ignored WHERE ignby=? ORDER BY LOWER(ign);');
	$stmt->execute([$U['nickname']]);
	while ($tmp = $stmt->fetch(PDO::FETCH_ASSOC)) {
		$ignored[] = htmlspecialchars($tmp['ign']);
	}
	if (count($ignored) > 0) {
		echo "<tr><td><table id=\"unignore\"><tr><th>$I[unignore]</th><td>";
		echo "<select name=\"unignore\" size=\"1\"><option value=\"\">$I[choose]</option>";
		foreach ($ignored as $ign) {
			echo "<option value=\"$ign\">$ign</option>";
		}
		echo '</select></td></tr></table></td></tr>';
		thr();
	}
	echo "<tr><td><table id=\"ignore\"><tr><th>$I[ignore]</th><td>";
	echo "<select name=\"ignore\" size=\"1\"><option value=\"\">$I[choose]</option>";
	$stmt = $db->prepare('SELECT poster, style FROM ' . PREFIX . 'messages INNER JOIN (SELECT nickname, style FROM ' . PREFIX . 'sessions UNION SELECT nickname, style FROM ' . PREFIX . 'members) AS t ON (' .  PREFIX . 'messages.poster=t.nickname) WHERE poster!=? AND poster NOT IN (SELECT ign FROM ' . PREFIX . 'ignored WHERE ignby=?) GROUP BY poster ORDER BY LOWER(poster);');
	$stmt->execute([$U['nickname'], $U['nickname']]);
	while ($nick = $stmt->fetch(PDO::FETCH_NUM)) {
		echo '<option value="' . htmlspecialchars($nick[0]) . "\" style=\"$nick[1]\">" . htmlspecialchars($nick[0]) . '</option>';
	}
	echo '</select></td></tr></table></td></tr>';
	thr();
	echo "<tr><td><table id=\"refresh\"><tr><th>$I[refreshrate]</th><td>";
	echo "<input type=\"number\" name=\"refresh\" size=\"3\" maxlength=\"3\" min=\"5\" max=\"150\" value=\"$U[refresh]\"></td></tr></table></td></tr>";
	thr();
	preg_match('/#([0-9a-f]{6})/i', $U['style'], $matches);
	$color_value = isset($matches[1]) ? $matches[1] : 'FFFFFF';
	echo "<tr><td><table id=\"colour\"><tr><th>$I[fontcolour] (<a href=\"?action=colours&amp;session=$U[session]&amp;lang=$language\" target=\"view\">$I[viewexample]</a>)</th><td>";
	echo "<input type=\"color\" value=\"#{$color_value}\" name=\"colour\"></td></tr></table></td></tr>";
	thr();
	echo "<tr><td><table id=\"bgcolour\"><tr><th>$I[bgcolour] (<a href=\"?action=colours&amp;session=$U[session]&amp;lang=$language\" target=\"view\">$I[viewexample]</a>)</th><td>";
	echo "<input type=\"color\" value=\"#$U[bgcolour]\" name=\"bgcolour\"></td></tr></table></td></tr>";
	thr();
	if ($U['status'] >= 3) {
		echo "<tr><td><table id=\"font\"><tr><th>$I[fontface]</th><td><table>";
		echo "<tr><td>&nbsp;</td><td><select name=\"font\" size=\"1\"><option value=\"\">* $I[roomdefault] *</option>";
		$F = load_fonts();
		foreach ($F as $name => $font) {
			echo "<option style=\"$font\" ";
			if (strpos($U['style'], $font) !== false) {
				echo 'selected ';
			}
			echo "value=\"$name\">$name</option>";
		}
		echo '</select></td><td>&nbsp;</td><td><label><input type="checkbox" name="bold" id="bold" value="on"';
		if (strpos($U['style'], 'font-weight:bold;') !== false) {
			echo ' checked';
		}
		echo "><b>$I[bold]</b></label></td><td>&nbsp;</td><td><label><input type=\"checkbox\" name=\"italic\" id=\"italic\" value=\"on\"";
		if (strpos($U['style'], 'font-style:italic;') !== false) {
			echo ' checked';
		}
		echo "><i>$I[italic]</i></label></td><td>&nbsp;</td><td><label><input type=\"checkbox\" name=\"small\" id=\"small\" value=\"on\"";
		if (strpos($U['style'], 'font-size:smaller;') !== false) {
			echo ' checked';
		}
		echo "><small>$I[small]</small></label></td></tr></table></td></tr></table></td></tr>";
		thr();
	}
	echo '<tr><td>' . style_this(htmlspecialchars($U['nickname']) . " : $I[fontexample]", $U['style']) . '</td></tr>';
	thr();
	$bool_settings = ['timestamps', 'nocache', 'sortupdown', 'hidechatters'];
	if (get_setting('imgembed')) {
		$bool_settings[] = 'embed';
	}
	if ($U['status'] >= 5 && get_setting('incognito')) {
		$bool_settings[] = 'incognito';
	}
	foreach ($bool_settings as $setting) {
		echo "<tr><td><table id=\"$setting\"><tr><th>" . $I[$setting] . '</th><td>';
		echo "<label><input type=\"checkbox\" name=\"$setting\" value=\"on\"";
		if ($U[$setting]) {
			echo ' checked';
		}
		echo "><b>$I[enabled]</b></label></td></tr></table></td></tr>";
		thr();
	}
	if ($U['status'] >= 2 && get_setting('eninbox')) {
		echo "<tr><td><table id=\"eninbox\"><tr><th>$I[eninbox]</th><td>";
		echo "<select name=\"eninbox\" id=\"eninbox\">";
		echo '<option value="0"';
		if ($U['eninbox'] == 0) {
			echo ' selected';
		}
		echo ">$I[disabled]</option>";
		echo '<option value="1"';
		if ($U['eninbox'] == 1) {
			echo ' selected';
		}
		echo ">$I[eninall]</option>";
		echo '<option value="3"';
		if ($U['eninbox'] == 3) {
			echo ' selected';
		}
		echo ">$I[eninmem]</option>";
		echo '<option value="5"';
		if ($U['eninbox'] == 5) {
			echo ' selected';
		}
		echo ">$I[eninstaff]</option>";
		echo '</select></td></tr></table></td></tr>';
		thr();
	}
	echo "<tr><td><table id=\"tz\"><tr><th>$I[tz]</th><td>";
	echo "<select name=\"tz\">";
	$tzs = timezone_identifiers_list();
	foreach ($tzs as $tz) {
		echo "<option value=\"$tz\"";
		if ($U['tz'] == $tz) {
			echo ' selected';
		}
		echo ">$tz</option>";
	}
	echo '</select></td></tr></table></td></tr>';

	//MODIFICATION nicklinks setting (setting for clickable nicknames in the message frame
	//REMOVE LATER (Remove 18 LINES (Modification no longer needed)
	/*
    thr();
	echo "<tr><td><table id=\"clickablenicknames\"><tr><th>Clickable nicknames</th><td>";
	echo "<select name=\"clickablenicknames\">";
	

	$options = array(0, 1, 2);
	foreach($options as $option){
		echo "<option value=\"$option\"";
		
		if($U['clickablenicknames']==$option){
			echo ' selected';
		}
		
		if ($option == 0) echo ">Disabled</option>";
		elseif($option == 1) echo ">Select nickname from dropdown menu</option>";
		elseif($option == 2) echo ">Copy nickname to post box</option>";
	}
	echo '</select></td></tr></table></td></tr>';	
	*/

	thr();
	if ($U['status'] >= 2) {
		echo "<tr><td><table id=\"changepass\"><tr><th>$I[changepass]</th></tr>";
		echo '<tr><td><table>';
		echo "<tr><td>&nbsp;</td><td>$I[oldpass]</td><td><input type=\"password\" name=\"oldpass\" size=\"20\"></td></tr>";
		echo "<tr><td>&nbsp;</td><td>$I[newpass]</td><td><input type=\"password\" name=\"newpass\" size=\"20\"></td></tr>";
		echo "<tr><td>&nbsp;</td><td>$I[confirmpass]</td><td><input type=\"password\" name=\"confirmpass\" size=\"20\"></td></tr>";
		echo '</table></td></tr></table></td></tr>';
		thr();
		echo "<tr><td><table id=\"changenick\"><tr><th>$I[changenick]</th><td><table>";
		echo "<tr><td>&nbsp;</td><td>$I[newnickname]</td><td><input type=\"text\" name=\"newnickname\" size=\"20\">";
		echo '</table></td></tr></table></td></tr>';
		thr();
	}
	echo '<tr><td>' . submit($I['savechanges']) . '</td></tr></table></form>';
	if ($U['status'] > 1 && $U['status'] < 8) {
		echo '<br>' . form('profile', 'delete') . submit($I['deleteacc'], 'class="delbutton"') . '</form>';
	}
	echo "<br><p id=\"changelang\">$I[changelang]";
	foreach ($L as $lang => $name) {
		echo " <a href=\"?lang=$lang&amp;session=$U[session]&amp;action=controls\" target=\"controls\">$name</a>";
	}
	echo '</p><br>' . form('view') . submit($I['backtochat'], 'class="backbutton"') . '</form>';
	print_end();
}

function send_controls()
{
	global $I, $U;
	print_start('controls');
	$personalnotes = (bool) get_setting('personalnotes');
	echo '<table><tr>';
	echo '<td>' . form_target('post', 'post') . submit($I['reloadpb']) . '</form></td>';
	echo '<td>' . form_target('view', 'view') . submit($I['reloadmsgs']) . '</form></td>';
	echo '<td>' . form_target('view', 'profile') . submit($I['chgprofile']) . '</form></td>';
	//MODIFICATION Links Page
	if (get_setting('linksenabled') === '1') {
		echo '<td>' . form_target('view', 'links') . submit('Changelog') . '</form></td>';
	}

	//Forum Button was moved to the postbox (function send_post) 
	/*
	if($U['status']>= (int)get_setting('forumbtnaccess')){
         echo '<td>'.form_target('_blank', 'forum').submit('Forum').'</form></td>';
	}
	//ToDo handle forum request in function validate_input (redirect to forum page)
	*/

	//MODIFICATION for feature gallery
	if ($U['status'] >= (int)get_setting('galleryaccess')) {
		echo '<td>' . form_target('view', 'gallery') . submit('Gallery') . '</form></td>';
	}

	if ($U['status'] >= 5) {
		echo '<td>' . form_target('view', 'view') . hidden('modroom', '1') . submit('Mod Rooms') . '</form></td>';
	}


	if ($U['status'] >= 5) {
		echo '<td>' . form_target('view', 'admin') . submit($I['adminbtn']) . '</form></td>';
		//MODIFICATION for feature gallery. one line changed.
		//echo '<td>'.form_target('_blank', 'gallery').submit('Gallery').'</form></td>';
		if (!$personalnotes) {
			echo '<td>' . form_target('view', 'notes', 'staff') . submit($I['notes']) . '</form></td>';
		}
	}
	// Modification spare notes
	$sparenotesaccess = (int) get_setting('sparenotesaccess');
	if ($U['status'] >= 3) {
		if ($personalnotes) {
			echo '<td>' . form_target('view', 'notes') . submit($I['notes']) . '</form></td>';
		} elseif ($U['status'] >= $sparenotesaccess && $U['status'] === 3) {
			echo '<td>' . form_target('view', 'notes', 'spare') . submit($I['notes']) . '</form></td>';
		}
		echo '<td>' . form_target('_blank', 'login') . submit($I['clone']) . '</form></td>';
	}
	if (!isset($_REQUEST['sort'])) {
		$sort = 0;
	} else {
		$sort = 0;
	}
	// echo '<td>' . form_target('_parent', 'login') . hidden('sort', $sort) . submit($I['sortframe']) . '</form></td>';
	echo '<td>' . form_target('view', 'help') . submit($I['randh']) . '</form></td>';
	echo '<td>' . form_target('view', 'logout') . submit($I['exit'], 'id="exitbutton"') . '</form></td>';
	echo '</tr></table>';
	print_end();
}

function send_download()
{
	global $I, $db;
	if (isset($_REQUEST['id'])) {
		$stmt = $db->prepare('SELECT filename, type, data FROM ' . PREFIX . 'files WHERE hash=?;');
		$stmt->execute([$_REQUEST['id']]);
		if ($data = $stmt->fetch(PDO::FETCH_ASSOC)) {
			header("Content-Type: $data[type]");
			header("Content-Disposition: filename=\"$data[filename]\"");
			header('Pragma: no-cache');
			header('Cache-Control: no-cache, no-store, must-revalidate, max-age=0, private');
			header('Expires: 0');
			echo base64_decode($data['data']);
		} else {
			send_error($I['filenotfound']);
		}
	} else {
		send_error($I['filenotfound']);
	}
}

function send_logout()
{
	global $I, $U;
	print_start('logout');
	echo '<h1>' . sprintf($I['bye'], style_this(htmlspecialchars($U['nickname']), $U['style'])) . '</h1>' . form_target('_parent', '') . submit($I['backtologin'], 'class="backbutton"') . '</form>';
	print_end();
}

function send_colours()
{
	global $I;
	print_start('colours');
	echo "<h2>$I[colourtable]</h2><kbd><b>";
	for ($red = 0x00; $red <= 0xFF; $red += 0x33) {
		for ($green = 0x00; $green <= 0xFF; $green += 0x33) {
			for ($blue = 0x00; $blue <= 0xFF; $blue += 0x33) {
				$hcol = sprintf('%02X%02X%02X', $red, $green, $blue);
				echo "<span style=\"color:#$hcol\">$hcol</span> ";
			}
			echo '<br>';
		}
		echo '<br>';
	}
	echo '</b></kbd>' . form('profile') . submit($I['backtoprofile'], ' class="backbutton"') . '</form>';
	print_end();
}

function nav()
{
	echo '
	<div class="navbartitle"><a href="#" style="text-decoration: none; color: #fff;">404 Chatroom Not Found</a></div>
	<nav class="topnav">
	<ul class="topnav">
	<li><a href="#ABOUT" target="_self">About</a></li>
	<li><a href="https://github.com/d-a-s-h-o/universe" target="_blank">Source</a></li>
	<li><a href="/" target="_blank">Homepage</a></li>
	<a class="wgbtn" href="#logincbox">Login</a>
	</ul> </nav>';
}

function send_login()
{
	global $I, $L;
	$ga = (int) get_setting('guestaccess');
	if ($ga === 4) {
		send_chat_disabled();
	}
	print_start('login');
	nav();
	$englobal = (int) get_setting('englobalpass');
	//MODIFICATION frontpagetext
	//Frontpage text added
	/* $frontpagetext=get_setting('frontpagetext');
		if(!empty($frontpagetext)){
			echo "<span id=\"\">$frontpagetext</span>";
		} */
	//MODIFICATION Javascript check.
	//ToDo (Maybe later)

	//MODIFICATION Topic on Frontpage disabled
	//echo '<h1 id="chatname">'.get_setting('chatname').'</h1>';
	echo '<div id="logincbox" class="overlaycbx"><div class="popupcbx"><h2>Login</h2><a class="closecbx" href="#">&times;</a><div class="contentcbx">';
	echo form_target('_parent', 'login') . '<table>';
	if ($englobal === 1 && isset($_REQUEST['globalpass'])) {
		echo hidden('globalpass', $_REQUEST['globalpass']);
	}
	if ($englobal !== 1 || (isset($_REQUEST['globalpass']) && $_REQUEST['globalpass'] == get_setting('globalpass'))) {
		echo "<tr><td>$I[nick]</td><td><input type=\"text\" name=\"nick\" size=\"15\" autofocus></td></tr>";
		echo "<tr><td>$I[pass]</td><td><input type=\"password\" name=\"pass\" size=\"15\"></td></tr>";
		send_captcha();
		if ($ga !== 0) {
			if (get_setting('guestreg') != 0) {
				echo "<tr><td>$I[regpass]</td><td><input type=\"password\" name=\"regpass\" size=\"15\" placeholder=\"$I[optional]\"></td></tr>";
			}
			if ($englobal === 2) {
				echo "<tr><td>$I[globalloginpass]</td><td><input type=\"password\" name=\"globalpass\" size=\"15\"></td></tr>";
			}
			echo "<tr><td colspan=\"2\">$I[choosecol]<br><select name=\"colour\"><option value=\"\">* $I[randomcol] *</option>";
			print_colours();
			echo '</select></td></tr>';
		} else {
			echo "<tr><td colspan=\"2\">$I[noguests]</td></tr>";
		}
		echo '<tr><td colspan="2">' . submit($I['enter']) . '</td></tr></table></form>';
		echo '<br>';
		get_nowchatting();
		// echo '<br><div id="topic">';
		//MODIFICATION Topic on Frontpage disabled. 1 lines "removed"
		//echo get_setting('topic');
		// echo '</div>';
		$rulestxt = get_setting('rulestxt');

		//MODIFICATION Rules on Frontpage disabled. 3 lines "removed"
		/*
		if(!empty($rulestxt)){
			echo "<div id=\"rules\"><h2>$I[rules]</h2><b>$rulestxt</b></div>";
		}
		*/
	} else {
		echo "<tr><td>$I[globalloginpass]</td><td><input type=\"password\" name=\"globalpass\" size=\"15\" autofocus></td></tr>";
		if ($ga === 0) {
			echo "<tr><td colspan=\"2\">$I[noguests]</td></tr>";
		}
		echo '<tr><td colspan="2">' . submit($I['enter']) . '</td></tr></table></form>';
	}
	/*echo "<p id=\"changelang\">$I[changelang]";
	foreach($L as $lang=>$name){
		echo " <a href=\"$_SERVER[SCRIPT_NAME]?lang=$lang\">$name</a>";
	}*/

	//MODIFICATION we hide our script version for security reasons and because it was modificated. 1 line replaced.
	//echo '</p>'.credit();
	//echo '</p>'; 
	echo '</table>';
	$link4o4 = 'https://4-0-4.io';
	$class = 'clearnet';

	echo '</div></div></div>';
	echo "<div class=\"odiv\"><div class=\"splash\"><h2><strong>Welcome to the 404 Chatroom</strong></h2><div class=\"splashcard\"><br>
	<h3><ins>Shocking News</ins>: New Updates! We're online!</h3><br>
	<strong>Welcome to the 404 Chatroom - <em>The most over-compensating chat on tor</em>.</strong>
	<br>Are you looking for a fun - stress free, user friendly - totally secret awesome badass cool darkweb chat? That's such a coincidence, because that's what this is. All you have to do is press the <strong>Login</strong> button in the top right hand corner, enter your credentials, and start chatting. If you want to chat anonymously, just enter any nickname press <strong>Enter Chat</strong> straight away and get at it. We hope you have fun!
	<br><br>
	<div class=\"callout alert\" style=\"background: none; border: 2px; border-style: solid; border-color: var(--accent); border-radius: 0.5em; padding: 1em; color: white; margin-left: 10%; margin-right: 10%;\">  <p style=\"color: white; text-align: center\"><center>The <span style=\"color: #404 Chatroomffff80;\">404 Chatroom</span> Rules</center></p><hr><ol>  <li><span style=\"color: var(--accent);\">Nothing gross or illegal.</span></li>  <li>Freedom of speech is welcomed, but be nice.</li>  <li>Please <span style=\"color: var(--accent);\">be respectful</span> to other chatters</li>  <li>Please <span style=\"color: var(--accent);\">use meaningful</span> and <span style=\"color: var(--accent);\">non-offensive nicknames</span>. No pedo nicks.</li>  <li>Please <span style=\"color: var(--accent);\">use English</span> in the Main Chat please.</li>  <li>Please <span style=\"color: var(--accent);\">no advertising</span> with out staff approval .</li>  <li>No drug or gun endorsements, or endorsements of other illegal markets.</li></ol> <hr /></div>
	<br><br>
	</div><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>
	<a href=\"http://4o4o4hn4hsujpnbsso7tqigujuokafxys62thulbk2k3mf46vq22qfqd.onion/\"><div class=\"tip\" style=\"position: fixed; bottom : 0; width: 100%\"><h4 style=\"color:white;\">~ Part of the 404 Project ~</h4></div>
	</a>
	<div class=\"idiv\" id=\"ABOUT\"><div class=\"idivs1\">&nbsp;</div>
        
        <div class=\"idivc\">
        
        <div style=\"text-align:center\"><h3><a name=\"Links\">About The Chat</a></h3></div>
        <br><br>
	<div class=\"insb\">Spread the word</div>
	<br>
	If you are passionate about promoting this chat, why not put a link to the site/chat in your regular forum profile signature? Go to your signature edit box and use something like this:<br><br>
	<div class=\"scrollbox\"><div class=\"sbc\"><pre><code>[b][size=100][bgcolor=#121525][color=#166FA6][/color][color=#F7F7F7]the 404 Chatroom:[/color][color=#166FA6] [/color][/bgcolor][/size] [size=100][bgcolor=#C13B5B][color=#F7F7F7]The dopest chat of darkweb.[/color][color=#C13B5B][/color][/bgcolor][/size][/b]</code></pre></div></div> <br>
	
	<div class=\"insb\">Ideas and to-do's that need your input</div>
	<br>
	If you have theme ideas for the chat - or other improvements you'd like to see implemented, just contact a member of staff. Your feedback is highly appreciated.<br><br>
        </div><div class=\"idivs2\">&nbsp;</div><br>
	</div></div>";
	print_end();
}

function send_chat_disabled()
{
	print_start('disabled');
	echo get_setting('disabletext');
	print_end();
}

function send_error($err)
{
	global $I;
	print_start('error');
	echo "<h2>$I[error]: $err</h2>" . form_target('_parent', '') . submit($I['backtologin'], 'class="backbutton"') . '</form>';
	print_end();
}

function send_fatal_error($err)
{
	global $I;
	echo '<!DOCTYPE html><html><head>' . meta_html();
	echo "<title>$I[fatalerror]</title>";
	echo "<style type=\"text/css\">body{background-color:#000000;color:#FF0033;}</style>";
	echo '</head><body>';
	echo "<h2>$I[fatalerror]: $err</h2>";
	print_end();
}

function print_notifications()
{
	global $I, $U, $db;
	echo '<span id="notifications">';
	if ($U['status'] >= 2 && $U['eninbox'] != 0) {
		$stmt = $db->prepare('SELECT COUNT(*) FROM ' . PREFIX . 'inbox WHERE recipient=?;');
		$stmt->execute([$U['nickname']]);
		$tmp = $stmt->fetch(PDO::FETCH_NUM);
		if ($tmp[0] > 0) {
			echo '<p>' . form('inbox') . submit(sprintf($I['inboxmsgs'], $tmp[0])) . '</form></p>';
		}
	}
	if ($U['status'] >= 5 && get_setting('guestaccess') == 3) {
		$result = $db->query('SELECT COUNT(*) FROM ' . PREFIX . 'sessions WHERE entry=0 AND status=1;');
		$temp = $result->fetch(PDO::FETCH_NUM);
		if ($temp[0] > 0) {
			echo '<p>';
			echo form('admin', 'approve');
			echo submit(sprintf($I['approveguests'], $temp[0])) . '</form></p>';
		}
	}
	echo '</span>';
}
function print_chatters()
{
	global $I, $U, $db, $language;

	$icon_star_red = "<img border='0' src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAwAAAAMCAYAAABWdVznAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAB3RJTUUH4wgIACgc4JxSRwAAARBJREFUKM99kL1KA1EQhb/Z6+4GJQQbDQi+Q7CPYMBGKxtrVyRsaSkEg4iCBGxMuQQ2kGewzxtYiW+gpSD5u94dq4hsLp5u5jtnhhnwaJ6mu4tOZ93H1nxNJpNjrDXAUxkF+HWi1p75wErAjkZGnGsBDdvtbpa5zNN0X6bTDQBVFTFmT527ARCRnqqORaQgCNA4nsq83d5mNnsGGvyvFyqVI1lWiyS5UufufU4Jw9soy64B5C9YJMmlOvdYMneiLLvzHq3OHZSnq7VN75e+h8MAaAGIMRcShueAAofu7TVYCRTjcRP4kmq1Hg0GWZRlA6nVdoAP99A7XQmoMXGc51tRv//xu78o3uM8r2sYfi5bP+VcXsOKMjGVAAAAAElFTkSuQmCC'/>";

	$icon_star_gold = "<img border='0' src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAwAAAAMCAYAAABWdVznAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAAsTAAALEwEAmpwYAAABKElEQVQoz32QvUoDQRSFz53ZjfEnMTFgkkYQrOyCragYsdFCLAIpRXwASyEIIoog2PgQiUbRTsXON4i1D7AKmhUk2d3MzLWKhOzgKb9vhnvvASwJb2dnOo+LYzbnWGHkbUr9JQFcDjsBa3ibdLhjM7EP7deaBKsymbDUeV7LDnvq3RSXhfoZBzFgiFjIBaH8IwAwcuKcmF5AbAiAdlJdipqFvFT+A5mghH/CItnSTnqD+qB3NXUgVfsU4Nhj42aOnYp/CAA0KFQjsy+0fzHItJuruZXPE+vRxMFqrBXdWbK25LXOBHGvDBIwTnZPu5O7gGTicP0p4Hj96jq3ouuJj+79XL7Pgrv5oq4nPN1IV2MTtEyOyGo0Pbr19v63IkJPVqOCclLfffYLGXVpfXSgIhUAAAAASUVORK5CYII='/>";

	$icon_star_silver = "<img border='0' src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAwAAAAMCAYAAABWdVznAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAAsTAAALEwEAmpwYAAAA8ElEQVQoz42STSuEURiGr/tgw8pOTfkPk61GIQorG6uz0CRri1moSUmklF8gm/PuZI1m5x/MrPwEH8VGQym3zVHT6yw8y/ujnufqgcKklGaHt/OTJS+URNsb1y+77X8XgE3b2/8qvA26Y8AS0Bz2lqfrvlJKC8BUXkWS5mwfAkg6s30v6TvnP8aBB9s3QDOXRm/pAJ2s9SWta4TMvu2T0t6SjmKMBwCq4dyzfV4Ld2OMx8WjbS8WELeKlB77pyHTQdKOpDZgYOXu0+FPoTdotID3EMJMjPEixng58fXaAJ6er6qt0jus1rWqqpS9tV/tB1UBYQLU/vuEAAAAAElFTkSuQmCC'/>";

	$icon_star_bronze = "<img border='0' src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAwAAAAMCAYAAABWdVznAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAAsTAAALEwEAmpwYAAABEElEQVQoz42QL0hDYRTFf/d7s2jSYhN8w2YZVpmgsoGaDL5ZBBl2hRVhCCoMYWw2g8UijIF9yprYZQOjrymaBiLTsPddgz7Bx4fspnvPuX/OPeCIesGf6l/Pj7o44wIHka6dXTwXhx4A1q3V7aEGet2yp7AEZPrt5fEkL/WCvxBZHQNQRURkTlUPAUSoqnIrggXBM3xILfAnI6stIMP/0fGMrEpcVTf8fVWtOHUbOS41wwMALwbbD7273OzEG5BPNJdLzfDI+bSqLia3W6tZp0svnRPDtzuIyI4xUgQUyN186m9fKk4uK+dZ4H0kZab3Go+vAFe7M63waXDf3UoHQOPP6Vrg55NyTjfT8sOtxNgX5ehXBVg4i6sAAAAASUVORK5CYII='/>";

	$icon_heart_red = "<img border='0' src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAwAAAAMCAYAAABWdVznAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAAsTAAALEwEAmpwYAAABs0lEQVQoz22Ry2sTURSHv3vvPNLMTBLTiiVIFSsuxFCIuBJEKi58LN3730k0BRcVBVEpXSloN1IrrYJSHyQTZ5pn03nc6yJpF+K3/J3v/BbnCIDnNqeWa9WrjuN4xlJbF3Z+7gNsX1pccjPdyI3u7+13P9zP6InXc1SvXDy/UQn8upSSLM97nU7nzmGaumdrtXVHWb7BEPf6W+8/f1+1Fqqle+XAr9u2DYBlWWW3OPfCEYHrFQoFYwwAlVLQOHcmuGVpaEgpOUYbw+nqfNkYw7EMoKREIlZkotlO9HRghABAGIMUApSCWWa0xlFqR/7pDzZ+t8NxNhojkgSpNUJMPZFmiMkEMRqQxPFwPBi+lXdH5steO3zZ7Ubo8RjybNYqwOSQpiSDEV/b4bOVOP2mAKzEtBZ1+jAwVHzHBrcASkKuSQ4GfOzGnxrR0SqABHjgCx1m+vpubxiFYYzp9WFyRBYdsBvFnR+T9OZm2REnF3hcVAA0PevyZqVgftUqJlpaMO/mPb0e2MsAT2bOCS1/+oeWZ197U3IOX5XcYdOz6wBPA4f/sjZbahbV7UdFdQNg7R/5Lza2vZnfg8j9AAAAAElFTkSuQmCC'/>";

	//Color was changed from blue to light blue
	$icon_heart_blue = "<img border='0' src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAwAAAAMCAYAAABWdVznAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAAsTAAALEwEAmpwYAAABqUlEQVQoz2WQu2tTYRiHn/c7JyeXJpbopnAU9yJEHFSUEHUoTiIOXQTXtouLf4K46RBHVxcLHQwIIhKdXOwi6iISW/Ba06QnObmc7/teB220+My/Gz8BaNz9WK2W8yejiDkR2Xh4/fAWwNKDrdgGpmas3/2a+Ncvbh7ty8X7nYNHyrl2qWgWAq9YY/r9JFu0nvyhueBxaCgDJBPd6HRtI6wUgsulolmIAIwQoPNRaJ5EkM+HUuAPpaLUqgeCCyFQC7yCEQCcCpVCMC8o/xJ4JXT+hHEqb60xM/EeRkBE9plE5L1JJ7bdS2w6yhTUIyiB/E53XnFeGakwmPjBKNNX5tnKsQ/bY/t0J1MmVlH9O8UrTB2Mpo7toW+1luOOAfjSD64mvazTszBB9uoBmFrPTuLetZbjJQADcOd27MehOTsY2O7uwJJ6yJwynCrd1H9Plfpi85PMDKk3tFfjzyPkXG8MvcTyc+j4NnI6VDnzfCX+cePWcQWY3fConOPaIKNxr3MqDMxL47wbh+Z0ezV+s16JuJJM+Y+1cg6AenPzUr25eR5grRLt0/wCkH7H2hCmE9kAAAAASUVORK5CYII='/>";


	if (!$U['hidechatters']) {
		echo '<div id="chatters">';
		if ($U['status'] >= 5) {
			$stmt = $db->prepare('SELECT nickname, style, status, roomid, afk, afk_message FROM ' . PREFIX . 'sessions WHERE entry!=0 AND status>0 AND incognito=0 AND nickname NOT IN (SELECT ign FROM ' . PREFIX . 'ignored WHERE ignby=? UNION SELECT ignby FROM ' . PREFIX . 'ignored WHERE ign=?) ORDER BY status DESC, lastpost DESC;');
		} else {
			$stmt = $db->prepare('SELECT nickname, style, status, roomid, afk, afk_message FROM ' . PREFIX . 'sessions WHERE entry!=0 AND status>0 AND incognito=0 AND nickname NOT IN (SELECT ign FROM ' . PREFIX . 'ignored WHERE ignby=? UNION SELECT ignby FROM ' . PREFIX . 'ignored WHERE ign=?) ORDER BY lastpost DESC;');
		}
		$stmt->execute([$U['nickname'], $U['nickname']]);
		$nc = substr(time(), -6);
		$G = $M = $S = [];
		
		// Add Dot bot at top of appropriate list based on user status
		$bot_style = 'color:#ffffff;font-weight:bold;font-family:Arial, sans-serif;'; // Light blue color
		$bot_link = "<a style=\"text-decoration: none;\" href=\"?action=post&amp;session=$U[session]&amp;lang=$language&amp;nc=$nc&amp;sendto=Dot\" target=\"post\">" . style_this('Dot', $bot_style) . '</a>';
		$bot_display = "<nobr>" . rank_this(10) . " <span class='inroom'>" . $bot_link . "</span></nobr>";
		
		// Staff (status 5+) see Dot in staff list, others see in member list
		if ($U['status'] >= 5) {
			$S[] = $bot_display; // Add to staff array (will be shown first)
		} else {
			$M[] = $bot_display; // Add to member array (will be shown first)
		}
		
		while ($user = $stmt->fetch(PDO::FETCH_BOTH)) {
			//MODIFICATION chat rooms
			$roomclass = 'notinroom';
			if ($U['roomid'] === $user['roomid']) {
				$roomclass = 'inroom';
			}
			
			// Build room indicator that appears after username
			$room_indicator = '';
			if ($user['roomid'] !== $U['roomid']) {
				// User is in a different room
				if ($user['roomid'] === null) {
					// User is in Main Chat, viewer is not
					$room_indicator = " <small><a style='color:#888; text-decoration:none;' href='?action=view&amp;session=$U[session]&amp;room=*' target='view'>[Main Chat]</a></small>";
				} else {
					// User is in another room - check if viewer has access
					$stmt1 = $db->prepare('SELECT name FROM ' . PREFIX . 'rooms WHERE id=? AND access<=?;');
					$stmt1->execute([$user['roomid'], $U['status']]);
					if ($room = $stmt1->fetch(PDO::FETCH_NUM)) {
						// Viewer has access - show clickable room link
						$room_indicator = " <small><a style='color:#888; text-decoration:none;' href='?action=view&amp;session=$U[session]&amp;room=" . urlencode($user['roomid']) . "' target='view'>[" . htmlspecialchars($room[0]) . "]</a></small>";
					} else {
						// Viewer doesn't have access - show dimmed [other]
						$room_indicator = " <small style='color:#666;'>[other]</small>";
					}
				}
			}

			$stmt1 = $db->prepare('SELECT name FROM ' . PREFIX . 'rooms WHERE id=? AND access<=? ;');
			$stmt1->execute([$user['roomid'], $U['status']]);
			if ($room = $stmt1->fetch(PDO::FETCH_NUM)) {
				$roomname = $room[0];
			} else {
				$roomname = " ";
				if ($user['roomid'] === null) {
					$roomname = "[Main Chat]";
				}
			}
			$roomprefix = "<span class=\"$roomclass\" title=\"$roomname\">";
			$roompostfix = '</span>';

			// Add (afk) suffix if user is away
			$afk_suffix = '';
			if (!empty($user['afk']) && $user['afk'] == 1) {
				$afk_title = !empty($user['afk_message']) ? htmlspecialchars($user['afk_message']) : 'Away from keyboard';
				$afk_suffix = " <small style='color:#888;' title='$afk_title'>(afk)</small>";
			}

		// In modroom mode, link to user history viewer instead of PM compose
		if (isset($_REQUEST['modroom']) && $_REQUEST['modroom'] && $U['status'] >= 5) {
			$link = "<a style=\"text-decoration: none;\" href=\"?action=admin&amp;session=$U[session]&amp;do=userhistory&amp;user=" . urlencode($user[0]) . '" target="view">' . style_this(htmlspecialchars($user[0]), $user[1]) . $room_indicator . $afk_suffix . '</a>';
		} else {
			$link = "<a style=\"text-decoration: none;\" href=\"?action=post&amp;session=$U[session]&amp;lang=$language&amp;nc=$nc&amp;sendto=" . htmlspecialchars($user[0]) . '" target="post">' . style_this(htmlspecialchars($user[0]), $user[1]) . $room_indicator . $afk_suffix . '</a>';
		}
			//staff can see the different rank icons of the staff people
			if ($U['status'] >= 5) {    //if logged in user is moderator or higher            

				if ($user[2] >= 8) {
					$link = "<nobr>" . rank_this($user[2]) . $roomprefix . $link . $roompostfix . "</nobr>"; //adds red star icon in front of the nick.
					$S[] = $link;
				} elseif ($user[2] == 7) {
					$link = "<nobr>" . rank_this($user[2]) . $roomprefix . $link . $roompostfix . "</nobr>"; //adds gold star icon in front of the nick.
					$S[] = $link;
				} elseif ($user[2] == 6) {
					$link = "<nobr>" . rank_this($user[2]) . $roomprefix . $link . $roompostfix . "</nobr>"; //adds silver star icon in front of the nick.
					$S[] = $link;
				} elseif ($user[2] == 5) {
					$link = "<nobr>" . rank_this($user[2]) . $roomprefix . $link . $roompostfix . "</nobr>"; //adds bronze star icon in front of the nick.
					$S[] = $link;
				} elseif ($user[2] == 3) {
					$link = "<nobr>" . rank_this($user[2]) . $roomprefix . $link . $roompostfix . "</nobr>"; //adds "heart icon red" in front of the nick.
					$M[] = $link;
				} elseif ($user[2] == 2) {
					$link = "<nobr>" . rank_this($user[2]) . $roomprefix . $link . $roompostfix . "</nobr>"; //adds "heart icon pink" in front of the nick.
					$G[] = $link;
				} else {
					$G[] = $roomprefix . $link . $roompostfix;
				}

				//guests and members can't see the different rank icons of the staff
			} else {
				if ($user[2] >= 5) {
					$link = "<nobr>" . rank_this('5') . $roomprefix . $link . $roompostfix . "</nobr>"; //adds star icon in front of the nick. No break tags (deprecated) to prevent line break between icon and nickname.
					$M[] = $link;
				} elseif ($user[2] == 3) {
					$link = "<nobr>" . rank_this('3') . $roomprefix . $link . $roompostfix . "</nobr>"; //adds "heart icon red" in front of the nick.
					$M[] = $link;
				} elseif ($user[2] == 2) {
					$link = "<nobr>" . rank_this('2') . $roomprefix . $link . $roompostfix . "</nobr>"; //adds "heart icon" pink in front of the nick.
					$G[] = $link;
				} else {
					$G[] = $roomprefix . $link . $roompostfix;
				}
			} //end if
		} //end while
		
	// Display bot group first (always show Dot bot) - DISABLED: Dot now in staff/member lists
	// if (!empty($B)) {
	// 	echo "<span class='group'>Bot (1)</span><div>" . implode('</div><div>', $B) . '</div>';
	// 	if (!empty($S) || !empty($M) || !empty($RG) || !empty($G)) {
	// 		echo '<div>&nbsp;&nbsp;</div>';
	// 	}
	// } //end if
	
	if ($U['status'] >= 5) {
			$chanlinks = "<a style=\"color:#fff; text-decoration: none\" href=\"?action=post&amp;session=$U[session]&amp;lang=$language&amp;nc=$nc&amp;sendto=s 48\" target=\"post\">$I[staff]</a>";
			$chanlinksys = "<a style=\"color:#fff; text-decoration: none\" href=\"?action=post&amp;session=$U[session]&amp;lang=$language&amp;nc=$nc&amp;sendto=s 50\" target=\"post\">$I[tosysmsg]</a>";
			$chanlinkm = "<a style=\"color:#fff; text-decoration: none\" href=\"?action=post&amp;session=$U[session]&amp;lang=$language&amp;nc=$nc&amp;sendto=s 31\" target=\"post\">$I[members2]</a>";
			$chanlinkapp = "$I[applicants]";  // Applicants (status 2) - staff can see but no channel
			$chanlinkg = "$I[guests]";
		} elseif ($U['status'] == 3) {
			$chanlinks = "$I[staff]";
			$chanlinksys = "$I[tosysmsg]";
			$chanlinkm = "<a style=\"color:#fff; text-decoration: none\" href=\"?action=post&amp;session=$U[session]&amp;lang=$language&amp;nc=$nc&amp;sendto=s 31\"  target=\"post\">$I[members2]</a>";
			$chanlinkapp = "$I[applicants]";  // Members see applicants but no channel
			$chanlinkg = "$I[guests]";
		} elseif ($U['status'] == 2) {
			$chanlinks = "$I[staff]";
			$chanlinksys = "$I[tosysmsg]";
			$chanlinkm = "$I[members2]";
			$chanlinkapp = "$I[applicants]";  // Applicants see label but no channel
			$chanlinkg = "$I[guests]";
		} else {
			$chanlinks = "$I[staff]";
			$chanlinksys = "$I[tosysmsg]";
			$chanlinkm = "$I[members2]";
			$chanlinkapp = "$I[applicants]";
			$chanlinkg = "$I[guests]";
		}
		if (!empty($S)) {
			echo "<span class='group'>" . $chanlinks . " (" . count($S) . ")</span><div>" . implode('</span><br><span>', $S) . '</div>';
			if (!empty($M) || !empty($R) || !empty($G)) {
				echo '<div>&nbsp;&nbsp;</div>';
			}
		}
		if (!empty($M)) {
			echo "<span class='group'>" . $chanlinkm . " (" . count($M) . ")</span><div>" . implode('</span><br><span>', $M) . '</div>';
			if (!empty($RG) || !empty($G)) {
				echo '<div>&nbsp;&nbsp;</div>';
			}
		}
		if (!empty($RG)) {
			echo "<span class='group'>" . $chanlinkapp . " (" . count($RG) . ")</span><div>" . implode('</span><br><span>', $RG) . '</div>';
			if (!empty($G)) {
				echo '<div>&nbsp;&nbsp;</div>';
			}
		}
		if (!empty($G)) {
			echo "<span class='group'>" . $chanlinkg . " (" . count($G) . ")</span><div>" . implode('</span><br><span>', $G) . '</div>';
		}
		echo '</div>';
	} //end if
} //end function print_chatters

//  session management

function create_session($setup, $nickname, $password)
{
	global $I, $U;
	$U['nickname'] = preg_replace('/\s/', '', $nickname);
	if (check_member($password)) {
		if ($setup && $U['status'] >= 7) {
			$U['incognito'] = 1;
		}
		$U['entry'] = $U['lastpost'] = time();
	} else {
		add_user_defaults($password);
		check_captcha(isset($_REQUEST['challenge']) ? $_REQUEST['challenge'] : '', isset($_REQUEST['captcha']) ? $_REQUEST['captcha'] : '');
		$ga = (int) get_setting('guestaccess');
		if (!valid_nick($U['nickname'])) {
			send_error(sprintf($I['invalnick'], get_setting('maxname'), get_setting('nickregex')));
		}
		if (!valid_pass($password)) {
			send_error(sprintf($I['invalpass'], get_setting('minpass'), get_setting('passregex')));
		}
		if ($ga === 0) {
			send_error($I['noguests']);
		} elseif ($ga === 3) {
			$U['entry'] = 0;
		}
		if (get_setting('englobalpass') != 0 && isset($_REQUEST['globalpass']) && $_REQUEST['globalpass'] != get_setting('globalpass')) {
			send_error($I['wrongglobalpass']);
		}
	}
	write_new_session($password);
}

function rank_this($status)
{

	/*
1 .rank.g { background-image: url('green-1.png'); }
2 .rank.ra { background-image: url('green-2.png'); }
3 .rank.m { background-image: url('blue-1.png'); }
5 .rank.mod { background-image: url('red-1.png'); }
6 .rank.sm { background-image: url('red-2.png'); }
7 .rank.a { background-image: url('red-3.png'); }
8 .rank.sa { background-image: url('yellow-1.png'); }
*/

	$rank = "";

	switch ($status) {
		case 1:
			$rank = "g";
			break;
		case 2:
			$rank = "ra";
			break;
		case 3:
			$rank = "m";
			break;
		case 5:
			$rank = "mod";
			break;
		case 6:
			$rank = "sm";
			break;
		case 7:
			$rank = "a";
			break;
		case 8:
			$rank = "sa";
			break;
		case 9:
			$rank = "sa";
			break;
		case 10:
			$rank = "boom";
			break;
		default:
			$rank = "";
	}

	if (strlen($rank)) {
		return sprintf("<span class=\"rank %s\"></span><bdi class=\"spacer\"></bdi>", $rank);
	}
	return '';
}

function check_captcha($challenge, $captcha_code)
{
	global $I, $db, $memcached;
	$captcha = (int) get_setting('captcha');
	if ($captcha !== 0) {
		if (empty($challenge)) {
			send_error($I['wrongcaptcha']);
		}
		if (MEMCACHED) {
			if (!$code = $memcached->get(DBNAME . '-' . PREFIX . "captcha-$_REQUEST[challenge]")) {
				send_error($I['captchaexpire']);
			}
			$memcached->delete(DBNAME . '-' . PREFIX . "captcha-$_REQUEST[challenge]");
		} else {
			$stmt = $db->prepare('SELECT code FROM ' . PREFIX . 'captcha WHERE id=?;');
			$stmt->execute([$challenge]);
			$stmt->bindColumn(1, $code);
			if (!$stmt->fetch(PDO::FETCH_BOUND)) {
				send_error($I['captchaexpire']);
			}
			$time = time();
			$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'captcha WHERE id=? OR time<(?-(SELECT value FROM ' . PREFIX . "settings WHERE setting='captchatime'));");
			$stmt->execute([$challenge, $time]);
		}
		if ($captcha_code !== $code) {
			if ($captcha !== 3 || strrev($captcha_code) !== $code) {
				send_error($I['wrongcaptcha']);
			}
		}
	}
}

function is_definitely_ssl()
{
	if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') {
		return true;
	}
	if (isset($_SERVER['SERVER_PORT']) && ('443' == $_SERVER['SERVER_PORT'])) {
		return true;
	}
	if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && ('https' == $_SERVER['HTTP_X_FORWARDED_PROTO'])) {
		return true;
	}
	return false;
}

function set_secure_cookie($name, $value)
{
	if (version_compare(PHP_VERSION, '7.3.0') >= 0) {
		setcookie($name, $value, ['expires' => 0, 'path' => '/', 'domain' => '', 'secure' => is_definitely_ssl(), 'httponly' => true, 'samesite' => 'Strict']);
	} else {
		setcookie($name, $value, 0, '/', '', is_definitely_ssl(), true);
	}
}

function write_new_session($password)
{
	global $I, $U, $db;
	$stmt = $db->prepare('SELECT * FROM ' . PREFIX . 'sessions WHERE nickname=?;');
	$stmt->execute([$U['nickname']]);
	if ($temp = $stmt->fetch(PDO::FETCH_ASSOC)) {
		// check whether alrady logged in
		if (password_verify($password, $temp['passhash'])) {
			$U = $temp;
			// Ensure user has a color in their style
			$U['style'] = ensure_color_in_style($U['style']);
			check_kicked();
			set_secure_cookie(COOKIENAME, $U['session']);
		} else {
			send_error("$I[userloggedin]<br>$I[wrongpass]");
		}
	} else {
		// create new session
		$stmt = $db->prepare('SELECT null FROM ' . PREFIX . 'sessions WHERE session=?;');
		do {
			if (function_exists('random_bytes')) {
				$U['session'] = bin2hex(random_bytes(16));
			} else {
				$U['session'] = md5(uniqid($U['nickname'], true) . mt_rand());
			}
			$stmt->execute([$U['session']]);
		} while ($stmt->fetch(PDO::FETCH_NUM)); // check for hash collision
		if (isset($_SERVER['HTTP_USER_AGENT'])) {
			$useragent = htmlspecialchars($_SERVER['HTTP_USER_AGENT']);
		} else {
			$useragent = '';
		}
		if (get_setting('trackip')) {
			$ip = $_SERVER['REMOTE_ADDR'];
		} else {
			$ip = '';
		}
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'sessions (session, nickname, status, refresh, style, lastpost, passhash, useragent, bgcolour, entry, timestamps, embed, incognito, ip, nocache, tz, eninbox, sortupdown, hidechatters, nocache_old) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);');
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'sessions (session, nickname, status, refresh, style, lastpost, passhash, useragent, bgcolour, entry, timestamps, embed, incognito, ip, nocache, tz, eninbox, sortupdown, hidechatters, nocache_old) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);');
		$stmt->execute([$U['session'], $U['nickname'], $U['status'], $U['refresh'], $U['style'], $U['lastpost'], $U['passhash'], $useragent, $U['bgcolour'], $U['entry'], $U['timestamps'], $U['embed'], $U['incognito'], $ip, $U['nocache'], $U['tz'], $U['eninbox'], $U['sortupdown'], $U['hidechatters'], $U['nocache_old']]);
		set_secure_cookie(COOKIENAME, $U['session']);

		//MDIFICATION for clickable nicknames setting. (clickablenicknames value added)
		/* REMVOE LATER
		$stmt=$db->prepare('INSERT INTO ' . PREFIX . 'sessions (session, nickname, status, refresh, style, lastpost, passhash, useragent, bgcolour, entry, timestamps, embed, incognito, ip, nocache, tz, eninbox, sortupdown, hidechatters, nocache_old, clickablenicknames) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);');
		$stmt->execute([$U['session'], $U['nickname'], $U['status'], $U['refresh'], $U['style'], $U['lastpost'], $U['passhash'], $useragent, $U['bgcolour'], $U['entry'], $U['timestamps'], $U['embed'], $U['incognito'], $ip, $U['nocache'], $U['tz'], $U['eninbox'], $U['sortupdown'], $U['hidechatters'], $U['nocache_old'],$U['clickablenicknames'] ]);
		setcookie(COOKIENAME, $U['session']);
		*/

		//MODIFICATION adminjoinleavemsg setting for join/leave message for admins
		if (($U['status'] >= 3 && $U['status'] <= 6 && !$U['incognito']) || ($U['status'] >= 7 && !$U['incognito'] && (bool) get_setting('adminjoinleavemsg'))) {
			add_system_message(sprintf(get_setting('msgenter'), style_this_clickable(htmlspecialchars($U['nickname']), $U['style'])));
		}
	}
}

function approve_session()
{
	global $db;
	if (isset($_REQUEST['what'])) {
		if ($_REQUEST['what'] === 'allowchecked' && isset($_REQUEST['csid'])) {
			$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET entry=lastpost WHERE nickname=?;');
			foreach ($_REQUEST['csid'] as $nick) {
				$stmt->execute([$nick]);
			}
		} elseif ($_REQUEST['what'] === 'allowall' && isset($_REQUEST['alls'])) {
			$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET entry=lastpost WHERE nickname=?;');
			foreach ($_REQUEST['alls'] as $nick) {
				$stmt->execute([$nick]);
			}
		} elseif ($_REQUEST['what'] === 'denychecked' && isset($_REQUEST['csid'])) {
			$time = 60 * (get_setting('kickpenalty') - get_setting('guestexpire')) + time();
			$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET lastpost=?, status=0, kickmessage=? WHERE nickname=? AND status=1;');
			foreach ($_REQUEST['csid'] as $nick) {
				$stmt->execute([$time, $_REQUEST['kickmessage'], $nick]);
			}
		} elseif ($_REQUEST['what'] === 'denyall' && isset($_REQUEST['alls'])) {
			$time = 60 * (get_setting('kickpenalty') - get_setting('guestexpire')) + time();
			$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET lastpost=?, status=0, kickmessage=? WHERE nickname=? AND status=1;');
			foreach ($_REQUEST['alls'] as $nick) {
				$stmt->execute([$time, $_REQUEST['kickmessage'], $nick]);
			}
		}
	}
}

function check_login()
{
	global $I, $U, $db;
	$ga = (int) get_setting('guestaccess');
	if (isset($_REQUEST['session'])) {
		parse_sessions();
	}
	if (isset($U['session'])) {
		check_kicked();
	} elseif (get_setting('englobalpass') == 1 && (!isset($_REQUEST['globalpass']) || $_REQUEST['globalpass'] != get_setting('globalpass'))) {
		send_error($I['wrongglobalpass']);
	} elseif (!isset($_REQUEST['nick']) || !isset($_REQUEST['pass'])) {
		send_login();
	} else {
		if ($ga === 4) {
			send_chat_disabled();
		}
		if (!empty($_REQUEST['regpass']) && $_REQUEST['regpass'] !== $_REQUEST['pass']) {
			send_error($I['noconfirm']);
		}
		create_session(false, $_REQUEST['nick'], $_REQUEST['pass']);
		if (!empty($_REQUEST['regpass'])) {
			$guestreg = (int) get_setting('guestreg');
			if ($guestreg === 1) {
				register_guest(2, $_REQUEST['nick']);
				$U['status'] = 2;
			} elseif ($guestreg === 2) {
				register_guest(3, $_REQUEST['nick']);
				$U['status'] = 3;
			}
		}
	}
	if ($U['status'] == 1) {
		if ($ga === 2 || $ga === 3) {
			$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET entry=0 WHERE session=?;');
			$stmt->execute([$U['session']]);
			send_waiting_room();
		}
	}
}

function kill_session()
{
	global $U, $db;
	parse_sessions();
	check_expired();
	check_kicked();
	setcookie(COOKIENAME, false);
	$_REQUEST['session'] = '';
	$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'sessions WHERE session=?;');
	$stmt->execute([$U['session']]);

	//Modification adminjoinleavemsg
	if (($U['status'] >= 3 && $U['status'] <= 6 && !$U['incognito']) || ($U['status'] >= 7 && !$U['incognito'] && (bool) get_setting('adminjoinleavemsg'))) {
		//MODIFICATION for clickablenicknames stlye_this_clickable instead of style_this
		add_system_message(sprintf(get_setting('msgexit'), style_this_clickable(htmlspecialchars($U['nickname']), $U['style'])));
	}
}

function kick_chatter($names, $mes, $purge)
{
	global $U, $db;
	$lonick = '';
	$time = 60 * (get_setting('kickpenalty') - get_setting('guestexpire')) + time();
	$check = $db->prepare('SELECT style, entry FROM ' . PREFIX . 'sessions WHERE nickname=? AND status!=0 AND (status<? OR nickname=?);');
	$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET lastpost=?, status=0, kickmessage=? WHERE nickname=?;');
	$all = false;
	if ($names[0] === 's &') {
		$tmp = $db->query('SELECT nickname FROM ' . PREFIX . 'sessions WHERE status=1;');
		$names = [];
		while ($name = $tmp->fetch(PDO::FETCH_NUM)) {
			$names[] = $name[0];
		}
		$all = true;
	}
	$i = 0;
	foreach ($names as $name) {
		$check->execute([$name, $U['status'], $U['nickname']]);
		if ($temp = $check->fetch(PDO::FETCH_ASSOC)) {
			$stmt->execute([$time, $mes, $name]);
			if ($purge) {
				del_all_messages($name, $temp['entry']);
			}
			// Log the kick action
			log_mod_action('kick', $name, $mes ?: 'No reason provided', get_setting('kickpenalty'), false, null, 2);
			log_user_action($name, 'kick', $U['nickname'], $mes ?: 'No reason provided', get_setting('kickpenalty') * 60);
			//MODIFICATION style_thins replaced with style_this_clickable
			$lonick .= style_this_clickable(htmlspecialchars($name), $temp['style']) . ', ';
			++$i;
		}
	}
	if ($i > 0) {
		if ($all) {
			add_system_message(get_setting('msgallkick'));
		} else {
			$lonick = substr($lonick, 0, -2);
			if ($i > 1) {
				add_system_message(sprintf(get_setting('msgmultikick'), $lonick));
			} else {
				add_system_message(sprintf(get_setting('msgkick'), $lonick));
			}
		}
		return true;
	}
	return false;
}

function logout_chatter($names)
{
	global $U, $db;
	$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'sessions WHERE nickname=? AND status<?;');
	if ($names[0] === 's &') {
		$tmp = $db->query('SELECT nickname FROM ' . PREFIX . 'sessions WHERE status=1;');
		$names = [];
		while ($name = $tmp->fetch(PDO::FETCH_NUM)) {
			$names[] = $name[0];
		}
	}
	foreach ($names as $name) {
		$stmt->execute([$name, $U['status']]);
	}
}

function check_session()
{
	global $U, $bridge;
	parse_sessions();
	check_expired();
	check_kicked();
	if ($U['entry'] == 0) {
		send_waiting_room();
	}

	// Bridge integration: notify IRC when user joins
	if (BRIDGE_ENABLED && $U['entry'] != 0 && !isset($_SESSION['bridge_joined'])) {
		if (!isset($bridge) || !$bridge->isConnected()) {
			$bridge = new BridgeClient();
			$bridge->connect();
		}

		if ($bridge->isConnected()) {
			$bridge->notifyUserJoin($U['nickname'], $U['nickname'], $U['status']);
			$_SESSION['bridge_joined'] = true;
		}
	}
}

function check_expired()
{
	global $I, $U;
	
	// Run moderation system cleanup periodically
	static $last_cleanup = 0;
	if (time() - $last_cleanup > 300) { // Run every 5 minutes
		cleanup_moderation_system();
		$last_cleanup = time();
	}
	
	if (!isset($U['session'])) {
		setcookie(COOKIENAME, false);
		$_REQUEST['session'] = '';
		send_error($I['expire']);
	}
}

function get_count_mods()
{
	global $db;
	$c = $db->query('SELECT COUNT(*) FROM ' . PREFIX . 'sessions WHERE status>=5 AND nickname!=\'Dot\'')->fetch(PDO::FETCH_NUM);
	return $c[0];
}

function check_kicked()
{
	global $I, $U;
	if ($U['status'] == 0) {
		setcookie(COOKIENAME, false);
		$_REQUEST['session'] = '';
		send_error("$I[kicked]<br>$U[kickmessage]");
	}
}

function get_nowchatting()
{
	global $I, $db;
	parse_sessions();
	$stmt = $db->query('SELECT COUNT(*) FROM ' . PREFIX . 'sessions WHERE entry!=0 AND status>0 AND incognito=0;');
	$count = $stmt->fetch(PDO::FETCH_NUM);
	echo '<div id="chatters">' . sprintf($I['curchat'], $count[0]) . '<br>';
	if (!get_setting('hidechatters')) {

		//MODIFICATION hidden ranks on frontpage. Some lines changed and some lines added.
		$stmt = $db->query('SELECT nickname, style FROM ' . PREFIX . 'sessions WHERE entry!=0 AND status>=3 AND incognito=0 ORDER BY lastpost DESC;');
		while ($user = $stmt->fetch(PDO::FETCH_NUM)) {
			echo style_this(htmlspecialchars($user[0]), $user[1]) . ' &nbsp; ';
		}

		$stmt = $db->query('SELECT nickname, style FROM ' . PREFIX . 'sessions WHERE entry!=0 AND status>0 AND status<3 AND incognito=0 ORDER BY status DESC, lastpost DESC;');
		while ($user = $stmt->fetch(PDO::FETCH_NUM)) {
			echo style_this(htmlspecialchars($user[0]), $user[1]) . ' &nbsp; ';
		}
	}

	echo '</div>';
}

function parse_sessions()
{
	global $U, $db;
	// look for our session
	if (isset($_REQUEST['session'])) {
		$stmt = $db->prepare('SELECT * FROM ' . PREFIX . 'sessions WHERE session=?;');
		$stmt->execute([$_REQUEST['session']]);
		if ($tmp = $stmt->fetch(PDO::FETCH_ASSOC)) {
			$U = $tmp;
			// Ensure user has a color in their style
			$U['style'] = ensure_color_in_style($U['style']);
		}
	}
	set_default_tz();
}

//  member handling

function check_member($password)
{
	global $I, $U, $db;
	$stmt = $db->prepare('SELECT * FROM ' . PREFIX . 'members WHERE nickname=?;');
	$stmt->execute([$U['nickname']]);
	if ($temp = $stmt->fetch(PDO::FETCH_ASSOC)) {
		if (get_setting('dismemcaptcha') == 0) {
			check_captcha(isset($_REQUEST['challenge']) ? $_REQUEST['challenge'] : '', isset($_REQUEST['captcha']) ? $_REQUEST['captcha'] : '');
		}
		if ($temp['passhash'] === md5(sha1(md5($U['nickname'] . $password)))) {
			// old hashing method, update on the fly
			$temp['passhash'] = password_hash($password, PASSWORD_DEFAULT);
			$stmt = $db->prepare('UPDATE ' . PREFIX . 'members SET passhash=? WHERE nickname=?;');
			$stmt->execute([$temp['passhash'], $U['nickname']]);
		}
		if (password_verify($password, $temp['passhash'])) {
			$U = $temp;
			// Ensure user has a color in their style
			$U['style'] = ensure_color_in_style($U['style']);
			$stmt = $db->prepare('UPDATE ' . PREFIX . 'members SET lastlogin=? WHERE nickname=?;');
			$stmt->execute([time(), $U['nickname']]);
			return true;
		} else {
			send_error("$I[regednick]<br>$I[wrongpass]");
		}
	}
	return false;
}

function delete_account()
{
	global $U, $db;
	if ($U['status'] < 8) {
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET status=1, incognito=0 WHERE nickname=?;');
		$stmt->execute([$U['nickname']]);
		$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'members WHERE nickname=?;');
		$stmt->execute([$U['nickname']]);
		$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'inbox WHERE recipient=?;');
		$stmt->execute([$U['nickname']]);
		$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'notes WHERE type=2 AND editedby=?;');
		$stmt->execute([$U['nickname']]);
		$U['status'] = 1;
	}
}

function register_guest($status, $nick)
{
	global $I, $U, $db;
	$stmt = $db->prepare('SELECT style FROM ' . PREFIX . 'members WHERE nickname=?');
	$stmt->execute([$nick]);
	if ($tmp = $stmt->fetch(PDO::FETCH_NUM)) {
		return sprintf($I['alreadyreged'], style_this(htmlspecialchars($nick), $tmp[0]));
	}
	$stmt = $db->prepare('SELECT * FROM ' . PREFIX . 'sessions WHERE nickname=? AND status=1;');
	$stmt->execute([$nick]);
	if ($reg = $stmt->fetch(PDO::FETCH_ASSOC)) {
		$reg['status'] = $status;
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET status=? WHERE session=?;');
		$stmt->execute([$reg['status'], $reg['session']]);
	} else {
		return sprintf($I['cantreg'], htmlspecialchars($nick));
	}

	$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'members (nickname, passhash, status, refresh, bgcolour, regedby, timestamps, embed, style, incognito, nocache, tz, eninbox, sortupdown, hidechatters, nocache_old) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);');

	//MODIFICATION for clickable nicknames
	/* REMOVE LATER
	$stmt=$db->prepare('INSERT INTO ' . PREFIX . 'members (nickname, passhash, status, refresh, bgcolour, regedby, timestamps, embed, style, incognito, nocache, tz, eninbox, sortupdown, hidechatters, clickablenicknames, nocache_old) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);');
	*/

	//MODIFICATION for clickable nicknames
	/* REMOVE LATER
	$stmt->execute([$reg['nickname'], $reg['passhash'], $reg['status'], $reg['refresh'], $reg['bgcolour'], $U['nickname'], $reg['timestamps'], $reg['embed'], $reg['style'], $reg['incognito'], $reg['nocache'], $reg['tz'], $reg['eninbox'], $reg['sortupdown'], $reg['hidechatters'], $reg['clickablenicknames'], $reg['nocache_old']]);
	*/
	$stmt->execute([$reg['nickname'], $reg['passhash'], $reg['status'], $reg['refresh'], $reg['bgcolour'], $U['nickname'], $reg['timestamps'], $reg['embed'], $reg['style'], $reg['incognito'], $reg['nocache'], $reg['tz'], $reg['eninbox'], $reg['sortupdown'], $reg['hidechatters'], $reg['nocache_old']]);
	if ($reg['status'] == 3) {
		//MODIFICATION stlye_this_clickable instead of style_this
		add_system_message(sprintf(get_setting('msgmemreg'), style_this_clickable(htmlspecialchars($reg['nickname']), $reg['style'])));
	} else {
		//MODIFICATION stlye_this_clickable instead of style_this
		add_system_message(sprintf(get_setting('msgsureg'), style_this_clickable(htmlspecialchars($reg['nickname']), $reg['style'])));
	}
	return sprintf($I['successreg'], style_this(htmlspecialchars($reg['nickname']), $reg['style']));
}

function register_new($nick, $pass)
{
	global $I, $U, $db;
	$nick = preg_replace('/\s/', '', $nick);
	if (empty($nick)) {
		return '';
	}
	$stmt = $db->prepare('SELECT null FROM ' . PREFIX . 'sessions WHERE nickname=?');
	$stmt->execute([$nick]);
	if ($stmt->fetch(PDO::FETCH_NUM)) {
		return sprintf($I['cantreg'], htmlspecialchars($nick));
	}
	if (!valid_nick($nick)) {
		return sprintf($I['invalnick'], get_setting('maxname'), get_setting('nickregex'));
	}
	if (!valid_pass($pass)) {
		return sprintf($I['invalpass'], get_setting('minpass'), get_setting('passregex'));
	}
	$stmt = $db->prepare('SELECT null FROM ' . PREFIX . 'members WHERE nickname=?');
	$stmt->execute([$nick]);
	if ($stmt->fetch(PDO::FETCH_NUM)) {
		return sprintf($I['alreadyreged'], htmlspecialchars($nick));
	}

	$reg = [
		'nickname'	=> $nick,
		'passhash'	=> password_hash($pass, PASSWORD_DEFAULT),
		//Modification Register new Applicant
		'status'	=> (get_setting('suguests') ? 2 : 3),

		'refresh'	=> get_setting('defaultrefresh'),
		'bgcolour'	=> get_setting('colbg'),
		'regedby'	=> $U['nickname'],
		'timestamps'	=> get_setting('timestamps'),
		'style'		=> 'color:#' . get_setting('coltxt') . ';',
		'embed'		=> 1,
		'incognito'	=> 0,
		'nocache'	=> 0,
		'nocache_old'	=> 1,
		'tz'		=> get_setting('defaulttz'),
		'eninbox'	=> 0,
		'sortupdown'	=> get_setting('sortupdown'),
		'hidechatters'	=> get_setting('hidechatters'),

		//MODIFICATION clickable nicknames
		/* REMOVE LATER
		'clickablenicknames'	=>0,
		*/
	];
	/*REMOVE LATER
    $stmt=$db->prepare('INSERT INTO ' . PREFIX . 'members (nickname, passhash, status, refresh, bgcolour, regedby, timestamps, style, embed, incognito, nocache, tz, eninbox, sortupdown, hidechatters, clickablenicknames, nocache_old) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);');
	*/
	$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'members (nickname, passhash, status, refresh, bgcolour, regedby, timestamps, style, embed, incognito, nocache, tz, eninbox, sortupdown, hidechatters, nocache_old) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);');
	$stmt->execute([$reg['nickname'], $reg['passhash'], $reg['status'], $reg['refresh'], $reg['bgcolour'], $reg['regedby'], $reg['timestamps'], $reg['style'], $reg['embed'], $reg['incognito'], $reg['nocache'], $reg['tz'], $reg['eninbox'], $reg['sortupdown'], $reg['hidechatters'], $reg['nocache_old']]);
	return sprintf($I['successreg'], htmlspecialchars($reg['nickname']));
}

function change_status($nick, $status)
{
	global $I, $U, $db;
	if (empty($nick)) {
		return '';
	} elseif (!preg_match('/^[023567\-]$/', $status)) {
		return sprintf($I['cantchgstat'], htmlspecialchars($nick));
	}
	
	// Get target user's current status
	$stmt = $db->prepare('SELECT status, incognito, style FROM ' . PREFIX . 'members WHERE nickname=?;');
	$stmt->execute([$nick]);
	if (!$old = $stmt->fetch(PDO::FETCH_NUM)) {
		return sprintf($I['cantchgstat'], htmlspecialchars($nick));
	}
	$target_status = $old[0];
	
	// Use can_promote helper for permission checks
	if ($status === '-') {
		// Check if user can demote target to status 0 (deletion path)
		if (!can_promote($U['status'], $target_status, 0)) {
			return sprintf($I['cantchgstat'], htmlspecialchars($nick));
		}
	} else {
		// Check if user can promote target to new status
		if (!can_promote($U['status'], $target_status, (int)$status)) {
			return sprintf($I['cantchgstat'], htmlspecialchars($nick));
		}
	}
	
	if ($_REQUEST['set'] === '-') {
		$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'members WHERE nickname=?;');
		$stmt->execute([$nick]);
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET status=1, incognito=0 WHERE nickname=?;');
		$stmt->execute([$nick]);
		log_audit($U['nickname'], $U['status'], 'member_deleted', $nick, 1, "Member deleted from database (status changed from $target_status to guest)");
		return sprintf($I['succdel'], style_this(htmlspecialchars($nick), $old[2]));
	} else {
		if ($status < 5) {
			$old[1] = 0;
		}
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'members SET status=?, incognito=? WHERE nickname=?;');
		$stmt->execute([$status, $old[1], $nick]);
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET status=?, incognito=? WHERE nickname=?;');
		$stmt->execute([$status, $old[1], $nick]);
		log_audit($U['nickname'], $U['status'], 'status_change', $nick, (int)$status, "Changed from status $target_status to $status");
		return sprintf($I['succchg'], style_this(htmlspecialchars($nick), $old[2]));
	}
}

function passreset($nick, $pass)
{
	global $I, $U, $db;
	if (empty($nick)) {
		return '';
	}
	// Supermods can reset passwords for status 5 and below
	$maxStatus = ($U['status'] == 6) ? 5 : $U['status'] - 1;
	$stmt = $db->prepare('SELECT null FROM ' . PREFIX . 'members WHERE nickname=? AND status<=?;');
	$stmt->execute([$nick, $maxStatus]);
	if ($stmt->fetch(PDO::FETCH_ASSOC)) {
		$passhash = password_hash($pass, PASSWORD_DEFAULT);
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'members SET passhash=? WHERE nickname=?;');
		$stmt->execute([$passhash, $nick]);
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET passhash=? WHERE nickname=?;');
		$stmt->execute([$passhash, $nick]);
		return sprintf($I['succpassreset'], htmlspecialchars($nick));
	} else {
		return sprintf($I['cantresetpass'], htmlspecialchars($nick));
	}
}

function amend_profile()
{
	global $U;
	if (isset($_REQUEST['refresh'])) {
		$U['refresh'] = $_REQUEST['refresh'];
	}
	if ($U['refresh'] < 5) {
		$U['refresh'] = 5;
	} elseif ($U['refresh'] > 150) {
		$U['refresh'] = 150;
	}
	if (preg_match('/^#([a-f0-9]{6})$/i', $_REQUEST['colour'], $match)) {
		$colour = $match[1];
	} else {
		preg_match('/#([0-9a-f]{6})/i', $U['style'], $matches);
		$colour = $matches[1];
	}
	if (preg_match('/^#([a-f0-9]{6})$/i', $_REQUEST['bgcolour'], $match)) {
		$U['bgcolour'] = $match[1];
	}
	$U['style'] = "color:#$colour;";
	if ($U['status'] >= 3) {
		$F = load_fonts();
		if (isset($F[$_REQUEST['font']])) {
			$U['style'] .= $F[$_REQUEST['font']];
		}
		if (isset($_REQUEST['small'])) {
			$U['style'] .= 'font-size:smaller;';
		}
		if (isset($_REQUEST['italic'])) {
			$U['style'] .= 'font-style:italic;';
		}
		if (isset($_REQUEST['bold'])) {
			$U['style'] .= 'font-weight:bold;';
		}
	}
	if ($U['status'] >= 5 && isset($_REQUEST['incognito']) && get_setting('incognito')) {
		$U['incognito'] = 1;
	} else {
		$U['incognito'] = 0;
	}
	if (isset($_REQUEST['tz'])) {
		$tzs = timezone_identifiers_list();
		if (in_array($_REQUEST['tz'], $tzs)) {
			$U['tz'] = $_REQUEST['tz'];
		}
	}

	//MODIFICATION for clicable nicknames setting
	/* REMOVE LATER
	$clickablelinks_allowedvalues = array(0, 1, 2);
	if(isset($_REQUEST['clickablenicknames']) && in_array($_REQUEST['clickablenicknames'], $clickablelinks_allowedvalues)){
			$U['clickablenicknames'] = (int) $_REQUEST['clickablenicknames'];
    }
	*/

	if (isset($_REQUEST['eninbox']) && $_REQUEST['eninbox'] >= 0 && $_REQUEST['eninbox'] <= 5) {
		$U['eninbox'] = $_REQUEST['eninbox'];
	}
	$bool_settings = ['timestamps', 'embed', 'nocache', 'sortupdown', 'hidechatters'];
	foreach ($bool_settings as $setting) {
		if (isset($_REQUEST[$setting])) {
			$U[$setting] = 1;
		} else {
			$U[$setting] = 0;
		}
	}
}

function save_profile()
{
	global $I, $U, $db;
	amend_profile();
	//MODIFICATION for clickable nicknames setting
	/* REMOVE LATER
	$stmt=$db->prepare('UPDATE ' . PREFIX . 'sessions SET refresh=?, style=?, bgcolour=?, timestamps=?, embed=?, incognito=?, nocache=?, tz=?, eninbox=?, sortupdown=?, hidechatters=?, clickablenicknames=? WHERE session=?;');
	*/
	$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET refresh=?, style=?, bgcolour=?, timestamps=?, embed=?, incognito=?, nocache=?, tz=?, eninbox=?, sortupdown=?, hidechatters=? WHERE session=?;');

	//MODIFICATION for clickable nicknames (clickablenicknames)
	/* REMOVE LATER
	$stmt->execute([$U['refresh'], $U['style'], $U['bgcolour'], $U['timestamps'], $U['embed'], $U['incognito'], $U['nocache'], $U['tz'], $U['eninbox'], $U['sortupdown'], $U['hidechatters'], $U['clickablenicknames'], $U['session']]);
	*/
	$stmt->execute([$U['refresh'], $U['style'], $U['bgcolour'], $U['timestamps'], $U['embed'], $U['incognito'], $U['nocache'], $U['tz'], $U['eninbox'], $U['sortupdown'], $U['hidechatters'], $U['session']]);

	if ($U['status'] >= 2) {
		/* REMOVE LATER
		$stmt=$db->prepare('UPDATE ' . PREFIX . 'members SET refresh=?, bgcolour=?, timestamps=?, embed=?, incognito=?, style=?, nocache=?, tz=?, eninbox=?, sortupdown=?, hidechatters=?, clickablenicknames=? WHERE nickname=?;');
		$stmt->execute([$U['refresh'], $U['bgcolour'], $U['timestamps'], $U['embed'], $U['incognito'], $U['style'], $U['nocache'], $U['tz'], $U['eninbox'], $U['sortupdown'], $U['hidechatters'], $U['clickablenicknames'], $U['nickname']]);
    */
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'members SET refresh=?, bgcolour=?, timestamps=?, embed=?, incognito=?, style=?, nocache=?, tz=?, eninbox=?, sortupdown=?, hidechatters=? WHERE nickname=?;');
		$stmt->execute([$U['refresh'], $U['bgcolour'], $U['timestamps'], $U['embed'], $U['incognito'], $U['style'], $U['nocache'], $U['tz'], $U['eninbox'], $U['sortupdown'], $U['hidechatters'], $U['nickname']]);
	}
	if (!empty($_REQUEST['unignore'])) {
		$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'ignored WHERE ign=? AND ignby=?;');
		$stmt->execute([$_REQUEST['unignore'], $U['nickname']]);
	}
	if (!empty($_REQUEST['ignore'])) {
		$stmt = $db->prepare('SELECT null FROM ' . PREFIX . 'messages WHERE poster=? AND poster NOT IN (SELECT ign FROM ' . PREFIX . 'ignored WHERE ignby=?);');
		$stmt->execute([$_REQUEST['ignore'], $U['nickname']]);
		if ($U['nickname'] !== $_REQUEST['ignore'] && $stmt->fetch(PDO::FETCH_NUM)) {
			$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'ignored (ign, ignby) VALUES (?, ?);');
			$stmt->execute([$_REQUEST['ignore'], $U['nickname']]);
		}
	}
	if ($U['status'] > 1 && !empty($_REQUEST['newpass'])) {
		if (!valid_pass($_REQUEST['newpass'])) {
			return sprintf($I['invalpass'], get_setting('minpass'), get_setting('passregex'));
		}
		if (!isset($_REQUEST['oldpass'])) {
			$_REQUEST['oldpass'] = '';
		}
		if (!isset($_REQUEST['confirmpass'])) {
			$_REQUEST['confirmpass'] = '';
		}
		if ($_REQUEST['newpass'] !== $_REQUEST['confirmpass']) {
			return $I['noconfirm'];
		} else {
			$U['newhash'] = password_hash($_REQUEST['newpass'], PASSWORD_DEFAULT);
		}
		if (!password_verify($_REQUEST['oldpass'], $U['passhash'])) {
			return $I['wrongpass'];
		}
		$U['passhash'] = $U['newhash'];
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET passhash=? WHERE session=?;');
		$stmt->execute([$U['passhash'], $U['session']]);
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'members SET passhash=? WHERE nickname=?;');
		$stmt->execute([$U['passhash'], $U['nickname']]);
	}
	if ($U['status'] > 1 && !empty($_REQUEST['newnickname'])) {
		$msg = set_new_nickname();
		if ($msg !== '') {
			return $msg;
		}
	}
	return $I['succprofile'];
}

function set_new_nickname()
{
	global $I, $U, $db;
	$_REQUEST['newnickname'] = preg_replace('/\s/', '', $_REQUEST['newnickname']);
	if (!valid_nick($_REQUEST['newnickname'])) {
		return sprintf($I['invalnick'], get_setting('maxname'), get_setting('nickregex'));
	}
	$stmt = $db->prepare('SELECT id FROM ' . PREFIX . 'sessions WHERE nickname=? UNION SELECT id FROM ' . PREFIX . 'members WHERE nickname=?;');
	$stmt->execute([$_REQUEST['newnickname'], $_REQUEST['newnickname']]);
	if ($stmt->fetch(PDO::FETCH_NUM)) {
		return $I['nicknametaken'];
	} else {
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'members SET nickname=? WHERE nickname=?;');
		$stmt->execute([$_REQUEST['newnickname'], $U['nickname']]);
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET nickname=? WHERE nickname=?;');
		$stmt->execute([$_REQUEST['newnickname'], $U['nickname']]);
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'messages SET poster=? WHERE poster=?;');
		$stmt->execute([$_REQUEST['newnickname'], $U['nickname']]);
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'messages SET recipient=? WHERE recipient=?;');
		$stmt->execute([$_REQUEST['newnickname'], $U['nickname']]);
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'ignored SET ignby=? WHERE ignby=?;');
		$stmt->execute([$_REQUEST['newnickname'], $U['nickname']]);
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'ignored SET ign=? WHERE ign=?;');
		$stmt->execute([$_REQUEST['newnickname'], $U['nickname']]);
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'inbox SET poster=? WHERE poster=?;');
		$stmt->execute([$_REQUEST['newnickname'], $U['nickname']]);
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'notes SET editedby=? WHERE editedby=?;');
		$stmt->execute([$_REQUEST['newnickname'], $U['nickname']]);
		$U['nickname'] = $_REQUEST['newnickname'];
	}
	return '';
}

//sets default settings for guests
function add_user_defaults($password)
{
	global $U;
	$U['refresh'] = get_setting('defaultrefresh');
	$U['bgcolour'] = get_setting('colbg');
	if (!isset($_REQUEST['colour']) || !preg_match('/^[a-f0-9]{6}$/i', $_REQUEST['colour']) || abs(greyval($_REQUEST['colour']) - greyval(get_setting('colbg'))) < 75) {
		do {
			$colour = sprintf('%06X', mt_rand(0, 16581375));
		} while (abs(greyval($colour) - greyval(get_setting('colbg'))) < 75);
	} else {
		$colour = $_REQUEST['colour'];
	}
	$U['style'] = "color:#$colour;";
	$U['timestamps'] = get_setting('timestamps');
	$U['embed'] = 1;
	$U['incognito'] = 0;
	$U['status'] = 1;
	$U['nocache'] = get_setting('sortupdown');
	if ($U['nocache']) {
		$U['nocache_old'] = 0;
	} else {
		$U['nocache_old'] = 1;
	}
	$U['tz'] = get_setting('defaulttz');
	$U['eninbox'] = 1;
	$U['sortupdown'] = get_setting('sortupdown');
	$U['hidechatters'] = get_setting('hidechatters');
	$U['passhash'] = password_hash($password, PASSWORD_DEFAULT);
	$U['entry'] = $U['lastpost'] = time();

	//MODIFICATION for clickable nicknames
	/* REMOVE LATER
	$U['clickablenicknames']=0;
	*/
}

// message handling

function validate_input()
{
	//global $U, $db;
	global $U, $db, $language;

	$inbox = false;
	$maxmessage = get_setting('maxmessage');
	$message = mb_substr($_REQUEST['message'], 0, $maxmessage);
	$rejected = mb_substr($_REQUEST['message'], $maxmessage);
	
	// Check if user is muted (but allow PMs to moderators)
	$sending_to_mod = false;
	if (!empty($_REQUEST['sendto'])) {
		// Check if recipient is a moderator
		$stmt = $db->prepare('SELECT status FROM ' . PREFIX . 'sessions WHERE nickname=?;');
		$stmt->execute([$_REQUEST['sendto']]);
		$recipient_data = $stmt->fetch(PDO::FETCH_ASSOC);
		if ($recipient_data && $recipient_data['status'] >= 5) {
			$sending_to_mod = true;
		}
	}
	
	if (!$sending_to_mod && is_user_muted($U['nickname'])) {
		$muted_until = is_user_muted($U['nickname']);
		$remaining = ceil(($muted_until - time()) / 60);
		send_post("You are muted for $remaining more minutes. You can still PM moderators for assistance.");
		return;
	}
	
	// Handle /help command - show only to user as PM from Dot bot
	if (preg_match('~^(/help)\s*$~iu', $message)) {
		$helpText = generate_help_text($U['status']);
		send_bot_pm($U['nickname'], "<strong>Chat Help:</strong><br>" . $helpText);
		return;
	}
	
	// Handle custom bot commands (. prefix)
	if (preg_match('/^\.([a-zA-Z0-9_]+)(?:\s+(.*))?$/i', $message, $matches)) {
		$command = strtolower($matches[1]);
		$bot_commands = get_botcommands();
		foreach ($bot_commands as $cmd) {
			if (strtolower($cmd['command']) === $command) {
				// Check minimum status requirement
				if ($U['status'] >= $cmd['min_status']) {
					send_bot_pm($U['nickname'], $cmd['response']);
				} else {
					send_bot_pm($U['nickname'], "⚠️ You don't have permission to use this command.");
				}
				return; // Don't post the message
			}
		}
		// Command not found - let it fall through as normal message
	}
	
	if ($U['postid'] === $_REQUEST['postid']) { // ignore double post=reload from browser or proxy
		$message = '';
	} elseif ((time() - $U['lastpost']) <= 1) { // time between posts too short, reject!
		$rejected = $_REQUEST['message'];
		$message = '';
	}
	if (!empty($rejected)) {
		$rejected = trim($rejected);
		$rejected = htmlspecialchars($rejected);
	}
	$message = htmlspecialchars($message);
	$message = preg_replace("/(\r?\n|\r\n?)/u", '<br>', $message);
	if (isset($_REQUEST['multi'])) {
		$message = preg_replace('/\s*<br>/u', '<br>', $message);
		$message = preg_replace('/<br>(<br>)+/u', '<br><br>', $message);
		$message = preg_replace('/<br><br>\s*$/u', '<br>', $message);
		$message = preg_replace('/^<br>\s*$/u', '', $message);
	} else {
		$message = str_replace('<br>', ' ', $message);
	}
	$message = trim($message);
	$message = preg_replace('/\s+/u', ' ', $message);
	$recipient = '';

	//This ist the the place where the username is added to $displaysend (and later to the message).

	/*
		'r @'
        's 17'
        's 24'
        's 31'
        's 48'
        's 56'
        's 65'
	*/

	// This Room - default (poststatus 1, visible in current room only)
	if (!isset($_REQUEST['sendto']) || $_REQUEST['sendto'] === 'room' || $_REQUEST['sendto'] === '') {
		$poststatus = 1;
		$displaysend = style_this_clickable(htmlspecialchars($U['nickname']), $U['style']) . ' - ';
		$roomid = $U['roomid']; // Message stays in current room
		$allrooms = 0;
		
	// Members channel [M] - status 3+ (broadcasts to all rooms)
	} elseif ($_REQUEST['sendto'] === 's 31' && $U['status'] >= 3) {
		$poststatus = 3;
		$displaysend = '[M] ' . style_this_clickable(htmlspecialchars($U['nickname']), $U['style']) . ' - ';
		$roomid = null; // Visible in all rooms
		$allrooms = 1;
		
	// Staff channel [Staff] - status 5+ (broadcasts to all rooms)
	} elseif ($_REQUEST['sendto'] === 's 48' && $U['status'] >= 5) {
		$poststatus = 5;
		$displaysend = '[Staff] ' . style_this_clickable(htmlspecialchars($U['nickname']), $U['style']) . ' - ';
		$roomid = null;
		$allrooms = 1;
		
	// Admin channel [Admin] - status 6+ (broadcasts to all rooms)
	} elseif ($_REQUEST['sendto'] === 's 56' && $U['status'] >= 6) {
		$poststatus = 6;
		$displaysend = '[Admin] ' . style_this_clickable(htmlspecialchars($U['nickname']), $U['style']) . ' - ';
		$roomid = null;
		$allrooms = 1;
		
	// All (broadcast to everyone in all rooms) - status 5+
	} elseif ($_REQUEST['sendto'] === 's 17' && $U['status'] >= 5) {
		$poststatus = 1; // Everyone can see (poststatus 1)
		$displaysend = style_this_clickable(htmlspecialchars($U['nickname']), $U['style']) . ' - ';
		$roomid = null;
		$allrooms = 1; // Broadcasts to all rooms
		log_audit($U['nickname'], $U['status'], 'message_sent', null, null, 'All (Broadcast)');
		
	// System Message (backward compatibility) - status 5+
	} elseif ($_REQUEST['sendto'] === 's 50' && $U['status'] >= 5) {
		$poststatus = 1;
		$displaysend = ''; // No prefix for system messages
		$roomid = null;
		$allrooms = 1;
		log_audit($U['nickname'], $U['status'], 'message_sent', null, null, 'System Message');
	} else { // known nick in room?
		if (get_setting('disablepm')) {
			//PMs disabled
			return;
		}
		
	// Handle PMs to Dot bot - process as commands without prefix
	if ($_REQUEST['sendto'] === 'Dot') {
		try {
			$message = trim($message);
			$response = process_dot_command($message, $U['nickname'], $U['status']);
			if ($response) {
				send_bot_pm($U['nickname'], $response);
			} else {
				send_bot_pm($U['nickname'], "⚠️ No response generated for command: " . htmlspecialchars($message));
			}
		} catch (PDOException $e) {
			// Database errors
			$errorMsg = "⚠️ Database Error: " . $e->getMessage();
			send_bot_pm($U['nickname'], $errorMsg);
			error_log($errorMsg);
		} catch (Exception $e) {
			// If there's an error, send an error message to the user with details
			$errorMsg = "⚠️ Error: " . $e->getMessage() . " in " . $e->getFile() . " on line " . $e->getLine();
			send_bot_pm($U['nickname'], $errorMsg);
			error_log($errorMsg);
		}
		return; // Don't actually send the PM to "Dot"
	}		$stmt = $db->prepare('SELECT null FROM ' . PREFIX . 'ignored WHERE (ignby=? AND ign=?) OR (ign=? AND ignby=?);');
		$stmt->execute([$_REQUEST['sendto'], $U['nickname'], $_REQUEST['sendto'], $U['nickname']]);
		if ($stmt->fetch(PDO::FETCH_NUM)) {
			//ignored
			return;
		}
		$tmp = false;
		$stmt = $db->prepare('SELECT s.style, 0 AS inbox FROM ' . PREFIX . 'sessions AS s LEFT JOIN ' . PREFIX . 'members AS m ON (m.nickname=s.nickname) WHERE s.nickname=? AND (s.incognito=0 OR (m.eninbox!=0 AND m.eninbox<=?));');
		$stmt->execute([$_REQUEST['sendto'], $U['status']]);
		if (!$tmp = $stmt->fetch(PDO::FETCH_ASSOC)) {
			$stmt = $db->prepare('SELECT style, 1 AS inbox FROM ' . PREFIX . 'members WHERE nickname=? AND eninbox!=0 AND eninbox<=?;');
			$stmt->execute([$_REQUEST['sendto'], $U['status']]);
			if (!$tmp = $stmt->fetch(PDO::FETCH_ASSOC)) {
				//nickname left or disabled offline inbox for us
				return;
			}
		}
		$recipient = $_REQUEST['sendto'];
		$poststatus = 9;

		$displaysend = sprintf(get_setting('msgsendprv'), style_this_clickable(htmlspecialchars($U['nickname']), $U['style']), style_this_clickable(htmlspecialchars($recipient), $tmp['style']));
		$inbox = $tmp['inbox'];
	}
	if ($poststatus !== 9 && preg_match('~^/me~iu', $message)) {
		$displaysend = style_this(htmlspecialchars("$U[nickname] "), $U['style']);
		$message = preg_replace("~^/me\s?~iu", '', $message);
	}
	
	// Process /whisper command (shows text in gray/muted style)
	if ($poststatus !== 9 && preg_match('~^/whisper~iu', $message)) {
		$message = preg_replace("~^/whisper\s?~iu", '', $message);
		$message = '<em style="color:#888;font-style:italic;">' . $message . '</em>';
	}
	
	// Process chat commands (excluding /help which are handled earlier)
	$message = process_chat_commands($message, $U['nickname'], $U['status'], $poststatus);
	
	// If command was handled (returns empty), don't post message
	// UNLESS a file is being uploaded (allow empty message with file attachment)
	if ($message === '' && (!isset($_FILES['file']) || $_FILES['file']['error'] === UPLOAD_ERR_NO_FILE)) {
		return '';
	}
	
	try {
		$message = apply_filter($message, $poststatus, $U['nickname']);
	} catch (Exception $e) {
		if (strpos($e->getMessage(), 'WARN_FILTER:') === 0) {
			// Warning filter triggered - extract original message and return to postbox
			$original_message = substr($e->getMessage(), strlen('WARN_FILTER:'));
			return $original_message;
		}
		// Re-throw if it's not a warn filter exception
		throw $e;
	}
	$message = create_hotlinks($message);
	$message = apply_linkfilter($message);
	
	// Handle file upload with detailed step-by-step logging
	$hash = null;
	$upload_log = [];
	
	if (isset($_FILES['file'])) {
		$upload_log[] = 'Step 1: File input detected';
		$upload_log[] = 'File error code: ' . $_FILES['file']['error'];
		$upload_log[] = 'File size: ' . $_FILES['file']['size'] . ' bytes';
		$upload_log[] = 'File name: ' . $_FILES['file']['name'];
		$upload_log[] = 'File type: ' . $_FILES['file']['type'];
		$upload_log[] = 'Temp file: ' . $_FILES['file']['tmp_name'];
		
		if ($_FILES['file']['error'] !== UPLOAD_ERR_NO_FILE) {
			$upload_log[] = 'Step 2: File was uploaded (not empty selection)';
			
			$upload_enabled = get_setting('enfileupload');
			$max_size_kb = get_setting('maxuploadsize');
			$upload_log[] = 'Step 3: Upload enabled for rank: ' . $upload_enabled;
			$upload_log[] = 'User rank: ' . $U['status'];
			$upload_log[] = 'Max size: ' . $max_size_kb . ' KB';
			
			// Check if user has permission
			if ($upload_enabled > 0 && $upload_enabled <= $U['status']) {
				$upload_log[] = 'Step 4: Permission check PASSED';
				
				if ($_FILES['file']['error'] === UPLOAD_ERR_OK) {
					$upload_log[] = 'Step 5: PHP upload error check PASSED';
					
					$file_size_kb = $_FILES['file']['size'] / 1024;
					$max_size_bytes = 1024 * $max_size_kb;
					
					$upload_log[] = 'File size: ' . number_format($file_size_kb, 2) . ' KB';
					$upload_log[] = 'Max allowed: ' . number_format($max_size_kb, 2) . ' KB';
					
					if ($_FILES['file']['size'] > 0 && $_FILES['file']['size'] <= $max_size_bytes) {
						$upload_log[] = 'Step 6: Size validation PASSED';
						
						try {
							if (file_exists($_FILES['file']['tmp_name'])) {
								$upload_log[] = 'Step 7: Temp file exists';
								$hash = sha1_file($_FILES['file']['tmp_name']);
								$upload_log[] = 'Step 8: Hash generated: ' . $hash;
								
								$name = htmlspecialchars($_FILES['file']['name']);
								$message = sprintf(get_setting('msgattache'), "<a class=\"attachement\" href=\"?action=download&amp;id=$hash\" target=\"_blank\">$name</a>", $message);
								$upload_log[] = 'Step 9: SUCCESS - File will be saved';
							} else {
								$upload_log[] = 'Step 7 ERROR: Temp file does not exist!';
								$message = '<span style="color:#ff6666;">⚠ Upload failed: Temp file missing</span> ' . $message;
							}
						} catch (Exception $e) {
							$upload_log[] = 'Step 7 EXCEPTION: ' . $e->getMessage();
							$message = '<span style="color:#ff6666;">⚠ Upload failed: ' . $e->getMessage() . '</span> ' . $message;
						}
					} else {
						// File size validation failed
						if ($_FILES['file']['size'] == 0) {
							$upload_log[] = 'Step 6 FAILED: File is empty';
							$message = '<span style="color:#ff6666;">⚠ Upload failed: File is empty</span> ' . $message;
						} else {
							$upload_log[] = 'Step 6 FAILED: File too large';
							$message = '<span style="color:#ff6666;">⚠ Upload failed: File too large (' . number_format($file_size_kb, 0) . ' KB / max ' . number_format($max_size_kb) . ' KB)</span> ' . $message;
						}
					}
				} else {
					// PHP upload error
					$upload_log[] = 'Step 5 FAILED: PHP upload error';
					$error_msgs = [
						UPLOAD_ERR_INI_SIZE => 'exceeds php.ini limit',
						UPLOAD_ERR_FORM_SIZE => 'exceeds form limit',
						UPLOAD_ERR_PARTIAL => 'only partially uploaded',
						UPLOAD_ERR_NO_TMP_DIR => 'missing temp directory',
						UPLOAD_ERR_CANT_WRITE => 'failed to write to disk',
						UPLOAD_ERR_EXTENSION => 'blocked by PHP extension'
					];
					$error_msg = $error_msgs[$_FILES['file']['error']] ?? 'unknown error (code ' . $_FILES['file']['error'] . ')';
					$upload_log[] = 'Error: ' . $error_msg;
					$message = '<span style="color:#ff6666;">⚠ Upload failed: ' . $error_msg . '</span> ' . $message;
				}
			} else {
				// User doesn't have permission
				$upload_log[] = 'Step 4 FAILED: Permission denied';
				$message = '<span style="color:#ff6666;">⚠ Upload failed: Insufficient permissions (requires rank ' . $upload_enabled . '+)</span> ' . $message;
			}
		} else {
			$upload_log[] = 'Step 2: No file selected (UPLOAD_ERR_NO_FILE)';
		}
		
		// Log to file for debugging
		if (count($upload_log) > 1) {
			error_log('[UPLOAD DEBUG ' . date('Y-m-d H:i:s') . '] User: ' . $U['nickname'] . "\n" . implode("\n", $upload_log) . "\n");
		}
	}
	if (add_message($message, $recipient, $U['nickname'], $U['status'], $poststatus, $displaysend, $U['style'])) {
		$U['lastpost'] = time();
		
		// Remove AFK status when user sends a message
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET lastpost=?, postid=?, afk=0, afk_message=NULL WHERE session=?;');
		$stmt->execute([$U['lastpost'], $_REQUEST['postid'], $U['session']]);
		
		$stmt = $db->prepare('SELECT id FROM ' . PREFIX . 'messages WHERE poster=? ORDER BY id DESC LIMIT 1;');
		$stmt->execute([$U['nickname']]);
		$id = $stmt->fetch(PDO::FETCH_NUM);
		if ($inbox && $id) {
			$newmessage = [
				'postdate'	=> time(),
				'poster'	=> $U['nickname'],
				'recipient'	=> $recipient,

				'text'		=> "<span class=\"usermsg\">$displaysend" . style_this($message, $U['style']) . '</span>'
			];
			if (MSGENCRYPTED) {
				$newmessage['text'] = base64_encode(sodium_crypto_aead_aes256gcm_encrypt($newmessage['text'], '', AES_IV, ENCRYPTKEY));
			}
			$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'inbox (postdate, postid, poster, recipient, text) VALUES(?, ?, ?, ?, ?)');
			$stmt->execute([$newmessage['postdate'], $id[0], $newmessage['poster'], $newmessage['recipient'], $newmessage['text']]);
		}
		if (isset($hash) && $id) {
			error_log('[UPLOAD DEBUG] Step 10: Saving to database - postid: ' . $id[0] . ', hash: ' . $hash);
			
			try {
				if (!empty($_FILES['file']['type']) && preg_match('~^[a-z0-9/\-\.\+]*$~i', $_FILES['file']['type'])) {
					$type = $_FILES['file']['type'];
				} else {
					$type = 'application/octet-stream';
				}
				error_log('[UPLOAD DEBUG] Step 11: File type: ' . $type);
				
				// Read file data and clean up temp file
				if (file_exists($_FILES['file']['tmp_name'])) {
					$file_data = file_get_contents($_FILES['file']['tmp_name']);
					error_log('[UPLOAD DEBUG] Step 12: Read ' . strlen($file_data) . ' bytes from temp file');
					
					$temp_file = $_FILES['file']['tmp_name'];
					
					if ($file_data !== false) {
						$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'files (postid, hash, filename, type, data) VALUES (?, ?, ?, ?, ?);');
						$stmt->execute([$id[0], $hash, str_replace('"', '\"', $_FILES['file']['name']), $type, base64_encode($file_data)]);
						error_log('[UPLOAD DEBUG] Step 13: SUCCESS - Saved to database');
					} else {
						error_log('[UPLOAD DEBUG] Step 12 ERROR: Could not read file data');
					}
					
					// Clean up temp file
					if (file_exists($temp_file)) {
						unlink($temp_file);
						error_log('[UPLOAD DEBUG] Step 14: Cleaned up temp file');
					}
				} else {
					error_log('[UPLOAD DEBUG] Step 12 ERROR: Temp file no longer exists!');
				}
			} catch (Exception $e) {
				error_log('[UPLOAD DEBUG] EXCEPTION during database save: ' . $e->getMessage());
			}
		} elseif (isset($_FILES['file']) && $_FILES['file']['error'] !== UPLOAD_ERR_NO_FILE && file_exists($_FILES['file']['tmp_name'])) {
			// Clean up temp file if upload failed but file exists
			error_log('[UPLOAD DEBUG] Cleaning up failed upload temp file');
			unlink($_FILES['file']['tmp_name']);
		}
	}
	return $rejected;
}

function apply_filter($message, $poststatus, $nickname)
{
	global $I, $U;
	
	// Check auto-moderation rules first
	$automod_result = check_automod_rules($nickname, $message, $U['status']);
	if ($automod_result) {
		$action_result = apply_automod_action($nickname, $automod_result['rule'], $automod_result['reason']);
		// If action is 'delete', block the message
		if ($automod_result['rule']['action'] === 'delete') {
			setcookie(COOKIENAME, false);
			$_REQUEST['session'] = '';
			send_error("Message blocked by auto-moderation: " . $automod_result['reason']);
		}
	}
	
	$message = str_replace('<br>', "\n", $message);
	$message = apply_mention($message);
	$filters = get_filters();
	foreach ($filters as $filter) {
		// Skip staff-only filters if user is not staff (5+)
		if (!empty($filter['staff_only']) && $U['status'] < 5) {
			continue;
		}
		
		if ($poststatus !== 9 || !$filter['allowinpm']) {
			if ($filter['cs']) {
				$message = preg_replace("/$filter[match]/u", $filter['replace'], $message, -1, $count);
			} else {
				$message = preg_replace("/$filter[match]/iu", $filter['replace'], $message, -1, $count);
			}
		}
		// Handle bot_reply - send automated PM from Dot bot
		if (isset($count) && $count > 0 && $filter['bot_reply']) {
			send_bot_pm($nickname, $filter['replace']);
		}
		// Handle kick filter
		if (isset($count) && $count > 0 && $filter['kick'] && ($U['status'] < 5 || get_setting('filtermodkick'))) {
			kick_chatter([$nickname], "[Filter #$filter[id]]: $filter[replace]", false);
			setcookie(COOKIENAME, false);
			$_REQUEST['session'] = '';
			send_error("$I[kicked]<br>$filter[replace]");
		}
		// Handle warn filter
		if (isset($count) && $count > 0 && !empty($filter['warn']) && $U['status'] < 5) {
			// Add warning with severity 1 and 10 day expiration
			add_user_warning($nickname, "Triggered filter #$filter[id]: " . substr($filter['match'], 0, 50), true, 'System', 1, 10);
			// Send warning PM from Dot with filter reason
			send_bot_pm($nickname, "⚠️ Warning: Your message triggered a content filter.<br><strong>Reason:</strong> $filter[replace]<br><br>Please review the chat rules.");
			// Throw exception to reject message and return to postbox
			throw new Exception('WARN_FILTER:' . $message);
		}
	}
	$message = str_replace("\n", '<br>', $message);
	return $message;
}

function apply_linkfilter($message)
{
	$filters = get_linkfilters();
	foreach ($filters as $filter) {
		$message = preg_replace_callback(
			"/<a href=\"([^\"]+)\" target=\"_blank\"( rel=\"noreferrer noopener\")?>(.*?(?=<\/a>))<\/a>/iu",
			function ($matched) use (&$filter) {
				return "<a href=\"$matched[1]\" target=\"_blank\"$matched[2]>" . preg_replace("/$filter[match]/iu", $filter['replace'], $matched[3]) . '</a>';
			},
			$message
		);
	}
	$redirect = get_setting('redirect');
	if (get_setting('imgembed')) {
		$message = preg_replace_callback(
			'/\[img\]\s?<a href="([^"]+)" target="_blank"( rel=\"noreferrer noopener\")?>(.*?(?=<\/a>))<\/a>/iu',
			function ($matched) {
				return str_ireplace('[/img]', '', "<br><a href=\"$matched[1]\" target=\"_blank\"$matched[2]><img src=\"$matched[1]\"></a><br>");
			},
			$message
		);
	}
	if (empty($redirect)) {
		$redirect = "?action=redirect&amp;url=";
	}
	if (get_setting('forceredirect')) {
		$message = preg_replace_callback(
			'/<a href="([^"]+)" target="_blank"( rel=\"noreferrer noopener\")?>(.*?(?=<\/a>))<\/a>/u',
			function ($matched) use ($redirect) {
				return "<a href=\"$redirect" . rawurlencode($matched[1]) . "\" target=\"_blank\"$matched[2]>$matched[3]</a>";
			},
			$message
		);
	} elseif (preg_match_all('/<a href="([^"]+)" target="_blank"( rel=\"noreferrer noopener\")?>(.*?(?=<\/a>))<\/a>/u', $message, $matches)) {
		foreach ($matches[1] as $match) {
			if (!preg_match('~^http(s)?://~u', $match)) {
				$message = preg_replace_callback(
					'/<a href="(' . preg_quote($match, '/') . ')\" target=\"_blank\"( rel=\"noreferrer noopener\")?>(.*?(?=<\/a>))<\/a>/u',
					function ($matched) use ($redirect) {
						return "<a href=\"$redirect" . rawurlencode($matched[1]) . "\" target=\"_blank\"$matched[2]>$matched[3]</a>";
					},
					$message
				);
			}
		}
	}
	return $message;
}

/**
 * Process chat commands and handle special actions
 * 
 * Supported commands:
 * /help - Shows help information for the chat
 * /afk - Marks user as away from keyboard (adds [AFK] to name in chatters list)
 * /locate username - Shows what room a user is currently in
 * /shrug - Adds ¯\_(ツ)_/¯ to the end of the message
 * /flip - Adds (╯°□°)╯︵ ┻━┻ to the end of the message
 * /unflip - Adds (ヘ･_･)ヘ┳━┳ to the end of the message
 * 
 * @param string $message The original message
 * @param string $nickname The user's nickname
 * @param int $status The user's status level
 * @param int $poststatus The post status (1=all, 3=members, 5=mods, etc.)
 * @return string The processed message
 */
function process_chat_commands($message, $nickname, $status, $poststatus)
{
	global $db, $I, $U;
	
	// Handle /afk command
	if (preg_match('~^/afk\s*(.*)$~iu', $message, $matches)) {
		// Set AFK status in database
		$afkMessage = trim($matches[1]);
		if (empty($afkMessage)) {
			$afkMessage = "Away from keyboard";
		}
		
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET afk=1, afk_message=? WHERE nickname=?;');
		$stmt->execute([$afkMessage, $nickname]);
		
		// Update global $U if this is the current user
		if ($U['nickname'] === $nickname) {
			$U['afk'] = 1;
			$U['afk_message'] = $afkMessage;
		}
		
		// Get user's style for system message
		$stmt = $db->prepare('SELECT style, roomid FROM ' . PREFIX . 'sessions WHERE nickname=?;');
		$stmt->execute([$nickname]);
		$user_data = $stmt->fetch(PDO::FETCH_ASSOC);
		$user_style = $user_data ? $user_data['style'] : '';
		$user_roomid = $user_data ? $user_data['roomid'] : null;
		
		// Send system message
		$styled_name = style_this(htmlspecialchars($nickname), $user_style);
		add_system_message("$styled_name is AFK: " . htmlspecialchars($afkMessage), $user_roomid);
		
		// Return empty to prevent regular message posting
		return '';
	}
	
	// Handle /back command (only if already AFK)
	if (preg_match('~^/back$~iu', $message)) {
		// Check if user is actually AFK
		$stmt = $db->prepare('SELECT afk, style, roomid FROM ' . PREFIX . 'sessions WHERE nickname=?;');
		$stmt->execute([$nickname]);
		$user_data = $stmt->fetch(PDO::FETCH_ASSOC);
		
		if ($user_data && $user_data['afk'] == 1) {
			// Remove AFK status
			$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET afk=0, afk_message=NULL WHERE nickname=?;');
			$stmt->execute([$nickname]);
			
			// Update global $U if this is the current user
			if ($U['nickname'] === $nickname) {
				$U['afk'] = 0;
				$U['afk_message'] = null;
			}
			
			// Send system message
			$styled_name = style_this(htmlspecialchars($nickname), $user_data['style']);
			add_system_message("$styled_name is back", $user_data['roomid']);
		}
		
		// Return empty to prevent regular message posting
		return '';
	}
	
	// Handle /locate command
	if (preg_match('~^/locate\s+(.+)$~iu', $message, $matches)) {
		$targetUser = trim($matches[1]);
		return locate_user($targetUser, $status);
	}
	
	// Handle /shrug command
	if (preg_match('~^/shrug\s*(.*)$~iu', $message, $matches)) {
		$userMessage = trim($matches[1]);
		if (!empty($userMessage)) {
			return $userMessage . " ¯\\_(ツ)_/¯";
		} else {
			return "¯\\_(ツ)_/¯";
		}
	}
	
	// Handle /flip command
	if (preg_match('~^/flip\s*(.*)$~iu', $message, $matches)) {
		$userMessage = trim($matches[1]);
		if (!empty($userMessage)) {
			return $userMessage . " (╯°□°)╯︵ ┻━┻";
		} else {
			return "(╯°□°)╯︵ ┻━┻";
		}
	}
	
	// Handle /unflip command
	if (preg_match('~^/unflip\s*(.*)$~iu', $message, $matches)) {
		$userMessage = trim($matches[1]);
		if (!empty($userMessage)) {
			return $userMessage . " (ヘ･_･)ヘ┳━┳";
		} else {
			return "(ヘ･_･)ヘ┳━┳";
		}
	}
	
	// Return original message if no commands matched
	return $message;
}

/**
 * Generate help text based on user status level
 * 
 * @param int $status User's status level
 * @return string Formatted help text
 */
function generate_help_text($status)
{
	$help = "Available commands:<br>";
	$help .= "• <strong>/me [action]</strong> - Perform an action<br>";
	$help .= "• <strong>/whisper [text]</strong> - Display text in muted/whispered style<br>";
	$help .= "• <strong>/help</strong> - Show this help message<br>";
	$help .= "• <strong>/afk [message]</strong> - Mark yourself as away from keyboard<br>";
	$help .= "• <strong>/locate [username]</strong> - Find what room a user is in<br>";
	$help .= "• <strong>/shrug [message]</strong> - Add ¯\\_(ツ)_/¯ to your message<br>";
	$help .= "• <strong>/flip [message]</strong> - Add (╯°□°)╯︵ ┻━┻ to your message<br>";
	$help .= "• <strong>/unflip [message]</strong> - Add (ヘ･_･)ヘ┳━┳ to your message<br>";
	$help .= "• <strong>!rules</strong> - Show chat rules<br>";
	$help .= "• <strong>@username</strong> - Mention a user (use autocomplete)<br><br>";
	
	$help .= "<strong>Basic Usage:</strong><br>";
	$help .= "• Click on usernames to send private messages<br>";
	$help .= "• Use the dropdown to select who receives your message<br>";
	$help .= "• Emojis can be used with :emojiname: format<br>";
	
	if ($status >= 3) {
		$help .= "<br><strong>Member Features:</strong><br>";
		$help .= "• Access to member-only channels<br>";
		$help .= "• Custom font colors and styles<br>";
	}
	
	if ($status >= 5) {
		$help .= "<br><strong>Moderator Features:</strong><br>";
		$help .= "• Kick and ban users<br>";
		$help .= "• Access to staff channels<br>";
		$help .= "• Message cleanup tools<br>";
	}
	
	if ($status >= 7) {
		$help .= "<br><strong>Admin Features:</strong><br>";
		$help .= "• Full administrative access<br>";
		$help .= "• User management and registration<br>";
		$help .= "• System configuration<br>";
	}
	
	return $help;
}

/**
 * Locate a user and return their current room information
 * 
 * @param string $targetUser The username to locate
 * @param int $requestingUserStatus The status of the user making the request
 * @return string Location information or error message
 */
function locate_user($targetUser, $requestingUserStatus)
{
	global $db;
	
	if (!$db) {
		return "⚠️ Database connection error.";
	}
	
	try {
		// Search for the user in active sessions
		$stmt = $db->prepare('SELECT s.nickname, s.entry, s.status, r.name as roomname FROM ' . PREFIX . 'sessions s LEFT JOIN ' . PREFIX . 'rooms r ON s.roomid=r.id WHERE s.nickname=? AND s.entry!=0 ORDER BY s.entry DESC LIMIT 1;');
		if (!$stmt) {
			return "⚠️ Database query preparation failed.";
		}
		$stmt->execute([$targetUser]);
		$user = $stmt->fetch(PDO::FETCH_ASSOC);
		
		if (!$user) {
			return "User '<strong>$targetUser</strong>' is not currently online.";
		}
		
		// Check if user is incognito and requesting user has sufficient privileges
		try {
			$stmt = $db->prepare('SELECT incognito FROM ' . PREFIX . 'sessions WHERE nickname=?;');
			if ($stmt) {
				$stmt->execute([$targetUser]);
				$incognito = $stmt->fetch(PDO::FETCH_ASSOC);
				
				if ($incognito && isset($incognito['incognito']) && $incognito['incognito'] == 1 && $requestingUserStatus < 5) {
					return "User '<strong>$targetUser</strong>' location is private.";
				}
			}
		} catch (PDOException $e) {
			// incognito column might not exist, continue
			error_log("Incognito check error: " . $e->getMessage());
		}
		
		// Determine room information
		$location = "Main Chat";
		if (!empty($user['roomname'])) {
			$location = "Room: " . htmlspecialchars($user['roomname']);
		}
		
		// Show status-based location if in a status-based channel
		if ($user['status'] >= 7) {
			$statusLocation = " (Admin area)";
		} elseif ($user['status'] >= 5) {
			$statusLocation = " (Staff area)";
		} elseif ($user['status'] >= 3) {
			$statusLocation = " (Members area)";
		} else {
			$statusLocation = "";
		}
		
		return "📍 '<strong>$targetUser</strong>' is in: <strong>$location</strong>$statusLocation";
		
	} catch (PDOException $e) {
		error_log("locate_user PDOException: " . $e->getMessage());
		return "⚠️ Database error: " . $e->getMessage();
	} catch (Exception $e) {
		error_log("locate_user error: " . $e->getMessage());
		return "⚠️ Error locating user: " . $e->getMessage();
	}
}

function create_hotlinks($message)
{
	//Make hotlinks for URLs, redirect through dereferrer script to prevent session leakage
	// 1. all explicit schemes with whatever xxx://yyyyyyy
	$message = preg_replace('~(^|[^\w"])(\w+://[^\s<>]+)~iu', "$1<<$2>>", $message);
	// 2. valid URLs without scheme:
	$message = preg_replace('~((?:[^\s<>]*:[^\s<>]*@)?[a-z0-9\-]+(?:\.[a-z0-9\-]+)+(?::\d*)?/[^\s<>]*)(?![^<>]*>)~iu', "<<$1>>", $message); // server/path given
	$message = preg_replace('~((?:[^\s<>]*:[^\s<>]*@)?[a-z0-9\-]+(?:\.[a-z0-9\-]+)+:\d+)(?![^<>]*>)~iu', "<<$1>>", $message); // server:port given
	$message = preg_replace('~([^\s<>]*:[^\s<>]*@[a-z0-9\-]+(?:\.[a-z0-9\-]+)+(?::\d+)?)(?![^<>]*>)~iu', "<<$1>>", $message); // au:th@server given
	// 3. likely servers without any hints but not filenames like *.rar zip exe etc.
	$message = preg_replace('~((?:[a-z0-9\-]+\.)*(?:[a-z2-7]{55}d|[a-z2-7]{16})\.onion)(?![^<>]*>)~iu', "<<$1>>", $message); // *.onion
	$message = preg_replace('~([a-z0-9\-]+(?:\.[a-z0-9\-]+)+(?:\.(?!rar|zip|exe|gz|7z|bat|doc)[a-z]{2,}))(?=[^a-z0-9\-\.]|$)(?![^<>]*>)~iu', "<<$1>>", $message); // xxx.yyy.zzz
	// Convert every <<....>> into proper links:
	$message = preg_replace_callback(
		'/<<([^<>]+)>>/u',
		function ($matches) {
			if (strpos($matches[1], '://') === false) {
				return "<a href=\"http://$matches[1]\" target=\"_blank\" rel=\"noreferrer noopener\">$matches[1]</a>";
			} else {
				return "<a href=\"$matches[1]\" target=\"_blank\" rel=\"noreferrer noopener\">$matches[1]</a>";
			}
		},
		$message
	);
	return $message;
}

function apply_mention($message)
{
	return preg_replace_callback('/\@([^\s]+)/iu', function ($matched) {
		global $db;
		$nick = htmlspecialchars_decode($matched[1]);
		$rest = '';
		for ($i = 0; $i <= 3; ++$i) {
			//match case-sensitive present nicknames
			$stmt = $db->prepare('SELECT style FROM ' . PREFIX . 'sessions WHERE nickname=?;');
			$stmt->execute([$nick]);
			if ($tmp = $stmt->fetch(PDO::FETCH_NUM)) {
				return style_this(htmlspecialchars("@$nick"), $tmp[0]) . $rest;
			}
			//match case-insensitive present nicknames
			$stmt = $db->prepare('SELECT style FROM ' . PREFIX . 'sessions WHERE LOWER(nickname)=LOWER(?);');
			$stmt->execute([$nick]);
			if ($tmp = $stmt->fetch(PDO::FETCH_NUM)) {
				return style_this(htmlspecialchars("@$nick"), $tmp[0]) . $rest;
			}
			//match case-sensitive members
			$stmt = $db->prepare('SELECT style FROM ' . PREFIX . 'members WHERE nickname=?;');
			$stmt->execute([$nick]);
			if ($tmp = $stmt->fetch(PDO::FETCH_NUM)) {
				return style_this(htmlspecialchars("@$nick"), $tmp[0]) . $rest;
			}
			//match case-insensitive members
			$stmt = $db->prepare('SELECT style FROM ' . PREFIX . 'members WHERE LOWER(nickname)=LOWER(?);');
			$stmt->execute([$nick]);
			if ($tmp = $stmt->fetch(PDO::FETCH_NUM)) {
				return style_this(htmlspecialchars("@$nick"), $tmp[0]) . $rest;
			}
			if (strlen($nick) === 1) {
				break;
			}
			$rest = mb_substr($nick, -1) . $rest;
			$nick = mb_substr($nick, 0, -1);
		}
		return $matched[0];
	}, $message);
}

function add_message($message, $recipient, $poster, $delstatus, $poststatus, $displaysend, $style)
{
	global $db, $U;
	if ($message === '') {
		return false;
	}
	//Modifications for chat rooms
	$roomid = $U['roomid'];
	if (isset($_REQUEST['sendto']) && $_REQUEST['sendto'] === 'r @' && $U['status'] >= 5) {
		$allrooms = 1;
		$roomid = null;
	} else {
		$allrooms = 0;
	}
	
	//MODIFICATION Handle System Message channel
	if (isset($_REQUEST['sendto']) && $_REQUEST['sendto'] === 's 50' && $U['status'] >= 5) {
		// System Message: store styled message with sender info for staff viewing
		$displaysend = '<span class="sysmsg">[System: ' . style_this_clickable(htmlspecialchars($U['nickname']), $U['style']) . '] ';
		$messageText = $displaysend . style_this($message, $style) . '</span>';
	} else {
		$messageText = "<span class=\"usermsg\">$displaysend" . style_this($message, $style) . '</span>';
	}
	
	$newmessage = [
		'postdate'	=> time(),
		'poststatus'	=> $poststatus,
		'poster'	=> $poster,
		'recipient'	=> $recipient,
		'text'		=> $messageText,
		'delstatus'	=> $delstatus,
		'roomid'	=> $roomid,
		'allrooms'	=> $allrooms
	];
	//Modifcation chat rooms
	if ($newmessage['roomid'] === NULL) {
		//prevent posting the same message twice, if no other message was posted in-between.
		$stmt = $db->prepare('SELECT id FROM ' . PREFIX . 'messages WHERE poststatus=? AND poster=? AND recipient=? AND text=? AND roomid IS NULL AND id IN (SELECT * FROM (SELECT id FROM ' . PREFIX . 'messages ORDER BY id DESC LIMIT 1) AS t);');
		$stmt->execute([$newmessage['poststatus'], $newmessage['poster'], $newmessage['recipient'], $newmessage['text']]);
	} else {
		$stmt = $db->prepare('SELECT id FROM ' . PREFIX . 'messages WHERE poststatus=? AND poster=? AND recipient=? AND text=? AND roomid=? AND id IN (SELECT * FROM (SELECT id FROM ' . PREFIX . 'messages ORDER BY id DESC LIMIT 1) AS t);');
		$stmt->execute([$newmessage['poststatus'], $newmessage['poster'], $newmessage['recipient'], $newmessage['text'], $newmessage['roomid']]);
	}
	if ($stmt->fetch(PDO::FETCH_NUM)) {
		return false;
	}
	write_message($newmessage);
	return true;
}
//Modification chat rooms
function add_system_message($mes, $roomid = NULL)
{
	if ($mes === '') {
		return;
	}
	$sysmessage = [
		'postdate'	=> time(),
		'poststatus'	=> 1,
		'poster'	=> '',
		'recipient'	=> '',
		'text'		=> "<span class=\"sysmsg\" style=\"color:#888;\">$mes</span>",
		'delstatus'	=> 4,
		'roomid'    => $roomid,
		'allrooms'	=> 0
	];
	write_message($sysmessage);
}

function write_message($message)
{
	global $db;
	if (MSGENCRYPTED) {
		$message['text'] = base64_encode(sodium_crypto_aead_aes256gcm_encrypt($message['text'], '', AES_IV, ENCRYPTKEY));
	}
	
	// Insert message with retry logic for database locks
	$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'messages (postdate, poststatus, poster, recipient, text, delstatus, roomid, allrooms) VALUES (?, ?, ?, ?, ?, ?, ?, ?);');
	db_execute_with_retry($stmt, [$message['postdate'], $message['poststatus'], $message['poster'], $message['recipient'], $message['text'], $message['delstatus'], $message['roomid'], $message['allrooms']]);

	// Bridge integration: notify IRC of new message
	if (BRIDGE_ENABLED && $message['poststatus'] < 9 && !empty($message['poster'])) {
		global $bridge;
		if (!isset($bridge) || !$bridge->isConnected()) {
			$bridge = new BridgeClient();
			$bridge->connect();
		}

		if ($bridge->isConnected()) {
			// Determine sendto destination
			if (!empty($message['recipient'])) {
				$sendto = "pm";
				$toUser = $message['recipient'];
			} elseif ($message['allrooms'] == 1) {
				// Map special broadcast destinations
				if (isset($_REQUEST['sendto'])) {
					$sendto = $_REQUEST['sendto'];
				} else {
					$sendto = "room";
				}
				$toUser = null;
			} elseif ($message['roomid'] !== null) {
				$sendto = "r " . $message['roomid'];
				$toUser = null;
			} else {
				$sendto = "room";
				$toUser = null;
			}

			// Check if message is /me action
			$messageText = strip_tags($message['text']); // Remove HTML styling
			$isAction = (strpos($messageText, '/me ') === 0);

			$bridge->notifyMessage(
				$message['poster'],
				$sendto,
				$messageText,
				$isAction,
				!empty($message['recipient']),
				$toUser
			);
		}
	}

	if ($message['poststatus'] < 9 && get_setting('sendmail')) {
		$subject = 'New Chat message';
		$headers = 'From: ' . get_setting('mailsender') . "\r\nX-Mailer: PHP/" . phpversion() . "\r\nContent-Type: text/html; charset=UTF-8\r\n";
		$body = '<html><body style="background-color:#' . get_setting('colbg') . ';color:#' . get_setting('coltxt') . ";\">$message[text]</body></html>";
		mail(get_setting('mailreceiver'), $subject, $body, $headers);
	}
}

/**
 * Send a private message from the Dot bot to a user
 * 
 * @param string $recipient The nickname of the user to receive the PM
 * @param string $message The message content (can include HTML)
 */
function send_bot_pm($recipient, $message)
{
	global $db;
	
	if ($message === '' || $recipient === '') {
		error_log("send_bot_pm failed: empty message or recipient");
		return false;
	}
	
	try {
		// Bot style - distinctive color for bot messages
		$bot_style = 'color:#ffffff;font-family:Arial, sans-serif;font-weight:bold;';
		$bot_nickname = 'Dot';
		
		// Format as a PM from bot to user
		$displaysend = sprintf(
			get_setting('msgsendprv'),
			style_this_clickable(htmlspecialchars($bot_nickname), $bot_style),
			style_this_clickable(htmlspecialchars($recipient), 'color:#fff;')
		);
		
		$messageText = "<span class=\"usermsg\">$displaysend" . style_this($message, $bot_style) . '</span>';
		
		$botMessage = [
			'postdate'   => time(),
			'poststatus' => 9, // PM status
			'poster'     => $bot_nickname,
			'recipient'  => $recipient,
			'text'       => $messageText,
			'delstatus'  => 1, // Visible to regular users
			'roomid'     => null,
			'allrooms'   => 0
		];
		
		write_message($botMessage);
		error_log("send_bot_pm success: sent to $recipient");
		return true;
	} catch (Exception $e) {
		error_log("send_bot_pm exception: " . $e->getMessage());
		return false;
	}
}

/**
 * Process commands sent via PM to Dot bot
 * Commands work without slash prefix when sent to Dot
 * 
 * @param string $message The message sent to Dot
 * @param string $nickname The user's nickname
 * @param int $status The user's status level
 * @return string The bot's response
 */
function process_dot_command($message, $nickname, $status)
{
	global $db;
	
	// Normalize the message
	$message = trim($message);
	$lower = strtolower($message);
	
	// Help command
	if ($lower === 'help' || $lower === 'commands' || $lower === '?') {
		return "<strong>Dot Bot Commands:</strong><br>" . 
		       "Send me any of these commands (no slash needed!):<br><br>" .
		       "• <strong>help</strong> - Show this message<br>" .
		       "• <strong>time</strong> - Get current server time<br>" .
		       "• <strong>locate [username]</strong> - Find a user's room<br>" .
		       "• <strong>online</strong> - Count online users<br>" .
		       "• <strong>stats</strong> - Show chat statistics<br>" .
		       "• <strong>flip</strong> - Random coin flip<br>" .
		       "• <strong>roll [dice]</strong> - Roll dice (e.g., 2d6)<br>" .
		       "• <strong>8ball [question]</strong> - Ask the magic 8-ball<br>" .
		       "• <strong>about</strong> - About this bot<br>";
	}
	
	// Time command
	if ($lower === 'time' || $lower === 'date') {
		return "🕐 Current server time: <strong>" . date('Y-m-d H:i:s T') . "</strong>";
	}
	
	// Online count
	if ($lower === 'online' || $lower === 'users' || $lower === 'count') {
		$result = $db->query('SELECT COUNT(*) FROM ' . PREFIX . 'sessions WHERE entry!=0 AND status>0;');
		$count = $result->fetch(PDO::FETCH_NUM)[0];
		return "👥 Currently <strong>$count users</strong> online in the chat.";
	}
	
	// Stats command
	if ($lower === 'stats' || $lower === 'statistics') {
		$total_messages = $db->query('SELECT COUNT(*) FROM ' . PREFIX . 'messages;')->fetch(PDO::FETCH_NUM)[0];
		$total_users = $db->query('SELECT COUNT(*) FROM ' . PREFIX . 'members;')->fetch(PDO::FETCH_NUM)[0];
		$online_users = $db->query('SELECT COUNT(*) FROM ' . PREFIX . 'sessions WHERE entry!=0 AND status>0;')->fetch(PDO::FETCH_NUM)[0];
		
		return "📊 <strong>Chat Statistics:</strong><br>" .
		       "Total Messages: $total_messages<br>" .
		       "Registered Users: $total_users<br>" .
		       "Currently Online: $online_users";
	}
	
	// Locate command
	if (preg_match('/^locate\s+(.+)$/i', $message, $matches)) {
		$target = trim($matches[1]);
		$response = locate_user($target, $status);
		return $response ? $response : "Unable to locate user.";
	}
	
	// Coin flip
	if ($lower === 'flip' || $lower === 'coin') {
		$result = mt_rand(0, 1) ? 'Heads' : 'Tails';
		return "🪙 Coin flip: <strong>$result</strong>!";
	}
	
	// Dice roll
	if (preg_match('/^roll\s*(\d+)?d(\d+)$/i', $message, $matches)) {
		$num = isset($matches[1]) && $matches[1] ? (int)$matches[1] : 1;
		$sides = (int)$matches[2];
		
		if ($num > 10 || $sides > 100) {
			return "❌ Too many dice or sides! Maximum is 10d100.";
		}
		
		$rolls = [];
		$total = 0;
		for ($i = 0; $i < $num; $i++) {
			$roll = mt_rand(1, $sides);
			$rolls[] = $roll;
			$total += $roll;
		}
		
		$rollsText = implode(', ', $rolls);
		return "🎲 Rolling {$num}d{$sides}: [$rollsText] = <strong>$total</strong>";
	} elseif ($lower === 'roll') {
		$roll = mt_rand(1, 6);
		return "🎲 Rolling 1d6: <strong>$roll</strong>";
	}
	
	// Magic 8-ball
	if (preg_match('/^8ball\s+(.+)$/i', $message, $matches)) {
		$answers = [
			"It is certain.", "Without a doubt.", "Yes, definitely.", "You may rely on it.",
			"As I see it, yes.", "Most likely.", "Outlook good.", "Yes.",
			"Signs point to yes.", "Reply hazy, try again.", "Ask again later.",
			"Better not tell you now.", "Cannot predict now.", "Concentrate and ask again.",
			"Don't count on it.", "My reply is no.", "My sources say no.",
			"Outlook not so good.", "Very doubtful."
		];
		$answer = $answers[array_rand($answers)];
		return "🎱 <em>" . htmlspecialchars($matches[1]) . "</em><br><strong>$answer</strong>";
	}
	
	// About
	if ($lower === 'about' || $lower === 'info') {
		return "🤖 <strong>I'm Dot, your friendly chat bot!</strong><br>" .
		       "I'm here to help you with useful commands and information.<br>" .
		       "Send me <strong>help</strong> to see what I can do!";
	}
	
	// Unknown command
	return "🤔 I don't understand that command. Send me <strong>help</strong> to see what I can do!";
}

//Modified
function clean_chat()
{
	global $db;
	$db->query('DELETE FROM ' . PREFIX . 'messages;');
	add_system_message(sprintf(get_setting('msgclean'), get_setting('chatname')));
}
//Modified
function clean_room()
{
	global $db, $U;
	$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'messages where roomid=?;');
	$stmt->execute([$U['roomid']]);
}

function clean_selected($status, $nick)
{
	global $db;
	if (isset($_REQUEST['mid'])) {

		//Service Admins (7+) can permanently delete already-deleted messages (purge)
		if ($status >= 7) {
			error_log("Purge mode active for status $status");
			// Check each message - if already deleted, purge it permanently, otherwise soft delete
			$stmt_check = $db->prepare('SELECT deleted FROM ' . PREFIX . 'messages WHERE id=?;');
			$stmt_purge = $db->prepare('DELETE FROM ' . PREFIX . 'messages WHERE id=?;');
			$stmt_soft = $db->prepare('UPDATE ' . PREFIX . 'messages SET deleted=1 WHERE id=? AND (poster=? OR recipient=? OR (poststatus<=? AND delstatus<9));');
			
			foreach ($_REQUEST['mid'] as $mid) {
				$stmt_check->execute([$mid]);
				$result = $stmt_check->fetch(PDO::FETCH_ASSOC);
				
				if ($result && $result['deleted'] == 1) {
					// Already soft-deleted, purge permanently
					error_log("Purging message $mid (already deleted)");
					$stmt_purge->execute([$mid]);
				} else {
					// Not deleted yet, soft delete
					error_log("Soft deleting message $mid (deleted=" . ($result['deleted'] ?? 'null') . ")");
					$stmt_soft->execute([$mid, $nick, $nick, $status]);
				}
			}
		}
		//Modification modsdeladminmsg - moderators can delete admin messages (but he can only delete the messages he is able to read.)
		elseif ((get_setting('modsdeladminmsg') == 1) && ($status >= 5)) {

			$stmt = $db->prepare('UPDATE ' . PREFIX . 'messages SET deleted=1 WHERE id=? AND (poster=? OR recipient=? OR (poststatus<= ' . $status . ' AND delstatus<9));');
			foreach ($_REQUEST['mid'] as $mid) {
				$stmt->execute([$mid, $nick, $nick]);
			}
		} else {
			$stmt = $db->prepare('UPDATE ' . PREFIX . 'messages SET deleted=1 WHERE id=? AND (poster=? OR recipient=? OR (poststatus<? AND delstatus<?));');
			foreach ($_REQUEST['mid'] as $mid) {
				$stmt->execute([$mid, $nick, $nick, $status, $status]);
			}
		}
	}
}

function clean_inbox_selected()
{
	global $U, $db;
	if (isset($_REQUEST['mid'])) {
		$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'inbox WHERE id=? AND recipient=?;');
		foreach ($_REQUEST['mid'] as $mid) {
			$stmt->execute([$mid, $U['nickname']]);
		}
	}
}

function del_all_messages($nick, $entry)
{
	global $db;
	if ($nick == '') {
		return;
	}
	$stmt = $db->prepare('UPDATE ' . PREFIX . 'messages SET deleted=1 WHERE poster=? AND postdate>=?;');
	$stmt->execute([$nick, $entry]);
	$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'inbox WHERE poster=? AND postdate>=?;');
	$stmt->execute([$nick, $entry]);
}

function del_last_message()
{

	global $U, $db;
	if ($U['status'] > 1) {
		$entry = 0;
	} else {
		$entry = $U['entry'];
	}
	$stmt = $db->prepare('SELECT id FROM ' . PREFIX . 'messages WHERE poster=? AND postdate>=? ORDER BY id DESC LIMIT 1;');
	$stmt->execute([$U['nickname'], $entry]);
	if ($id = $stmt->fetch(PDO::FETCH_NUM)) {
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'messages SET deleted=1 WHERE id=?;');
		$stmt->execute($id);
		$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'inbox WHERE postid=?;');
		$stmt->execute($id);
	}
}

function print_messages($delstatus = 0, $modroom = 0)
{
	//line changed
	global $U, $I, $db, $language;


	$dateformat = get_setting('dateformat');
	if (!$U['embed'] && get_setting('imgembed')) {
		$removeEmbed = true;
	} else {
		$removeEmbed = false;
	}
	if ($U['timestamps'] && !empty($dateformat)) {
		$timestamps = true;
	} else {
		$timestamps = false;
	}
	if ($U['sortupdown']) {
		$direction = 'ASC';
	} else {
		$direction = 'DESC';
	}
	if ($U['status'] > 1) {
		$entry = 0;
	} else {
		$entry = $U['entry'];
	}
	if (isset($_REQUEST['modroom']) && $_REQUEST['modroom'] && $U['status'] >= 5) {
		$modroom = 1;
	} else {
		$modroom = 0;
	}

	//MODIFCATION chat rooms to only show messages of the all rooms

	//MODIFICATION DEL-BUTTONS some lines added to enable delete buttons in front of messages for mods and above.
	// look at function send_choose_messages for better understanding 
	$modmode = false;





	//modmode (DEL-Buttons) for mods. and for members (according to the memdel setting (always OR if no mod is present and if memkick setting enabled.)
	$memdel = (int)get_setting('memdel');
	if (($delstatus === 0 && $U['status'] >= 5) || ($U['status'] >= 3 && $memdel == 2) || ($U['status'] >= 3 && get_count_mods() == 0 && $memdel == 1)) {
		$modmode = true;
		$delstatus = $U['status'];
		//debug 
		//echo "modmode active";
	}


	//Modification for visibility of channels in all roooms
	$channelvisinroom = (int) get_setting('channelvisinroom');
	if ($channelvisinroom == 0) {
		$channelvisinroom = 2;
	}


	echo '<div id="messages">';

	if ($modmode === true) {
		echo form('admin_clean_message', 'clean');
		echo hidden('what', 'selected');
		echo hidden('modroom', $modroom); // so that deleting a message does not cause exiting modroom

		$stmt = $db->prepare('SELECT id, postdate, text, poststatus, delstatus, poster, recipient, roomid, allrooms, deleted FROM ' . PREFIX . 'messages WHERE (poststatus<=? OR ' .
			'(poststatus=9 AND ( (poster=? AND recipient NOT IN (SELECT ign FROM ' . PREFIX . 'ignored WHERE ignby=?) ) OR recipient=?) AND postdate>=?)' .
			') AND poster NOT IN (SELECT ign FROM ' . PREFIX . "ignored WHERE ignby=?) ORDER BY id $direction;");
		$stmt->execute([$U['status'], $U['nickname'], $U['nickname'], $U['nickname'], $entry, $U['nickname']]);


		while ($message = $stmt->fetch(PDO::FETCH_ASSOC)) {
			// Skip deleted messages for non-admins
			if ($message['deleted'] == 1 && $U['status'] < 7) {
				continue;
			}

			//Modification for chat rooms
			if ($message['poststatus'] < $channelvisinroom && $message['roomid'] !== $U['roomid'] && !$message['allrooms'] && !$modroom) {
				continue;
			}

			//Modification for modrooms in chat rooms
			$roomname = "";
			if ($modroom && !$message['allrooms']) {
				$roomname = 'Main Chat';
				if ($message['roomid'] != null) {
					$stmt1 = $db->prepare('SELECT name FROM ' . PREFIX . 'rooms WHERE id=? AND access<=?');
					$stmt1->execute([$message['roomid'], $U['status']]);
					if (!$name = $stmt1->fetch(PDO::FETCH_NUM)) {
						continue;
					}
					$roomname = $name[0];
				}
				$roomname = '[' . $roomname . ']';
			}

			prepare_message_print($message, $removeEmbed);
			
			// Determine if user can delete this message using permission helper
			$can_delete = can_delete_message($U['status'], $message['poststatus']);
			
			// Users can delete their own messages
			$is_own_message = ($message['poster'] === $U['nickname']);
			
			// Users can delete PMs they received, BUT NOT if sender has same or higher status
			$is_received_pm = false;
			if ($message['recipient'] === $U['nickname'] && $message['postdate'] >= $entry && !empty($message['poster'])) {
				// Get sender's status
				$stmt_sender = $db->prepare('SELECT status FROM ' . PREFIX . 'sessions WHERE nickname=?;');
				$stmt_sender->execute([$message['poster']]);
				$sender_data = $stmt_sender->fetch(PDO::FETCH_ASSOC);
				if (!$sender_data) {
					$stmt_sender = $db->prepare('SELECT status FROM ' . PREFIX . 'members WHERE nickname=?;');
					$stmt_sender->execute([$message['poster']]);
					$sender_data = $stmt_sender->fetch(PDO::FETCH_ASSOC);
				}
				$sender_status = $sender_data ? $sender_data['status'] : 1;
				
				// Can only delete received PMs if sender has lower status
				if ($sender_status < $U['status']) {
					$is_received_pm = true;
				}
			}
			
			// Special: Users can always delete PMs from Dot bot
			$is_dot_pm = ($message['poster'] === 'Dot' && $message['recipient'] === $U['nickname']);
			
			$show_del_button = $can_delete || $is_own_message || $is_received_pm || $is_dot_pm;
			
			// Service Admins (7+) can see and purge deleted messages
			$is_deleted = ($message['deleted'] == 1);
			$msg_class = $is_deleted ? "msg deleted-msg" : "msg";
			
			if ($show_del_button) {
				$del_title = $is_deleted ? "Purge message (permanent)" : "Delete message";
				echo "<div class=\"$msg_class\"><button title=\"$del_title\" class=\"delbutton_inline_removable\" name=\"mid[]\" type=\"submit\" value=\"$message[id]\">DEL</button>";
			} else {
				echo "<div class=\"$msg_class\">&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp";
			}



			//if((int)$U['clickablenicknames']>0){   //REMOVE LINE LATER
			if ((bool) get_setting('clickablenicknamesglobal')) {

				$message_new = make_nicknames_clickable($message['text']);
			} else {

			$message_new = $message['text'];
		}
		
		//MODIFICATION System Message: hide sender from status 3 and below (guests, junior/senior members)
		if ($U['status'] <= 3 && strpos($message_new, '<span class="sysmsg">[System:') !== false) {
			// Remove the [System: username] part for non-staff
			$message_new = preg_replace('/<span class="sysmsg">\[System: .*?\] /', '<span class="sysmsg">', $message_new);
			// Strip all style attributes and span tags from message text to show as plain white text
			$message_new = preg_replace('/<span style="[^"]*">/', '', $message_new);
			$message_new = str_replace('</span>', '', $message_new);
		}

		if ($timestamps) {
			echo ' <small>' . date($dateformat, $message['postdate']) . ' - </small>';
		}			if ($modroom) {
				echo "<span class=\"modroom\">$roomname</span>";
			}
			echo " $message_new";
			if ($message['deleted'] == 1) {
				echo ' <small>(deleted)</small>';
			}
			echo "</div>";
		}
		echo "</form>";
	} elseif ($delstatus > 0) {
		//Modification modsdeladminmsg

		if (get_setting('modsdeladminmsg') == 1) {
			$stmt = $db->prepare('SELECT postdate, id, poststatus, roomid, allrooms, text, deleted FROM ' . PREFIX . 'messages WHERE ' .
				"(poststatus<=? AND delstatus<9) OR ((poster=? OR recipient=?) AND postdate>=?) ORDER BY id $direction;");
			$stmt->execute([$U['status'], $U['nickname'], $U['nickname'], $entry]);
			while ($message = $stmt->fetch(PDO::FETCH_ASSOC)) {
				// Skip deleted messages for non-admins
				if ($message['deleted'] == 1 && $U['status'] < 7) {
					continue;
				}
				//Modification for chat rooms
				if ($message['poststatus'] < $channelvisinroom && $message['roomid'] !== $U['roomid'] && !$message['allrooms']) {
					continue;
				}

				prepare_message_print($message, $removeEmbed);
				if ($message['deleted'] == 1) {
					echo "<div class=\"msg deleted-msg\"><label><input type=\"checkbox\" name=\"mid[]\" value=\"$message[id]\">";
				} else {
					echo "<div class=\"msg\"><label><input type=\"checkbox\" name=\"mid[]\" value=\"$message[id]\">";
				}
				if ($timestamps) {
					echo ' <small>' . date($dateformat, $message['postdate']) . ' - </small>';
				}
				echo " $message[text]";
				if ($message['deleted'] == 1) {
					echo ' <small>(deleted)</small>';
				}
				echo "</label></div>";
			}
		} else {
			$stmt = $db->prepare('SELECT postdate, id, text, poststatus, roomid, allrooms, deleted FROM ' . PREFIX . 'messages WHERE ' .
				"(poststatus<? AND delstatus<?) OR ((poster=? OR recipient=?) AND postdate>=?) ORDER BY id $direction;");
			$stmt->execute([$U['status'], $delstatus, $U['nickname'], $U['nickname'], $entry]);
			while ($message = $stmt->fetch(PDO::FETCH_ASSOC)) {
				// Skip deleted messages for non-admins
				if ($message['deleted'] == 1 && $U['status'] < 7) {
					continue;
				}
				//Modification for chat rooms
				if ($message['poststatus'] < $channelvisinroom && $message['roomid'] !== $U['roomid'] && !$message['allrooms']) {
					continue;
				}
				prepare_message_print($message, $removeEmbed);
				if ($message['deleted'] == 1) {
					echo "<div class=\"msg deleted-msg\"><label><input type=\"checkbox\" name=\"mid[]\" value=\"$message[id]\">";
				} else {
					echo "<div class=\"msg\"><label><input type=\"checkbox\" name=\"mid[]\" value=\"$message[id]\">";
				}
				if ($timestamps) {
					echo ' <small>' . date($dateformat, $message['postdate']) . ' - </small>';
				}
				echo " $message[text]";
				if ($message['deleted'] == 1) {
					echo ' <small>(deleted)</small>';
				}
				echo "</label></div>";
			}
		}
	} else {
		$stmt = $db->prepare('SELECT id, postdate, text, roomid, allrooms, poststatus, deleted FROM ' . PREFIX . 'messages WHERE (poststatus<=? OR ' .
			'(poststatus=9 AND ( (poster=? AND recipient NOT IN (SELECT ign FROM ' . PREFIX . 'ignored WHERE ignby=?) ) OR recipient=?) AND postdate>=?)' .
			') AND poster NOT IN (SELECT ign FROM ' . PREFIX . "ignored WHERE ignby=?) ORDER BY id $direction;");
		$stmt->execute([$U['status'], $U['nickname'], $U['nickname'], $U['nickname'], $entry, $U['nickname']]);
		while ($message = $stmt->fetch(PDO::FETCH_ASSOC)) {
			// Skip deleted messages for non-admins
			if ($message['deleted'] == 1 && $U['status'] < 7) {
				continue;
			}
			//Modification for chat rooms
			if ($message['poststatus'] < $channelvisinroom && $message['roomid'] !== $U['roomid'] && !$message['allrooms']) {
				continue;
			}

			prepare_message_print($message, $removeEmbed);
			if ($message['deleted'] == 1) {
				echo '<div class="msg deleted-msg">';
			} else {
				echo '<div class="msg">';
			}

			//MODIFICATION to make nicknames clickable //REMOVE LINE LATER
			//if((int)$U['clickablenicknames']>0){//REMOVE LINE LATER
			//MODIFICATION to make nicknames clickable (global setting
			if ((bool) get_setting('clickablenicknamesglobal')) {
				$message_new = make_nicknames_clickable($message['text']);
			} else {

				$message_new = $message['text'];
			}
			
			//MODIFICATION System Message: hide sender from status 3 and below (guests, applicants, members)
			if ($U['status'] <= 3 && strpos($message_new, '<span class="sysmsg">[System:') !== false) {
				// Remove the [System: username] part for non-staff
				$message_new = preg_replace('/<span class="sysmsg">\[System: .*?\] /', '<span class="sysmsg">', $message_new);
				// Strip all style attributes and span tags from message text to show as plain white text
				$message_new = preg_replace('/<span style="[^"]*">/', '', $message_new);
				$message_new = str_replace('</span>', '', $message_new);
			}



			if ($timestamps) {
				echo '<small>' . date($dateformat, $message['postdate']) . ' - </small>';
			}
			echo "$message_new";
			if ($message['deleted'] == 1) {
				echo ' <small>(deleted)</small>';
			}
			echo "</div>";
		}
	}
	echo '</div>';
}

//MODIFICATION for clickable nicknames
function make_nicknames_clickable($message)
{

	global $U, $language;
	$nc = substr(time(), -6);

	$channel = "";
	$sender = "";
	$recipient = "";
	$pm = false;

	$channel_encoded = "";

	//pattern for default system message settings in chat setup. If system messages are changed in the setup, this pattern has to be changed as well. 
	$pattern_channel_detect = "(\[M\]\ |\[Staff\]\ |\[Admin\]\ )";

	$pattern_pm_detect = "\[(\<span\ style\=\"[^\"]{1,}\"\><span\ class\=\"clickablenickname\"\>[A-Za-z0-9]{1,}\<\/span\>\<\/span\>)\ to\ ((?1))\]";

	$pattern = "(\<span\ style\=\"[^\"]{1,}\"\>\<span\ class\=\"clickablenickname\"\>([A-Za-z0-9]{1,})\<\/span\>)";


	preg_match('/' . $pattern_pm_detect . '/i', $message, $matches);
	if (!empty($matches['0'])) {
		$pm = true;
	}

	preg_match('/' . $pattern_channel_detect . '/i', $message, $matches);
	if (!empty($matches['0'])) {
		if ($matches['0'] === "[M] ") {
			$channel = "s 31";
		} elseif ($matches['0'] === "[Staff] ") {
			$channel = "s 48";
		} elseif ($matches['0'] === "[Admin] ") {
			$channel = "s 56";
		} elseif (preg_match('/\[System: /', $matches['0'])) {
			$channel = "s 50";
		}
	} else {
		$channel = "room"; // Default to This Room
	}

	//channel must be encoded because of special character + and & and space
	$channel_encoded = urlencode($channel);

	/* REMOVE LATER
    //option 1
    if($pm || ((int)$U['clickablenicknames']===1)){
          $replacement = "<a class=\"nicklink\" href=\"?action=post&amp;session=$U[session]&amp;lang=$language&amp;nc=$nc&amp;sendto=".htmlspecialchars('$2').'" target="post">'.'$1'.'</a>';    
    }

    //option 2
    if(!$pm && ((int)$U['clickablenicknames']===2)){
    $replacement = "<a class=\"nicklink\" href=\"?action=post&amp;session=$U[session]&amp;lang=$language&amp;nc=$nc&amp;sendto=".$channel_encoded."&amp;nickname=@".htmlspecialchars('$2').'&nbsp" target="post">'.'$1'.'</a>';
    }
    */

	if ($pm) { //IF PM DETECTED
		$replacement = "<a class=\"nicklink\" href=\"?action=post&amp;session=$U[session]&amp;lang=$language&amp;nc=$nc&amp;sendto=" . htmlspecialchars('$2') . '" target="post">' . '$1' . '</a>';
	} else { //Message to all or to one of the channels
		$replacement = "<a class=\"nicklink\" href=\"?action=post&amp;session=$U[session]&amp;lang=$language&amp;nc=$nc&amp;sendto=" . $channel_encoded . "&amp;nickname=@" . htmlspecialchars('$2') . '&nbsp" target="post">' . '$1' . '</a>';
	}

	//regex for option 1 and option 2 and PM
	$message = preg_replace("/$pattern/", $replacement, $message);

	return $message;
}


function prepare_message_print(&$message, $removeEmbed)
{
	if (MSGENCRYPTED) {
		$message['text'] = sodium_crypto_aead_aes256gcm_decrypt(base64_decode($message['text']), null, AES_IV, ENCRYPTKEY);
	}
	if ($removeEmbed) {
		$message['text'] = preg_replace_callback(
			'/<img src="([^"]+)"><\/a>/u',
			function ($matched) {
				return "$matched[1]</a>";
			},
			$message['text']
		);
	}
}

// this and that

function send_headers()
{
	header('Content-Type: text/html; charset=UTF-8');
	header('Pragma: no-cache');
	header('Cache-Control: no-cache, no-store, must-revalidate, max-age=0');
	header('Expires: 0');
	header('Referrer-Policy: no-referrer');
	header("Content-Security-Policy: default-src 'self'; img-src * data:; media-src * data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
	header('X-Content-Type-Options: nosniff');
	header('X-Frame-Options: sameorigin');
	header('X-XSS-Protection: 1; mode=block');
	if ($_SERVER['REQUEST_METHOD'] === 'HEAD') {
		exit; // headers sent, no further processing needed
	}
}

function save_setup($C)
{
	global $db;
	//sanity checks and escaping
	foreach ($C['msg_settings'] as $setting) {
		$_REQUEST[$setting] = htmlspecialchars($_REQUEST[$setting]);
	}
	foreach ($C['number_settings'] as $setting) {
		settype($_REQUEST[$setting], 'int');
	}
	foreach ($C['colour_settings'] as $setting) {
		if (preg_match('/^#([a-f0-9]{6})$/i', $_REQUEST[$setting], $match)) {
			$_REQUEST[$setting] = $match[1];
		} else {
			unset($_REQUEST[$setting]);
		}
	}
	settype($_REQUEST['guestaccess'], 'int');
	if (!preg_match('/^[01234]$/', $_REQUEST['guestaccess'])) {
		unset($_REQUEST['guestaccess']);
	} elseif ($_REQUEST['guestaccess'] == 4) {
		$db->exec('DELETE FROM ' . PREFIX . 'sessions WHERE status<7;');
	}
	settype($_REQUEST['englobalpass'], 'int');
	settype($_REQUEST['captcha'], 'int');
	settype($_REQUEST['dismemcaptcha'], 'int');
	settype($_REQUEST['guestreg'], 'int');
	if (isset($_REQUEST['defaulttz'])) {
		$tzs = timezone_identifiers_list();
		if (!in_array($_REQUEST['defaulttz'], $tzs)) {
			unset($_REQUEST['defualttz']);
		}
	}
	$_REQUEST['rulestxt'] = preg_replace("/(\r?\n|\r\n?)/u", '<br>', $_REQUEST['rulestxt']);
	$_REQUEST['chatname'] = htmlspecialchars($_REQUEST['chatname']);
	$_REQUEST['redirect'] = htmlspecialchars($_REQUEST['redirect']);
	if ($_REQUEST['memberexpire'] < 5) {
		$_REQUEST['memberexpire'] = 5;
	}
	if ($_REQUEST['captchatime'] < 30) {
		$_REQUEST['memberexpire'] = 30;
	}
	if ($_REQUEST['defaultrefresh'] < 5) {
		$_REQUEST['defaultrefresh'] = 5;
	} elseif ($_REQUEST['defaultrefresh'] > 150) {
		$_REQUEST['defaultrefresh'] = 150;
	}
	if ($_REQUEST['maxname'] < 1) {
		$_REQUEST['maxname'] = 1;
	} elseif ($_REQUEST['maxname'] > 50) {
		$_REQUEST['maxname'] = 50;
	}
	if ($_REQUEST['maxmessage'] < 1) {
		$_REQUEST['maxmessage'] = 1;
	} elseif ($_REQUEST['maxmessage'] > 16000) {
		$_REQUEST['maxmessage'] = 16000;
	}
	if ($_REQUEST['numnotes'] < 1) {
		$_REQUEST['numnotes'] = 1;
	}
	if (!valid_regex($_REQUEST['nickregex'])) {
		unset($_REQUEST['nickregex']);
	}
	if (!valid_regex($_REQUEST['passregex'])) {
		unset($_REQUEST['passregex']);
	}
	// Modification spare notes
	if (!preg_match('/^[3567]$/', $_REQUEST['sparenotesaccess'])) {
		$_REQUEST['sparenotesaccess'] = '10';
	}
	$_REQUEST['sparenotesname'] = htmlspecialchars($_REQUEST['sparenotesname']);
	// End modification
	// Modification chat rooms
	if (!preg_match('/^[567]$/', $_REQUEST['roomcreateaccess'])) {
		unset($_REQUEST['roomcreateaccess']);
	}
	settype($_REQUEST['roomexpire'], 'int');
	if (!preg_match('/^[235679]$/', $_REQUEST['channelvisinroom'])) {
		unset($_REQUEST['channelvisinroom']);
	}
	// End modification

	//save values
	foreach ($C['settings'] as $setting) {
		if (isset($_REQUEST[$setting])) {
			update_setting($setting, $_REQUEST[$setting]);
		}
	}
}

function set_default_tz()
{
	global $U;
	if (isset($U['tz'])) {
		date_default_timezone_set($U['tz']);
	} else {
		date_default_timezone_set(get_setting('defaulttz'));
	}
}

function valid_admin()
{
	global $U;
	if (isset($_REQUEST['session'])) {
		parse_sessions();
	}
	if (!isset($U['session']) && isset($_REQUEST['nick']) && isset($_REQUEST['pass'])) {
		create_session(true, $_REQUEST['nick'], $_REQUEST['pass']);
	}
	if (isset($U['status'])) {
		if ($U['status'] >= 7) {
			return true;
		}
		send_access_denied();
	}
	return false;
}

function valid_nick($nick)
{
	$len = mb_strlen($nick);
	if ($len < 1 || $len > get_setting('maxname')) {
		return false;
	}

	// Bridge integration: reject nicknames starting with irc_ or web_ (reserved for bridge)
	if (BRIDGE_ENABLED && preg_match('/^(irc_|web_)/i', $nick)) {
		return false;
	}

	return preg_match('/' . get_setting('nickregex') . '/u', $nick);
}

function valid_pass($pass)
{
	if (mb_strlen($pass) < get_setting('minpass')) {
		return false;
	}
	return preg_match('/' . get_setting('passregex') . '/u', $pass);
}

function valid_regex(&$regex)
{
	$regex = preg_replace('~(^|[^\\\\])/~', "$1\/u", $regex); // Escape "/" if not yet escaped
	return (@preg_match("/$_REQUEST[match]/u", '') !== false);
}

function get_timeout($lastpost, $expire)
{
	$s = ($lastpost + 60 * $expire) - time();
	$m = floor($s / 60);
	$s %= 60;
	if ($s < 10) {
		$s = "0$s";
	}
	return "$m:$s";
}

// Advanced Moderation Helper Functions

function moderation_tables_exist() {
	global $db;
	static $tables_exist = null;
	
	if ($tables_exist !== null) {
		return $tables_exist;
	}
	
	try {
		// Try to query the mod_actions table
		$db->query('SELECT 1 FROM ' . PREFIX . 'mod_actions LIMIT 1');
		$tables_exist = true;
	} catch (Exception $e) {
		$tables_exist = false;
	}
	
	return $tables_exist;
}

function can_view_history($mod_status, $target_status) {
	// Mods (5+) can view history for users below their status
	if ($mod_status >= 5) {
		return $target_status < $mod_status;
	}
	return false;
}

function is_staff_online() {
	global $db;
	// Check if any non-incognito staff (status 5+) are online, excluding Dot
	$stmt = $db->query('SELECT COUNT(*) FROM ' . PREFIX . 'sessions WHERE entry!=0 AND status>=5 AND incognito=0 AND nickname!="Dot";');
	return $stmt->fetch(PDO::FETCH_NUM)[0] > 0;
}

function can_review_appeal($mod_status, $action_moderator_status) {
	// Mods can review their own actions and lower
	if ($mod_status == 5) {
		return $action_moderator_status <= 5;
	}
	// Super Mods can review mod actions
	if ($mod_status == 6) {
		return $action_moderator_status <= 6;
	}
	// Admins can review all
	if ($mod_status >= 7) {
		return true;
	}
	return false;
}

function can_modify_rules($mod_status, $operation) {
	// $operation: 'view', 'toggle', 'modify', 'create'
	if ($operation === 'view' && $mod_status >= 5) {
		return true;
	}
	if ($operation === 'toggle' && $mod_status >= 6) {
		return true;
	}
	if (in_array($operation, ['modify', 'create']) && $mod_status >= 7) {
		return true;
	}
	return false;
}

function log_mod_action($action_type, $target_user, $reason, $duration = 0, $auto_generated = false, $message_id = null, $severity = 1) {
	global $U, $db;
	if (!moderation_tables_exist()) {
		return null;
	}
	$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'mod_actions (action_type, moderator, target_user, reason, action_date, duration, auto_generated, related_message_id, severity) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);');
	$stmt->execute([
		$action_type,
		$U['nickname'] ?? 'System',
		$target_user,
		$reason,
		time(),
		$duration,
		$auto_generated ? 1 : 0,
		$message_id,
		$severity
	]);
	return $db->lastInsertId();
}

function get_user_warnings($user) {
	global $db;
	if (!moderation_tables_exist()) {
		return null;
	}
	$stmt = $db->prepare('SELECT * FROM ' . PREFIX . 'user_warnings WHERE user=?;');
	$stmt->execute([$user]);
	return $stmt->fetch(PDO::FETCH_ASSOC);
}

function add_user_warning($user, $reason, $auto = false, $issuer = 'System', $severity = 1, $expiry_days = 10) {
	global $db, $U;
	if (!moderation_tables_exist()) {
		return 0;
	}
	
	// Use issuer from function param or fall back to global user
	if ($issuer === 'System' && isset($U['nickname'])) {
		$issuer = $U['nickname'];
	}
	
	// Calculate expiration (0 = never expires)
	$expires = $expiry_days > 0 ? (time() + ($expiry_days * 86400)) : 0;
	
	$warnings = get_user_warnings($user);
	if ($warnings) {
		$new_count = $warnings['warning_count'] + 1;
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'user_warnings SET warning_count=?, last_warning=?, expires=? WHERE user=?;');
		$stmt->execute([$new_count, time(), $expires, $user]);
	} else {
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'user_warnings (user, warning_count, last_warning, expires) VALUES (?, 1, ?, ?);');
		$stmt->execute([$user, time(), $expires]);
		$new_count = 1;
	}
	
	// Log to user_history with severity and expiration info
	$details = $reason . " [Severity: $severity]" . ($expires > 0 ? " [Expires: " . date('Y-m-d', $expires) . "]" : " [Permanent]");
	log_user_action($user, 'warning', $issuer, $details, $expiry_days * 86400);
	
	return $new_count;
}

function clear_expired_warnings() {
	global $db;
	// Check if table exists before trying to clean
	try {
		$db->exec('DELETE FROM ' . PREFIX . 'user_warnings WHERE expires < ' . time() . ';');
	} catch (PDOException $e) {
		// Table doesn't exist yet, skip cleanup
	}
}

function check_automod_rules($user, $message, $status) {
	global $db;
	
	if (!moderation_tables_exist() || !(bool)get_setting('automod_enabled')) {
		return null;
	}
	
	// Don't auto-mod staff
	if ($status >= 5) {
		return null;
	}
	
	$rules = $db->query('SELECT * FROM ' . PREFIX . 'automod_rules WHERE enabled=1 ORDER BY id;')->fetchAll(PDO::FETCH_ASSOC);
	
	foreach ($rules as $rule) {
		$triggered = false;
		$reason = '';
		
		switch ($rule['rule_type']) {
			case 'spam_duplicate':
				// Check for duplicate messages in last minute
				$stmt = $db->prepare('SELECT COUNT(*) FROM ' . PREFIX . 'messages WHERE poster=? AND text=? AND postdate > ?;');
				$stmt->execute([$user, $message, time() - 60]);
				$count = $stmt->fetch(PDO::FETCH_NUM)[0];
				if ($count >= $rule['threshold']) {
					$triggered = true;
					$reason = "Spam detected: {$count} duplicate messages";
				}
				break;
				
			case 'flood_rate':
				// Check message rate
				$stmt = $db->prepare('SELECT COUNT(*) FROM ' . PREFIX . 'messages WHERE poster=? AND postdate > ?;');
				$stmt->execute([$user, time() - 60]);
				$count = $stmt->fetch(PDO::FETCH_NUM)[0];
				if ($count >= $rule['threshold']) {
					$triggered = true;
					$reason = "Flooding: {$count} messages per minute";
				}
				break;
				
			case 'caps_excessive':
				// Check for excessive caps
				$upper = preg_match_all('/[A-Z]/', $message);
				$total = strlen(preg_replace('/[^A-Za-z]/', '', $message));
				if ($total > 10 && $upper > 0) {
					$caps_percent = ($upper / $total) * 100;
					if ($caps_percent >= $rule['threshold']) {
						$triggered = true;
						$reason = "Excessive caps: {$caps_percent}%";
					}
				}
				break;
		}
		
		if ($triggered) {
			return [
				'rule' => $rule,
				'reason' => $reason
			];
		}
	}
	
	return null;
}

function apply_automod_action($user, $rule, $reason) {
	global $db, $I;
	
	$warnings = get_user_warnings($user);
	$warning_count = $warnings ? $warnings['warning_count'] : 0;
	
	// Escalation logic
	if ($rule['escalate'] && $warning_count > 0) {
		if ($warning_count == 1) {
			// Second offense: mute
			mute_user($user, 5, "Auto-mod: " . $reason);
			return "User muted (5 min) - Warning #2";
		} elseif ($warning_count == 2) {
			// Third offense: kick
			kick_chatter([$user], "Auto-mod: " . $reason, false);
			return "User kicked - Warning #3";
		} else {
			// Fourth+ offense: longer kick
			kick_chatter([$user], "Auto-mod: Multiple violations", true);
			return "User kicked with purge - Multiple warnings";
		}
	}
	
	// Apply rule action
	switch ($rule['action']) {
		case 'warn':
			add_user_warning($user, $reason, true);
			if ($rule['warn_message']) {
				add_system_message(sprintf($rule['warn_message'], htmlspecialchars($user)));
			}
			return "Warning issued";
			
		case 'mute':
			mute_user($user, $rule['duration'], "Auto-mod: " . $reason);
			return "User muted";
			
		case 'kick':
			kick_chatter([$user], "Auto-mod: " . $reason, false);
			return "User kicked";
			
		case 'delete':
			// Message will be blocked, just log
			log_mod_action('delete_message', $user, $reason, 0, true);
			return "Message blocked";
	}
	
	return null;
}

function mute_user($user, $duration_minutes, $reason) {
	global $db;
	if (!moderation_tables_exist()) {
		return;
	}
	$muted_until = time() + ($duration_minutes * 60);
	$stmt = $db->prepare('UPDATE ' . PREFIX . 'sessions SET muted_until=? WHERE nickname=?;');
	$stmt->execute([$muted_until, $user]);
	log_mod_action('mute', $user, $reason, $duration_minutes, false, null, 2);
}

function is_user_muted($user) {
	global $db;
	if (!moderation_tables_exist()) {
		return false;
	}
	try {
		$stmt = $db->prepare('SELECT muted_until FROM ' . PREFIX . 'sessions WHERE nickname=?;');
		$stmt->execute([$user]);
		$result = $stmt->fetch(PDO::FETCH_ASSOC);
		if ($result && $result['muted_until'] > time()) {
			return $result['muted_until'];
		}
	} catch (Exception $e) {
		// Column doesn't exist yet
	}
	return false;
}

function cleanup_moderation_system() {
	if (!moderation_tables_exist()) {
		return;
	}
	clear_expired_warnings();
	
	// Clear expired mutes
	global $db;
	try {
		$db->exec('UPDATE ' . PREFIX . 'sessions SET muted_until=0 WHERE muted_until > 0 AND muted_until < ' . time() . ';');
	} catch (PDOException $e) {
		// Column doesn't exist yet, skip cleanup
	}
}

function print_colours()
{
	global $I;
	// Prints a short list with selected named HTML colours and filters out illegible text colours for the given background.
	// It's a simple comparison of weighted grey values. This is not very accurate but gets the job done well enough.
	// name=>[colour, greyval(colour)]
	$colours = ['Beige' => ['F5F5DC', 242.25], 'Black' => ['000000', 0], 'Blue' => ['0000FF', 28.05], 'BlueViolet' => ['8A2BE2', 91.63], 'Brown' => ['A52A2A', 78.9], 'Cyan' => ['00FFFF', 178.5], 'DarkBlue' => ['00008B', 15.29], 'DarkGreen' => ['006400', 59], 'DarkRed' => ['8B0000', 41.7], 'DarkViolet' => ['9400D3', 67.61], 'DeepSkyBlue' => ['00BFFF', 140.74], 'Gold' => ['FFD700', 203.35], 'Grey' => ['808080', 128], 'Green' => ['008000', 75.52], 'HotPink' => ['FF69B4', 158.25], 'Indigo' => ['4B0082', 36.8], 'LightBlue' => ['ADD8E6', 204.64], 'LightGreen' => ['90EE90', 199.46], 'LimeGreen' => ['32CD32', 141.45], 'Magenta' => ['FF00FF', 104.55], 'Olive' => ['808000', 113.92], 'Orange' => ['FFA500', 173.85], 'OrangeRed' => ['FF4500', 117.21], 'Purple' => ['800080', 52.48], 'Red' => ['FF0000', 76.5], 'RoyalBlue' => ['4169E1', 106.2], 'SeaGreen' => ['2E8B57', 105.38], 'Sienna' => ['A0522D', 101.33], 'Silver' => ['C0C0C0', 192], 'Tan' => ['D2B48C', 184.6], 'Teal' => ['008080', 89.6], 'Violet' => ['EE82EE', 174.28], 'White' => ['FFFFFF', 255], 'Yellow' => ['FFFF00', 226.95], 'YellowGreen' => ['9ACD32', 172.65]];
	$greybg = greyval(get_setting('colbg'));
	foreach ($colours as $name => $colour) {
		if (abs($greybg - $colour[1]) > 75) {
			echo "<option value=\"$colour[0]\" style=\"color:#$colour[0];\">$I[$name]</option>";
		}
	}
}

function greyval($colour)
{
	return hexdec(substr($colour, 0, 2)) * .3 + hexdec(substr($colour, 2, 2)) * .59 + hexdec(substr($colour, 4, 2)) * .11;
}

function style_this($text, $styleinfo)
{
	// Ensure style has a color
	$styleinfo = ensure_color_in_style($styleinfo);
	return "<span style=\"$styleinfo\">$text</span>";
}

function ensure_color_in_style($style) {
	// Check if style has a color
	if (empty($style) || !preg_match('/#[0-9a-f]{6}/i', $style)) {
		// Generate random color
		$colors = ['FF0000', 'FF7F00', 'FFFF00', '00FF00', '0000FF', '4B0082', '9400D3', 
		           'FF1493', '00CED1', 'FFD700', '32CD32', 'FF69B4', '87CEEB', 'FFA500',
		           'BA55D3', '20B2AA', 'FF6347', '40E0D0', 'EE82EE', '00FA9A'];
		$random_color = $colors[array_rand($colors)];
		
		// Add color to style, keeping existing properties
		if (empty($style)) {
			$style = "color:#$random_color;";
		} else {
			$style = "color:#$random_color;" . $style;
		}
	}
	return $style;
}

//new function for clickablenicknames
function style_this_clickable($text, $styleinfo)
{
	// Ensure style has a color
	$styleinfo = ensure_color_in_style($styleinfo);
	return "<span style=\"$styleinfo\"><span class=\"clickablenickname\">$text</span></span>";
}

function check_init()
{
	global $db;
	return @$db->query('SELECT null FROM ' . PREFIX . 'settings LIMIT 1;');
}

// run every minute doing various database cleanup task
function cron()
{
	global $db;
	$time = time();
	if (get_setting('nextcron') > $time) {
		return;
	}
	update_setting('nextcron', $time + 10);
	
	// Auto-AFK: Mark users as AFK after 10 minutes of inactivity (without system message)
	$afk_threshold = $time - 600; // 10 minutes
	$db->exec('UPDATE ' . PREFIX . 'sessions SET afk=1, afk_message="Inactive" WHERE afk=0 AND lastpost<' . $afk_threshold . ' AND status>0;');
	
	// delete old sessions
	$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'sessions WHERE (status<=2 AND lastpost<(?-60*(SELECT value FROM ' . PREFIX . "settings WHERE setting='guestexpire'))) OR (status>2 AND lastpost<(?-60*(SELECT value FROM " . PREFIX . "settings WHERE setting='memberexpire')));");
	$stmt->execute([$time, $time]);
	// delete old messages
	$limit = get_setting('messagelimit');
	$stmt = $db->query('SELECT id FROM ' . PREFIX . "messages WHERE poststatus=1 AND roomid IS NULL ORDER BY id DESC LIMIT 1 OFFSET $limit;");
	if ($id = $stmt->fetch(PDO::FETCH_NUM)) {
		$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'messages WHERE id<=?;');
		$stmt->execute($id);
	}
	$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'messages WHERE id IN (SELECT * FROM (SELECT id FROM ' . PREFIX . 'messages WHERE postdate<(?-60*(SELECT value FROM ' . PREFIX . "settings WHERE setting='messageexpire'))) AS t);");
	$stmt->execute([$time]);
	// delete expired ignored people
	$result = $db->query('SELECT id FROM ' . PREFIX . 'ignored WHERE ign NOT IN (SELECT nickname FROM ' . PREFIX . 'sessions UNION SELECT nickname FROM ' . PREFIX . 'members UNION SELECT poster FROM ' . PREFIX . 'messages) OR ignby NOT IN (SELECT nickname FROM ' . PREFIX . 'sessions UNION SELECT nickname FROM ' . PREFIX . 'members UNION SELECT poster FROM ' . PREFIX . 'messages);');
	$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'ignored WHERE id=?;');
	while ($tmp = $result->fetch(PDO::FETCH_NUM)) {
		$stmt->execute($tmp);
	}
	// delete files that do not belong to any message
	$result = $db->query('SELECT id FROM ' . PREFIX . 'files WHERE postid NOT IN (SELECT id FROM ' . PREFIX . 'messages UNION SELECT postid FROM ' . PREFIX . 'inbox);');
	$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'files WHERE id=?;');
	while ($tmp = $result->fetch(PDO::FETCH_NUM)) {
		$stmt->execute($tmp);
	}
	// delete old notes
	$limit = get_setting('numnotes');
	// Modification for spare notes - keep most recent $limit of each type
	// Delete type 0 notes beyond limit
	$db->exec('DELETE FROM ' . PREFIX . "notes WHERE type=0 AND id NOT IN (SELECT id FROM " . PREFIX . "notes WHERE type=0 ORDER BY id DESC LIMIT $limit);");
	// Delete type 1 notes beyond limit
	$db->exec('DELETE FROM ' . PREFIX . "notes WHERE type=1 AND id NOT IN (SELECT id FROM " . PREFIX . "notes WHERE type=1 ORDER BY id DESC LIMIT $limit);");
	// Delete type 3 notes beyond limit
	$db->exec('DELETE FROM ' . PREFIX . "notes WHERE type=3 AND id NOT IN (SELECT id FROM " . PREFIX . "notes WHERE type=3 ORDER BY id DESC LIMIT $limit);");
	$result = $db->query('SELECT editedby, COUNT(*) AS cnt FROM ' . PREFIX . "notes WHERE type=2 GROUP BY editedby HAVING cnt>$limit;");
	$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'notes WHERE type=2 AND editedby=? AND id NOT IN (SELECT * FROM (SELECT id FROM ' . PREFIX . "notes WHERE type=2 AND editedby=? ORDER BY id DESC LIMIT $limit) AS t);");
	while ($tmp = $result->fetch(PDO::FETCH_NUM)) {
		$stmt->execute([$tmp[0], $tmp[0]]);
	}
	// delete old captchas
	$stmt = $db->prepare('DELETE FROM ' . PREFIX . 'captcha WHERE time<(?-(SELECT value FROM ' . PREFIX . "settings WHERE setting='captchatime'));");
	$stmt->execute([$time]);

	// modification expire rooms
	$result = $db->query('SELECT DISTINCT roomid FROM ' . PREFIX . 'sessions where roomid is not null;');
	while ($active = $result->fetch(PDO::FETCH_ASSOC)) {
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'rooms SET time=? WHERE id=?');
		$stmt->execute([$time, $active['roomid']]);
	}
	$expire = (int) get_setting('roomexpire') * 60;
	$stmt = $db->prepare('SELECT id FROM ' . PREFIX . 'rooms WHERE time<=? AND permanent=0');
	$stmt->execute([$time - $expire]);
	if (!$rooms = $stmt->fetchAll(PDO::FETCH_ASSOC)) {
		$rooms = [];
	}
	foreach ($rooms as $room) {
		remove_room(false, $room['id']);
	}

	// End modifications for rooms
}

function destroy_chat($C)
{
	global $I, $db, $memcached;
	setcookie(COOKIENAME, false);
	$_REQUEST['session'] = '';
	print_start('destory');
	$db->exec('DROP TABLE ' . PREFIX . 'captcha;');
	$db->exec('DROP TABLE ' . PREFIX . 'files;');
	$db->exec('DROP TABLE ' . PREFIX . 'filter;');
	$db->exec('DROP TABLE ' . PREFIX . 'ignored;');
	$db->exec('DROP TABLE ' . PREFIX . 'inbox;');
	$db->exec('DROP TABLE ' . PREFIX . 'linkfilter;');
	$db->exec('DROP TABLE ' . PREFIX . 'members;');
	$db->exec('DROP TABLE ' . PREFIX . 'messages;');
	$db->exec('DROP TABLE ' . PREFIX . 'notes;');
	$db->exec('DROP TABLE ' . PREFIX . 'sessions;');
	$db->exec('DROP TABLE ' . PREFIX . 'settings;');
	if (MEMCACHED) {
		$memcached->delete(DBNAME . '-' . PREFIX . 'filter');
		$memcached->delete(DBANEM . '-' . PREFIX . 'linkfilter');
		foreach ($C['settings'] as $setting) {
			$memcached->delete(DBNAME . '-' . PREFIX . "settings-$setting");
		}
		$memcached->delete(DBNAME . '-' . PREFIX . 'settings-dbversion');
		$memcached->delete(DBNAME . '-' . PREFIX . 'settings-msgencrypted');
		$memcached->delete(DBNAME . '-' . PREFIX . 'settings-nextcron');
	}
	echo "<h2>$I[destroyed]</h2><br><br><br>";
	echo form('setup') . submit($I['init']) . '</form>' . credit();
	print_end();
}

function init_chat()
{
	global $I, $db;
	$suwrite = '';
	if (check_init()) {
		$suwrite = $I['initdbexist'];
		$result = $db->query('SELECT null FROM ' . PREFIX . 'members WHERE status=8;');
		if ($result->fetch(PDO::FETCH_NUM)) {
			$suwrite = $I['initsuexist'];
		}
	} elseif (!preg_match('/^[a-z0-9]{1,20}$/i', $_REQUEST['sunick'])) {
		$suwrite = sprintf($I['invalnick'], 20, '^[A-Za-z1-9]*$');
	} elseif (mb_strlen($_REQUEST['supass']) < 5) {
		$suwrite = sprintf($I['invalpass'], 5, '.*');
	} elseif ($_REQUEST['supass'] !== $_REQUEST['supassc']) {
		$suwrite = $I['noconfirm'];
	} else {
		ignore_user_abort(true);
		set_time_limit(0);
		if (DBDRIVER === 0) { //MySQL
			$memengine = ' ENGINE=MEMORY';
			$diskengine = ' ENGINE=InnoDB';
			$charset = ' DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin';
			$primary = 'integer PRIMARY KEY AUTO_INCREMENT';
			$longtext = 'longtext';
		} elseif (DBDRIVER === 1) { //PostgreSQL
			$memengine = '';
			$diskengine = '';
			$charset = '';
			$primary = 'serial PRIMARY KEY';
			$longtext = 'text';
		} else { //SQLite
			$memengine = '';
			$diskengine = '';
			$charset = '';
			$primary = 'integer PRIMARY KEY';
			$longtext = 'text';
		}
		$db->exec('CREATE TABLE ' . PREFIX . "captcha (id $primary, time integer NOT NULL, code char(5) NOT NULL)$memengine$charset;");
		$db->exec('CREATE TABLE ' . PREFIX . "files (id $primary, postid integer NOT NULL UNIQUE, filename varchar(255) NOT NULL, hash char(40) NOT NULL, type varchar(255) NOT NULL, data $longtext NOT NULL)$diskengine$charset;");
		$db->exec('CREATE INDEX ' . PREFIX . 'files_hash ON ' . PREFIX . 'files(hash);');
		$db->exec('CREATE TABLE ' . PREFIX . "filter (id $primary, filtermatch varchar(255) NOT NULL, filterreplace text NOT NULL, allowinpm smallint NOT NULL, regex smallint NOT NULL, kick smallint NOT NULL, cs smallint NOT NULL, bot_reply smallint NOT NULL DEFAULT 0)$diskengine$charset;");
		$db->exec('CREATE TABLE ' . PREFIX . "botcommands (id $primary, command varchar(50) NOT NULL, response text NOT NULL, min_status smallint NOT NULL DEFAULT 0)$diskengine$charset;");
		$db->exec('CREATE TABLE ' . PREFIX . "ignored (id $primary, ign varchar(50) NOT NULL, ignby varchar(50) NOT NULL)$diskengine$charset;");
		$db->exec('CREATE INDEX ' . PREFIX . 'ign ON ' . PREFIX . 'ignored(ign);');
		$db->exec('CREATE INDEX ' . PREFIX . 'ignby ON ' . PREFIX . 'ignored(ignby);');
		$db->exec('CREATE TABLE ' . PREFIX . "inbox (id $primary, postdate integer NOT NULL, postid integer NOT NULL UNIQUE, poster varchar(50) NOT NULL, recipient varchar(50) NOT NULL, text text NOT NULL)$diskengine$charset;");
		$db->exec('CREATE INDEX ' . PREFIX . 'inbox_poster ON ' . PREFIX . 'inbox(poster);');
		$db->exec('CREATE INDEX ' . PREFIX . 'inbox_recipient ON ' . PREFIX . 'inbox(recipient);');
		$db->exec('CREATE TABLE ' . PREFIX . "linkfilter (id $primary, filtermatch varchar(255) NOT NULL, filterreplace varchar(255) NOT NULL, regex smallint NOT NULL)$diskengine$charset;");

		//MODIFICATION clickable nicknames
		/*REMOVE LATER
		$db->exec('CREATE TABLE ' . PREFIX . "members (id $primary, nickname varchar(50) NOT NULL UNIQUE, passhash varchar(255) NOT NULL, status smallint NOT NULL, refresh smallint NOT NULL, bgcolour char(6) NOT NULL, regedby varchar(50) DEFAULT '', lastlogin integer DEFAULT 0, timestamps smallint NOT NULL, embed smallint NOT NULL, incognito smallint NOT NULL, style varchar(255) NOT NULL, nocache smallint NOT NULL, tz varchar(255) NOT NULL, eninbox smallint NOT NULL, sortupdown smallint NOT NULL, hidechatters smallint NOT NULL, nocache_old smallint NOT NULL, clickablenicknames smallint NOT NULL DEFAULT 0)$diskengine$charset;");
		*/
		$db->exec('CREATE TABLE ' . PREFIX . "members (id $primary, nickname varchar(50) NOT NULL UNIQUE, passhash varchar(255) NOT NULL, status smallint NOT NULL, refresh smallint NOT NULL, bgcolour char(6) NOT NULL, regedby varchar(50) DEFAULT '', lastlogin integer DEFAULT 0, timestamps smallint NOT NULL, embed smallint NOT NULL, incognito smallint NOT NULL, style varchar(255) NOT NULL, nocache smallint NOT NULL, tz varchar(255) NOT NULL, eninbox smallint NOT NULL, sortupdown smallint NOT NULL, hidechatters smallint NOT NULL, nocache_old smallint NOT NULL)$diskengine$charset;");


		$db->exec('ALTER TABLE ' . PREFIX . 'inbox ADD FOREIGN KEY (recipient) REFERENCES ' . PREFIX . 'members(nickname) ON DELETE CASCADE ON UPDATE CASCADE;');
		$db->exec('CREATE TABLE ' . PREFIX . "messages (id $primary, postdate integer NOT NULL, poststatus smallint NOT NULL, poster varchar(50) NOT NULL, recipient varchar(50) NOT NULL, text text NOT NULL, delstatus smallint NOT NULL)$diskengine$charset;");
		$db->exec('CREATE INDEX ' . PREFIX . 'poster ON ' . PREFIX . 'messages (poster);');
		$db->exec('CREATE INDEX ' . PREFIX . 'recipient ON ' . PREFIX . 'messages(recipient);');
		$db->exec('CREATE INDEX ' . PREFIX . 'postdate ON ' . PREFIX . 'messages(postdate);');
		$db->exec('CREATE INDEX ' . PREFIX . 'poststatus ON ' . PREFIX . 'messages(poststatus);');
		$db->exec('CREATE TABLE ' . PREFIX . "notes (id $primary, type smallint NOT NULL, lastedited integer NOT NULL, editedby varchar(50) NOT NULL, text text NOT NULL)$diskengine$charset;");
		$db->exec('CREATE INDEX ' . PREFIX . 'notes_type ON ' . PREFIX . 'notes(type);');
		$db->exec('CREATE INDEX ' . PREFIX . 'notes_editedby ON ' . PREFIX . 'notes(editedby);');

		//MODIFICATION clickable nicknames
		/* REMOVE LATER
		$db->exec('CREATE TABLE ' . PREFIX . "sessions (id $primary, session char(32) NOT NULL UNIQUE, nickname varchar(50) NOT NULL UNIQUE, status smallint NOT NULL, refresh smallint NOT NULL, style varchar(255) NOT NULL, lastpost integer NOT NULL, passhash varchar(255) NOT NULL, postid char(6) NOT NULL DEFAULT '000000', useragent varchar(255) NOT NULL, kickmessage varchar(255) DEFAULT '', bgcolour char(6) NOT NULL, entry integer NOT NULL, timestamps smallint NOT NULL, embed smallint NOT NULL, incognito smallint NOT NULL, ip varchar(45) NOT NULL, nocache smallint NOT NULL, tz varchar(255) NOT NULL, eninbox smallint NOT NULL, sortupdown smallint NOT NULL, hidechatters smallint NOT NULL, nocache_old smallint NOT NULL, clickablenicknames smallint NOT NULL DEFAULT 0)$memengine$charset;");
		*/
		$db->exec('CREATE TABLE ' . PREFIX . "sessions (id $primary, session char(32) NOT NULL UNIQUE, nickname varchar(50) NOT NULL UNIQUE, status smallint NOT NULL, refresh smallint NOT NULL, style varchar(255) NOT NULL, lastpost integer NOT NULL, passhash varchar(255) NOT NULL, postid char(6) NOT NULL DEFAULT '000000', useragent varchar(255) NOT NULL, kickmessage varchar(255) DEFAULT '', bgcolour char(6) NOT NULL, entry integer NOT NULL, timestamps smallint NOT NULL, embed smallint NOT NULL, incognito smallint NOT NULL, ip varchar(45) NOT NULL, nocache smallint NOT NULL, tz varchar(255) NOT NULL, eninbox smallint NOT NULL, sortupdown smallint NOT NULL, hidechatters smallint NOT NULL, nocache_old smallint NOT NULL)$memengine$charset;");

		$db->exec('CREATE INDEX ' . PREFIX . 'status ON ' . PREFIX . 'sessions(status);');
		$db->exec('CREATE INDEX ' . PREFIX . 'lastpost ON ' . PREFIX . 'sessions(lastpost);');
		$db->exec('CREATE INDEX ' . PREFIX . 'incognito ON ' . PREFIX . 'sessions(incognito);');
		$db->exec('CREATE TABLE ' . PREFIX . "settings (setting varchar(50) NOT NULL PRIMARY KEY, value text NOT NULL)$diskengine$charset;");

		// Modification for chat rooms
		$db->exec('CREATE TABLE ' . PREFIX . "rooms (id $primary, name varchar(50) NOT NULL UNIQUE, access smallint NOT NULL, time integer NOT NULL, permanent smallint NOT NULL DEFAULT(0))$diskengine$charset;");
		$db->exec('ALTER TABLE ' . PREFIX . 'sessions ADD COLUMN roomid integer;');
		$db->exec('ALTER TABLE ' . PREFIX . 'messages ADD COLUMN roomid integer;');
		$db->exec('CREATE INDEX ' . PREFIX . 'sroomid ON ' . PREFIX . 'sessions(roomid);');
		$db->exec('CREATE INDEX ' . PREFIX . 'mroomid ON ' . PREFIX . 'messages(roomid);');
		$db->exec('ALTER TABLE ' . PREFIX . 'messages ADD COLUMN allrooms smallint NOT NULL DEFAULT(0);');


		$settings = [
			['guestaccess', '0'],
			['globalpass', ''],
			['englobalpass', '0'],
			['captcha', '0'],
			['dateformat', 'm-d H:i:s'],
			['rulestxt', ''],
			['msgencrypted', '0'],
			['dbversion', DBVERSION],
			['css', ''],
			['memberexpire', '60'],
			['guestexpire', '15'],
			['kickpenalty', '10'],
			['entrywait', '120'],
			['messageexpire', '14400'],
			['messagelimit', '150'],
			['maxmessage', 2000],
			['captchatime', '600'],
			['colbg', '000000'],
			['coltxt', 'FFFFFF'],
			['maxname', '20'],
			['minpass', '5'],
			['defaultrefresh', '20'],
			['dismemcaptcha', '0'],
			['suguests', '0'],
			['imgembed', '1'],
			['timestamps', '1'],
			['trackip', '0'],
			['captchachars', '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'],
			['memkick', '1'],
			['forceredirect', '0'],
			['redirect', ''],
			['incognito', '1'],
			['chatname', 'My Chat'],
			['topic', ''],
			['msgsendall', $I['sendallmsg']],
			['msgsendmem', $I['sendmemmsg']],
			['msgsendmod', $I['sendmodmsg']],
			['msgsendadm', $I['sendadmmsg']],
			['msgsendprv', $I['sendprvmsg']],
			['msgenter', $I['entermsg']],
			['msgexit', $I['exitmsg']],
			['msgmemreg', $I['memregmsg']],
			['msgsureg', $I['suregmsg']],
			['msgkick', $I['kickmsg']],
			['msgmultikick', $I['multikickmsg']],
			['msgallkick', $I['allkickmsg']],
			['msgclean', $I['cleanmsg']],
			['numnotes', '3'],
			['mailsender', 'www-data <www-data@localhost>'],
			['mailreceiver', 'Webmaster <webmaster@localhost>'],
			['sendmail', '0'],
			['modfallback', '1'],
			['guestreg', '0'],
			['disablepm', '0'],
			['disabletext', "<h1>$I[disabledtext]</h1>"],
			['defaulttz', 'UTC'],
			['eninbox', '0'],
			['passregex', '.*'],
			['nickregex', '^[A-Za-z0-9]*$'],
			['externalcss', ''],
			['enablegreeting', '0'],
			['sortupdown', '0'],
			['hidechatters', '0'],
			['enfileupload', '0'],
			['msgattache', '%2$s [%1$s]'],
			['maxuploadsize', '1024'],
			['nextcron', '0'],
			['personalnotes', '1'],
			['filtermodkick', '0'],

			//MODIFICATION Text field for links in settings and option to enable or disable links page.
			['links', ''],
			['linksenabled', '0'],

			//MODIFICATION option to enable or disable DEL-Buttons for members, if no mod is present. (DEL Buttons can bes used to delete messages within the message frame)
			['memdel', '0'],

			//MODIFICATION option to set galleryaccess for users depending on their rank(status).
			['galleryaccess', '10'],

			//MODIFICATION option to set forum button visibility for users depending on their rank(status).
			['forumbtnaccess', '10'],

			//MODIFICATION option to set link for the forum button 
			['forumbtnlink', 'forum/index.php'],

			//MODIFICATION frontpagetext (text for front page)
			['frontpagetext', ''],

			//MODIFICATION adminjoinleavemsg (admin join leave messages can be hidden)
			['adminjoinleavemsg', '1'],

			//MODIFICATION modsdeladminmsg (mods can delete admin messages)
			['modsdeladminmsg', '0'],

			//MODIFICATION clickablenicknamesglobal (nicknames at beginning of messages are clickable)
			['clickablenicknamesglobal', '1'],

			//MODIFICATION spare notes.
			['sparenotesname', ''],
			['sparenotesaccess', '10'],

			//MODIFICATION rooms
			['roomcreateaccess', '7'],
			['roomexpire', '10'],
			['channelvisinroom', '2']
		];
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'settings (setting, value) VALUES (?, ?);');
		foreach ($settings as $pair) {
			$stmt->execute($pair);
		}
		$reg = [
			'nickname'	=> $_REQUEST['sunick'],
			'passhash'	=> password_hash($_REQUEST['supass'], PASSWORD_DEFAULT),
			'status'	=> 8,
			'refresh'	=> 20,
			'bgcolour'	=> '000000',
			'timestamps'	=> 1,
			'style'		=> 'color:#FFFFFF;',
			'embed'		=> 1,
			'incognito'	=> 0,
			'nocache'	=> 0,
			'nocache_old'	=> 1,
			'tz'		=> 'UTC',
			'eninbox'	=> 0,
			'sortupdown'	=> 0,
			'hidechatters'	=> 0,
		];
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'members (nickname, passhash, status, refresh, bgcolour, timestamps, style, embed, incognito, nocache, tz, eninbox, sortupdown, hidechatters, nocache_old) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);');
		$stmt->execute([$reg['nickname'], $reg['passhash'], $reg['status'], $reg['refresh'], $reg['bgcolour'], $reg['timestamps'], $reg['style'], $reg['embed'], $reg['incognito'], $reg['nocache'], $reg['tz'], $reg['eninbox'], $reg['sortupdown'], $reg['hidechatters'], $reg['nocache_old']]);
		$suwrite = $I['susuccess'];
	}
	print_start('init');
	echo "<h2>$I[init]</h2><br><h3>$I[sulogin]</h3>$suwrite<br><br><br>";
	echo form('setup') . submit($I['initgosetup']) . '</form>' . credit();
	print_end();
}

function update_db()
{
	global $I, $db, $memcached;
	$dbversion = (int) get_setting('dbversion');
	$msgencrypted = (bool) get_setting('msgencrypted');
	if ($dbversion >= DBVERSION && $msgencrypted === MSGENCRYPTED) {
		return;
	}
	ignore_user_abort(true);
	set_time_limit(0);
	if (DBDRIVER === 0) { //MySQL
		$memengine = ' ENGINE=MEMORY';
		$diskengine = ' ENGINE=InnoDB';
		$charset = ' DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin';
		$primary = 'integer PRIMARY KEY AUTO_INCREMENT';
		$longtext = 'longtext';
	} elseif (DBDRIVER === 1) { //PostgreSQL
		$memengine = '';
		$diskengine = '';
		$charset = '';
		$primary = 'serial PRIMARY KEY';
		$longtext = 'text';
	} else { //SQLite
		$memengine = '';
		$diskengine = '';
		$charset = '';
		$primary = 'integer PRIMARY KEY';
		$longtext = 'text';
	}
	$msg = '';
	if ($dbversion < 2) {
		$db->exec('CREATE TABLE IF NOT EXISTS ' . PREFIX . "ignored (id integer unsigned NOT NULL PRIMARY KEY AUTO_INCREMENT, ignored varchar(50) NOT NULL, `by` varchar(50) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8;");
	}
	if ($dbversion < 3) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('rulestxt', '');");
	}
	if ($dbversion < 4) {
		$db->exec('ALTER TABLE ' . PREFIX . 'members ADD incognito smallint NOT NULL;');
	}
	if ($dbversion < 5) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('globalpass', '');");
	}
	if ($dbversion < 6) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('dateformat', 'm-d H:i:s');");
	}
	if ($dbversion < 7) {
		$db->exec('ALTER TABLE ' . PREFIX . 'captcha ADD code char(5) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL;');
	}
	if ($dbversion < 8) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('captcha', '0'), ('englobalpass', '0');");
		$ga = (int) get_setting('guestaccess');
		if ($ga === -1) {
			update_setting('guestaccess', 0);
			update_setting('englobalpass', 1);
		} elseif ($ga === 4) {
			update_setting('guestaccess', 1);
			update_setting('englobalpass', 2);
		}
	}
	if ($dbversion < 9) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting,value) VALUES ('msgencrypted', '0');");
		$db->exec('ALTER TABLE ' . PREFIX . 'settings MODIFY value varchar(20000) NOT NULL;');
		$db->exec('ALTER TABLE ' . PREFIX . 'messages DROP postid;');
	}
	if ($dbversion < 10) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('css', ''), ('memberexpire', '60'), ('guestexpire', '15'), ('kickpenalty', '10'), ('entrywait', '120'), ('messageexpire', '14400'), ('messagelimit', '150'), ('maxmessage', 2000), ('captchatime', '600');");
	}
	if ($dbversion < 11) {
		$db->exec('ALTER TABLE ' . PREFIX . 'captcha CHARACTER SET utf8 COLLATE utf8_bin;');
		$db->exec('ALTER TABLE ' . PREFIX . 'filter CHARACTER SET utf8 COLLATE utf8_bin;');
		$db->exec('ALTER TABLE ' . PREFIX . 'ignored CHARACTER SET utf8 COLLATE utf8_bin;');
		$db->exec('ALTER TABLE ' . PREFIX . 'messages CHARACTER SET utf8 COLLATE utf8_bin;');
		$db->exec('ALTER TABLE ' . PREFIX . 'notes CHARACTER SET utf8 COLLATE utf8_bin;');
		$db->exec('ALTER TABLE ' . PREFIX . 'settings CHARACTER SET utf8 COLLATE utf8_bin;');
		$db->exec('CREATE TABLE ' . PREFIX . "linkfilter (id integer unsigned NOT NULL PRIMARY KEY AUTO_INCREMENT, `match` varchar(255) NOT NULL, `replace` varchar(255) NOT NULL, regex smallint NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE utf8_bin;");
		$db->exec('ALTER TABLE ' . PREFIX . 'members ADD style varchar(255) NOT NULL;');
		$result = $db->query('SELECT * FROM ' . PREFIX . 'members;');
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'members SET style=? WHERE id=?;');
		$F = load_fonts();
		while ($temp = $result->fetch(PDO::FETCH_ASSOC)) {
			$style = "color:#$temp[colour];";
			if (isset($F[$temp['fontface']])) {
				$style .= $F[$temp['fontface']];
			}
			if (strpos($temp['fonttags'], 'i') !== false) {
				$style .= 'font-style:italic;';
			}
			if (strpos($temp['fonttags'], 'b') !== false) {
				$style .= 'font-weight:bold;';
			}
			$stmt->execute([$style, $temp['id']]);
		}
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('colbg', '000000'), ('coltxt', 'FFFFFF'), ('maxname', '20'), ('minpass', '5'), ('defaultrefresh', '20'), ('dismemcaptcha', '0'), ('suguests', '0'), ('imgembed', '1'), ('timestamps', '1'), ('trackip', '0'), ('captchachars', '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'), ('memkick', '1'), ('forceredirect', '0'), ('redirect', ''), ('incognito', '1');");
	}
	if ($dbversion < 12) {
		$db->exec('ALTER TABLE ' . PREFIX . 'captcha MODIFY code char(5) NOT NULL, DROP INDEX id, ADD PRIMARY KEY (id) USING BTREE;');
		$db->exec('ALTER TABLE ' . PREFIX . 'captcha ENGINE=MEMORY;');
		$db->exec('ALTER TABLE ' . PREFIX . 'filter MODIFY id integer unsigned NOT NULL AUTO_INCREMENT, MODIFY `match` varchar(255) NOT NULL, MODIFY replace varchar(20000) NOT NULL;');
		$db->exec('ALTER TABLE ' . PREFIX . 'ignored MODIFY ignored varchar(50) NOT NULL, MODIFY `by` varchar(50) NOT NULL, ADD INDEX(ignored), ADD INDEX(`by`);');
		$db->exec('ALTER TABLE ' . PREFIX . 'linkfilter MODIFY match varchar(255) NOT NULL, MODIFY replace varchar(255) NOT NULL;');
		$db->exec('ALTER TABLE ' . PREFIX . 'messages MODIFY poster varchar(50) NOT NULL, MODIFY recipient varchar(50) NOT NULL, MODIFY text varchar(20000) NOT NULL, ADD INDEX(poster), ADD INDEX(recipient), ADD INDEX(postdate), ADD INDEX(poststatus);');
		$db->exec('ALTER TABLE ' . PREFIX . 'notes MODIFY type char(5) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL, MODIFY editedby varchar(50) NOT NULL, MODIFY text varchar(20000) NOT NULL;');
		$db->exec('ALTER TABLE ' . PREFIX . 'settings MODIFY id integer unsigned NOT NULL, MODIFY setting varchar(50) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL, MODIFY value varchar(20000) NOT NULL;');
		$db->exec('ALTER TABLE ' . PREFIX . 'settings DROP PRIMARY KEY, DROP id, ADD PRIMARY KEY(setting);');
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('chatname', 'My Chat'), ('topic', ''), ('msgsendall', '$I[sendallmsg]'), ('msgsendmem', '$I[sendmemmsg]'), ('msgsendmod', '$I[sendmodmsg]'), ('msgsendadm', '$I[sendadmmsg]'), ('msgsendprv', '$I[sendprvmsg]'), ('numnotes', '3');");
	}
	if ($dbversion < 13) {
		$db->exec('ALTER TABLE ' . PREFIX . 'filter CHANGE `match` filtermatch varchar(255) NOT NULL, CHANGE `replace` filterreplace varchar(20000) NOT NULL;');
		$db->exec('ALTER TABLE ' . PREFIX . 'ignored CHANGE ignored ign varchar(50) NOT NULL, CHANGE `by` ignby varchar(50) NOT NULL;');
		$db->exec('ALTER TABLE ' . PREFIX . 'linkfilter CHANGE `match` filtermatch varchar(255) NOT NULL, CHANGE `replace` filterreplace varchar(255) NOT NULL;');
	}
	if ($dbversion < 14) {
		if (MEMCACHED) {
			$memcached->delete(DBNAME . '-' . PREFIX . 'members');
			$memcached->delete(DBNAME . '-' . PREFIX . 'ignored');
		}
		if (DBDRIVER === 0) { //MySQL - previously had a wrong SQL syntax and the captcha table was not created.
			$db->exec('CREATE TABLE IF NOT EXISTS ' . PREFIX . 'captcha (id integer unsigned NOT NULL PRIMARY KEY AUTO_INCREMENT, time integer unsigned NOT NULL, code char(5) NOT NULL) ENGINE=MEMORY DEFAULT CHARSET=utf8 COLLATE=utf8_bin;');
		}
	}
	if ($dbversion < 15) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('mailsender', 'www-data <www-data@localhost>'), ('mailreceiver', 'Webmaster <webmaster@localhost>'), ('sendmail', '0'), ('modfallback', '1'), ('guestreg', '0');");
	}
	if ($dbversion < 17) {
		$db->exec('ALTER TABLE ' . PREFIX . 'members ADD COLUMN nocache smallint NOT NULL DEFAULT 0;');
	}
	if ($dbversion < 18) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('disablepm', '0');");
	}
	if ($dbversion < 19) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('disabletext', '<h1>$I[disabledtext]</h1>');");
	}
	if ($dbversion < 20) {
		$db->exec('ALTER TABLE ' . PREFIX . 'members ADD COLUMN tz smallint NOT NULL DEFAULT 0;');
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('defaulttz', 'UTC');");
	}
	if ($dbversion < 21) {
		$db->exec('ALTER TABLE ' . PREFIX . 'members ADD COLUMN eninbox smallint NOT NULL DEFAULT 0;');
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('eninbox', '0');");
		if (DBDRIVER === 0) {
			$db->exec('CREATE TABLE ' . PREFIX . "inbox (id integer unsigned NOT NULL PRIMARY KEY AUTO_INCREMENT, postid integer unsigned NOT NULL, postdate integer unsigned NOT NULL, poster varchar(50) NOT NULL, recipient varchar(50) NOT NULL, text varchar(20000) NOT NULL, INDEX(postid), INDEX(poster), INDEX(recipient)) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;");
		} else {
			$db->exec('CREATE TABLE ' . PREFIX . "inbox (id $primary, postdate integer NOT NULL, postid integer NOT NULL, poster varchar(50) NOT NULL, recipient varchar(50) NOT NULL, text varchar(20000) NOT NULL);");
			$db->exec('CREATE INDEX ' . PREFIX . 'inbox_postid ON ' . PREFIX . 'inbox(postid);');
			$db->exec('CREATE INDEX ' . PREFIX . 'inbox_poster ON ' . PREFIX . 'inbox(poster);');
			$db->exec('CREATE INDEX ' . PREFIX . 'inbox_recipient ON ' . PREFIX . 'inbox(recipient);');
		}
	}
	if ($dbversion < 23) {
		$db->exec('DELETE FROM ' . PREFIX . "settings WHERE setting='enablejs';");
	}
	if ($dbversion < 25) {
		$db->exec('DELETE FROM ' . PREFIX . "settings WHERE setting='keeplimit';");
	}
	if ($dbversion < 26) {
		$db->exec('INSERT INTO ' . PREFIX . 'settings (setting, value) VALUES (\'passregex\', \'.*\'), (\'nickregex\', \'^[A-Za-z0-9]*$\');');
	}
	if ($dbversion < 27) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('externalcss', '');");
	}
	if ($dbversion < 28) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('enablegreeting', '0');");
	}
	if ($dbversion < 29) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('sortupdown', '0');");
		$db->exec('ALTER TABLE ' . PREFIX . 'members ADD COLUMN sortupdown smallint NOT NULL DEFAULT 0;');
	}
	if ($dbversion < 30) {
		$db->exec('ALTER TABLE ' . PREFIX . 'filter ADD COLUMN cs smallint NOT NULL DEFAULT 0;');
		if (MEMCACHED) {
			$memcached->delete(DBNAME . '-' . PREFIX . "filter");
		}
	}
	if ($dbversion < 31) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('hidechatters', '0');");
		$db->exec('ALTER TABLE ' . PREFIX . 'members ADD COLUMN hidechatters smallint NOT NULL DEFAULT 0;');
	}
	if ($dbversion < 32 && DBDRIVER === 0) {
		//recreate db in utf8mb4
		try {
			$olddb = new PDO('mysql:host=' . DBHOST . ';dbname=' . DBNAME, DBUSER, DBPASS, [PDO::ATTR_ERRMODE => PDO::ERRMODE_WARNING, PDO::ATTR_PERSISTENT => PERSISTENT]);
		} catch (PDOException $e) {
			send_fatal_error($I['nodb']);
		}
		$db->exec('DROP TABLE ' . PREFIX . 'captcha;');
		$db->exec('CREATE TABLE ' . PREFIX . "captcha (id integer PRIMARY KEY AUTO_INCREMENT, time integer NOT NULL, code char(5) NOT NULL) ENGINE=MEMORY DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;");
		$result = $olddb->query('SELECT filtermatch, filterreplace, allowinpm, regex, kick, cs FROM ' . PREFIX . 'filter;');
		$data = $result->fetchAll(PDO::FETCH_NUM);
		$db->exec('DROP TABLE ' . PREFIX . 'filter;');
		$db->exec('CREATE TABLE ' . PREFIX . "filter (id integer PRIMARY KEY AUTO_INCREMENT, filtermatch varchar(255) NOT NULL, filterreplace text NOT NULL, allowinpm smallint NOT NULL, regex smallint NOT NULL, kick smallint NOT NULL, cs smallint NOT NULL, bot_reply smallint NOT NULL DEFAULT 0) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;");
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'filter (filtermatch, filterreplace, allowinpm, regex, kick, cs) VALUES(?, ?, ?, ?, ?, ?);');
		foreach ($data as $tmp) {
			$stmt->execute($tmp);
		}
		$result = $olddb->query('SELECT ign, ignby FROM ' . PREFIX . 'ignored;');
		$data = $result->fetchAll(PDO::FETCH_NUM);
		$db->exec('DROP TABLE ' . PREFIX . 'ignored;');
		$db->exec('CREATE TABLE ' . PREFIX . "ignored (id integer PRIMARY KEY AUTO_INCREMENT, ign varchar(50) NOT NULL, ignby varchar(50) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;");
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'ignored (ign, ignby) VALUES(?, ?);');
		foreach ($data as $tmp) {
			$stmt->execute($tmp);
		}
		$db->exec('CREATE INDEX ' . PREFIX . 'ign ON ' . PREFIX . 'ignored(ign);');
		$db->exec('CREATE INDEX ' . PREFIX . 'ignby ON ' . PREFIX . 'ignored(ignby);');
		$result = $olddb->query('SELECT postdate, postid, poster, recipient, text FROM ' . PREFIX . 'inbox;');
		$data = $result->fetchAll(PDO::FETCH_NUM);
		$db->exec('DROP TABLE ' . PREFIX . 'inbox;');
		$db->exec('CREATE TABLE ' . PREFIX . "inbox (id integer PRIMARY KEY AUTO_INCREMENT, postdate integer NOT NULL, postid integer NOT NULL UNIQUE, poster varchar(50) NOT NULL, recipient varchar(50) NOT NULL, text text NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;");
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'inbox (postdate, postid, poster, recipient, text) VALUES(?, ?, ?, ?, ?);');
		foreach ($data as $tmp) {
			$stmt->execute($tmp);
		}
		$db->exec('CREATE INDEX ' . PREFIX . 'inbox_poster ON ' . PREFIX . 'inbox(poster);');
		$db->exec('CREATE INDEX ' . PREFIX . 'inbox_recipient ON ' . PREFIX . 'inbox(recipient);');
		$result = $olddb->query('SELECT filtermatch, filterreplace, regex FROM ' . PREFIX . 'linkfilter;');
		$data = $result->fetchAll(PDO::FETCH_NUM);
		$db->exec('DROP TABLE ' . PREFIX . 'linkfilter;');
		$db->exec('CREATE TABLE ' . PREFIX . "linkfilter (id integer PRIMARY KEY AUTO_INCREMENT, filtermatch varchar(255) NOT NULL, filterreplace varchar(255) NOT NULL, regex smallint NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;");
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'linkfilter (filtermatch, filterreplace, regex) VALUES(?, ?, ?);');
		foreach ($data as $tmp) {
			$stmt->execute($tmp);
		}
		$result = $olddb->query('SELECT nickname, passhash, status, refresh, bgcolour, regedby, lastlogin, timestamps, embed, incognito, style, nocache, tz, eninbox, sortupdown, hidechatters FROM ' . PREFIX . 'members;');
		$data = $result->fetchAll(PDO::FETCH_NUM);
		$db->exec('DROP TABLE ' . PREFIX . 'members;');
		$db->exec('CREATE TABLE ' . PREFIX . "members (id integer PRIMARY KEY AUTO_INCREMENT, nickname varchar(50) NOT NULL UNIQUE, passhash char(32) NOT NULL, status smallint NOT NULL, refresh smallint NOT NULL, bgcolour char(6) NOT NULL, regedby varchar(50) DEFAULT '', lastlogin integer DEFAULT 0, timestamps smallint NOT NULL, embed smallint NOT NULL, incognito smallint NOT NULL, style varchar(255) NOT NULL, nocache smallint NOT NULL, tz smallint NOT NULL, eninbox smallint NOT NULL, sortupdown smallint NOT NULL, hidechatters smallint NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;");
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'members (nickname, passhash, status, refresh, bgcolour, regedby, lastlogin, timestamps, embed, incognito, style, nocache, tz, eninbox, sortupdown, hidechatters) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);');
		foreach ($data as $tmp) {
			$stmt->execute($tmp);
		}
		$result = $olddb->query('SELECT postdate, poststatus, poster, recipient, text, delstatus FROM ' . PREFIX . 'messages;');
		$data = $result->fetchAll(PDO::FETCH_NUM);
		$db->exec('DROP TABLE ' . PREFIX . 'messages;');
		$db->exec('CREATE TABLE ' . PREFIX . "messages (id integer PRIMARY KEY AUTO_INCREMENT, postdate integer NOT NULL, poststatus smallint NOT NULL, poster varchar(50) NOT NULL, recipient varchar(50) NOT NULL, text text NOT NULL, delstatus smallint NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;");
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'messages (postdate, poststatus, poster, recipient, text, delstatus) VALUES(?, ?, ?, ?, ?, ?);');
		foreach ($data as $tmp) {
			$stmt->execute($tmp);
		}
		$db->exec('CREATE INDEX ' . PREFIX . 'poster ON ' . PREFIX . 'messages (poster);');
		$db->exec('CREATE INDEX ' . PREFIX . 'recipient ON ' . PREFIX . 'messages(recipient);');
		$db->exec('CREATE INDEX ' . PREFIX . 'postdate ON ' . PREFIX . 'messages(postdate);');
		$db->exec('CREATE INDEX ' . PREFIX . 'poststatus ON ' . PREFIX . 'messages(poststatus);');
		$result = $olddb->query('SELECT type, lastedited, editedby, text FROM ' . PREFIX . 'notes;');
		$data = $result->fetchAll(PDO::FETCH_NUM);
		$db->exec('DROP TABLE ' . PREFIX . 'notes;');
		$db->exec('CREATE TABLE ' . PREFIX . "notes (id integer PRIMARY KEY AUTO_INCREMENT, type char(5) NOT NULL, lastedited integer NOT NULL, editedby varchar(50) NOT NULL, text text NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;");
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'notes (type, lastedited, editedby, text) VALUES(?, ?, ?, ?);');
		foreach ($data as $tmp) {
			$stmt->execute($tmp);
		}
		$result = $olddb->query('SELECT setting, value FROM ' . PREFIX . 'settings;');
		$data = $result->fetchAll(PDO::FETCH_NUM);
		$db->exec('DROP TABLE ' . PREFIX . 'settings;');
		$db->exec('CREATE TABLE ' . PREFIX . "settings (setting varchar(50) NOT NULL PRIMARY KEY, value text NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;");
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'settings (setting, value) VALUES(?, ?);');
		foreach ($data as $tmp) {
			$stmt->execute($tmp);
		}
	}
	if ($dbversion < 33) {
		$db->exec('CREATE TABLE ' . PREFIX . "files (id $primary, postid integer NOT NULL UNIQUE, filename varchar(255) NOT NULL, hash char(40) NOT NULL, type varchar(255) NOT NULL, data $longtext NOT NULL)$diskengine$charset;");
		$db->exec('CREATE INDEX ' . PREFIX . 'files_hash ON ' . PREFIX . 'files(hash);');
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('enfileupload', '0'), ('msgattache', '%2\$s [%1\$s]'), ('maxuploadsize', '1024');");
	}
	if ($dbversion < 34) {
		$msg .= "<br>$I[cssupdate]";
		$db->exec('ALTER TABLE ' . PREFIX . 'members ADD COLUMN nocache_old smallint NOT NULL DEFAULT 0;');
	}
	if ($dbversion < 37) {
		$db->exec('ALTER TABLE ' . PREFIX . 'members MODIFY tz varchar(255) NOT NULL;');
		$db->exec('UPDATE ' . PREFIX . "members SET tz='UTC';");
		$db->exec('UPDATE ' . PREFIX . "settings SET value='UTC' WHERE setting='defaulttz';");
	}
	if ($dbversion < 38) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('nextcron', '0');");
		$db->exec('DELETE FROM ' . PREFIX . 'inbox WHERE recipient NOT IN (SELECT nickname FROM ' . PREFIX . 'members);'); // delete inbox of members who deleted themselves
	}
	if ($dbversion < 39) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('personalnotes', '1');");
		$result = $db->query('SELECT type, id FROM ' . PREFIX . 'notes;');
		while ($tmp = $result->fetch(PDO::FETCH_NUM)) {
			if ($tmp[0] === 'admin') {
				$tmp[0] = 0;
			} else {
				$tmp[0] = 1;
			}
			$data[] = $tmp;
		}
		$db->exec('ALTER TABLE ' . PREFIX . 'notes MODIFY type smallint NOT NULL;');
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'notes SET type=? WHERE id=?;');
		foreach ($data as $tmp) {
			$stmt->execute($tmp);
		}
		$db->exec('CREATE INDEX ' . PREFIX . 'notes_type ON ' . PREFIX . 'notes(type);');
		$db->exec('CREATE INDEX ' . PREFIX . 'notes_editedby ON ' . PREFIX . 'notes(editedby);');
	}
	if ($dbversion < 41) {
		$db->exec('DROP TABLE ' . PREFIX . 'sessions;');
		$db->exec('CREATE TABLE ' . PREFIX . "sessions (id $primary, session char(32) NOT NULL UNIQUE, nickname varchar(50) NOT NULL UNIQUE, status smallint NOT NULL, refresh smallint NOT NULL, style varchar(255) NOT NULL, lastpost integer NOT NULL, passhash varchar(255) NOT NULL, postid char(6) NOT NULL DEFAULT '000000', useragent varchar(255) NOT NULL, kickmessage varchar(255) DEFAULT '', bgcolour char(6) NOT NULL, entry integer NOT NULL, timestamps smallint NOT NULL, embed smallint NOT NULL, incognito smallint NOT NULL, ip varchar(45) NOT NULL, nocache smallint NOT NULL, tz varchar(255) NOT NULL, eninbox smallint NOT NULL, sortupdown smallint NOT NULL, hidechatters smallint NOT NULL, nocache_old smallint NOT NULL)$memengine$charset;");
		$db->exec('CREATE INDEX ' . PREFIX . 'status ON ' . PREFIX . 'sessions(status);');
		$db->exec('CREATE INDEX ' . PREFIX . 'lastpost ON ' . PREFIX . 'sessions(lastpost);');
		$db->exec('CREATE INDEX ' . PREFIX . 'incognito ON ' . PREFIX . 'sessions(incognito);');
		$result = $db->query('SELECT nickname, passhash, status, refresh, bgcolour, regedby, lastlogin, timestamps, embed, incognito, style, nocache, nocache_old, tz, eninbox, sortupdown, hidechatters FROM ' . PREFIX . 'members;');
		$members = $result->fetchAll(PDO::FETCH_NUM);
		$result = $db->query('SELECT postdate, postid, poster, recipient, text FROM ' . PREFIX . 'inbox;');
		$inbox = $result->fetchAll(PDO::FETCH_NUM);
		$db->exec('DROP TABLE ' . PREFIX . 'inbox;');
		$db->exec('DROP TABLE ' . PREFIX . 'members;');
		$db->exec('CREATE TABLE ' . PREFIX . "members (id $primary, nickname varchar(50) NOT NULL UNIQUE, passhash varchar(255) NOT NULL, status smallint NOT NULL, refresh smallint NOT NULL, bgcolour char(6) NOT NULL, regedby varchar(50) DEFAULT '', lastlogin integer DEFAULT 0, timestamps smallint NOT NULL, embed smallint NOT NULL, incognito smallint NOT NULL, style varchar(255) NOT NULL, nocache smallint NOT NULL, nocache_old smallint NOT NULL, tz varchar(255) NOT NULL, eninbox smallint NOT NULL, sortupdown smallint NOT NULL, hidechatters smallint NOT NULL)$diskengine$charset");
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'members (nickname, passhash, status, refresh, bgcolour, regedby, lastlogin, timestamps, embed, incognito, style, nocache, nocache_old, tz, eninbox, sortupdown, hidechatters) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);');
		foreach ($members as $tmp) {
			$stmt->execute($tmp);
		}
		$db->exec('CREATE TABLE ' . PREFIX . "inbox (id $primary, postdate integer NOT NULL, postid integer NOT NULL UNIQUE, poster varchar(50) NOT NULL, recipient varchar(50) NOT NULL, text text NOT NULL)$diskengine$charset;");
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'inbox (postdate, postid, poster, recipient, text) VALUES(?, ?, ?, ?, ?);');
		foreach ($inbox as $tmp) {
			$stmt->execute($tmp);
		}
		$db->exec('CREATE INDEX ' . PREFIX . 'inbox_poster ON ' . PREFIX . 'inbox(poster);');
		$db->exec('CREATE INDEX ' . PREFIX . 'inbox_recipient ON ' . PREFIX . 'inbox(recipient);');
		$db->exec('ALTER TABLE ' . PREFIX . 'inbox ADD FOREIGN KEY (recipient) REFERENCES ' . PREFIX . 'members(nickname) ON DELETE CASCADE ON UPDATE CASCADE;');
	}
	if ($dbversion < 42) {
		$db->exec('INSERT IGNORE INTO ' . PREFIX . "settings (setting, value) VALUES ('filtermodkick', '1');");
	}
	//MODIFICATION Text field for links in settings and option to enable or disable links page.
	if ($dbversion < 1142) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('links', '');");
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('linksenabled', '0');");
	}
	//MODIFICATION option to enable or disable DEL-Buttons for members, if no mod is present. (DEL Buttons can bes used to delete messages within the message frame)
	if ($dbversion < 1242) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('memdel', '0');");
	}

	//MODIFICATION clickable nicknames
	/* REMOVE LATER
	 if($dbversion<1243){
     $db->exec('ALTER TABLE ' . PREFIX . 'sessions ADD COLUMN clickablenicknames smallint NOT NULL DEFAULT 0;');
     $db->exec('ALTER TABLE ' . PREFIX . 'members ADD COLUMN clickablenicknames smallint NOT NULL DEFAULT 0;');
    }
    */

	//MODIFICATION option to set galleryaccess and forum button visibility for users depending on their rank(status).
	if ($dbversion < 1342) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('galleryaccess', '10');");
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('forumbtnaccess', '10');");
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('forumbtnlink', 'forum/index.php');");
	}
	//MODIFICATION fontpgagetext - Text field for text on front page of the chat.
	if ($dbversion < 1442) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('frontpagetext', '');");
	}
	//MODIFICATION modsdeladminmsg - mods can delete admin messages. To be more precise: Staff members can delete messages of higher ranked staff members, bot only those messages that the lower ranked staff member can read (where status <= poststatus).
	if ($dbversion < 1542) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('modsdeladminmsg', '0');");
	}
	//MODIFICATION adminjoinleavemsg to not create a system message if an admins arrives or leaves the chat
	if ($dbversion < 1642) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('adminjoinleavemsg', '1');");
	}

	//MODIFICATION clickablenicknamesglobal (nicknames at beginning of messages are clickable)
	if ($dbversion < 1742) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('clickablenicknamesglobal', '1');");
	}
	// Modification spare notes
	if ($dbversion < 2100) {
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('sparenotesaccess', '10');");
		$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('sparenotesname', '');");
	}
	// Modification for rooms
	if ($dbversion < 2101) {
		$db->exec('INSERT IGNORE INTO ' . PREFIX . "settings (setting, value) VALUES ('roomcreateaccess', '7');");
		$db->exec('CREATE TABLE ' . PREFIX . "rooms (id $primary, name varchar(50) NOT NULL UNIQUE, access smallint NOT NULL, time integer NOT NULL)$diskengine$charset");
		$db->exec('ALTER TABLE ' . PREFIX . 'sessions ADD COLUMN roomid integer;');
		$db->exec('ALTER TABLE ' . PREFIX . 'messages ADD COLUMN roomid integer;');
		$db->exec('CREATE INDEX ' . PREFIX . 'sroomid ON ' . PREFIX . 'sessions(roomid);');
		$db->exec('CREATE INDEX ' . PREFIX . 'mroomid ON ' . PREFIX . 'messages(roomid);');
		$db->exec('INSERT IGNORE INTO ' . PREFIX . "settings (setting, value) VALUES ('roomexpire', '10');");
	}
	// Modification for rooms
	if ($dbversion < 2102) {
		$db->exec('ALTER TABLE ' . PREFIX . 'rooms ADD COLUMN permanent smallint NOT NULL DEFAULT(0);');
		$db->exec('ALTER TABLE ' . PREFIX . 'messages ADD COLUMN allrooms smallint NOT NULL DEFAULT(0);');
	}
	// Modification for rooms
	if ($dbversion < 2103) {
		$db->exec('INSERT IGNORE INTO ' . PREFIX . "settings (setting, value) VALUES ('channelvisinroom', '2');");
	}
	
	// Advanced Moderation System - Mod Actions Log
	if ($dbversion < 2104) {
		try {
			$db->exec('CREATE TABLE IF NOT EXISTS ' . PREFIX . "mod_actions (
				id $primary, 
				action_type varchar(50) NOT NULL,
				moderator varchar(50) NOT NULL,
				target_user varchar(50) NOT NULL,
				reason text NOT NULL,
				action_date integer NOT NULL,
				duration integer DEFAULT 0,
				auto_generated smallint NOT NULL DEFAULT 0,
				related_message_id integer DEFAULT NULL,
				severity smallint NOT NULL DEFAULT 1
			)$diskengine$charset;");
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'mod_actions_target ON ' . PREFIX . 'mod_actions(target_user);');
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'mod_actions_moderator ON ' . PREFIX . 'mod_actions(moderator);');
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'mod_actions_date ON ' . PREFIX . 'mod_actions(action_date);');
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'mod_actions_type ON ' . PREFIX . 'mod_actions(action_type);');
		} catch (Exception $e) {
			// Migration failed, will retry on next load
		}
	}
	
	// Appeals System
	if ($dbversion < 2105) {
		try {
			$db->exec('CREATE TABLE IF NOT EXISTS ' . PREFIX . "appeals (
				id $primary,
				user varchar(50) NOT NULL,
				action_id integer NOT NULL,
				reason text NOT NULL,
				status varchar(20) NOT NULL DEFAULT 'pending',
				submitted_date integer NOT NULL,
				reviewed_by varchar(50) DEFAULT NULL,
				review_date integer DEFAULT NULL,
				decision text DEFAULT NULL
			)$diskengine$charset;");
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'appeals_user ON ' . PREFIX . 'appeals(user);');
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'appeals_status ON ' . PREFIX . 'appeals(status);');
		} catch (Exception $e) {
			// Migration failed, will retry on next load
		}
	}
	
	// Auto-Moderation Rules
	if ($dbversion < 2106) {
		try {
			$db->exec('CREATE TABLE IF NOT EXISTS ' . PREFIX . "automod_rules (
				id $primary,
				rule_name varchar(100) NOT NULL,
				rule_type varchar(50) NOT NULL,
				threshold integer NOT NULL,
				action varchar(50) NOT NULL,
				duration integer NOT NULL DEFAULT 0,
				enabled smallint NOT NULL DEFAULT 1,
				created_by varchar(50) NOT NULL,
				created_date integer NOT NULL,
				escalate smallint NOT NULL DEFAULT 0,
				warn_message text DEFAULT NULL
			)$diskengine$charset;");
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'automod_enabled ON ' . PREFIX . 'automod_rules(enabled);');
		} catch (Exception $e) {
			// Migration failed, will retry on next load
		}
	}
	
	// User Warnings Counter and Mute Column
	if ($dbversion < 2107) {
		try {
			$db->exec('CREATE TABLE IF NOT EXISTS ' . PREFIX . "user_warnings (
				id $primary,
				user varchar(50) NOT NULL,
				warning_count integer NOT NULL DEFAULT 0,
				last_warning integer NOT NULL,
				expires integer DEFAULT NULL
			)$diskengine$charset;");
			$db->exec('CREATE UNIQUE INDEX IF NOT EXISTS ' . PREFIX . 'user_warnings_user ON ' . PREFIX . 'user_warnings(user);');
			
			// Add muted_until to sessions table (might already exist)
			try {
				$db->exec('ALTER TABLE ' . PREFIX . 'sessions ADD COLUMN muted_until integer DEFAULT 0;');
			} catch (Exception $e) {
				// Column might already exist
			}
			
			// Add warning_level settings (check if exists first)
			$check = $db->query("SELECT COUNT(*) FROM " . PREFIX . "settings WHERE setting='warning_expiry_days';");
			if ($check->fetch(PDO::FETCH_NUM)[0] == 0) {
				$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('warning_expiry_days', '30');");
			}
			$check = $db->query("SELECT COUNT(*) FROM " . PREFIX . "settings WHERE setting='automod_enabled';");
			if ($check->fetch(PDO::FETCH_NUM)[0] == 0) {
				$db->exec('INSERT INTO ' . PREFIX . "settings (setting, value) VALUES ('automod_enabled', '1');");
			}
		} catch (Exception $e) {
			// Migration failed, will retry on next load
		}
	}
	
	// Dot bot integration - add bot_reply to filters
	if ($dbversion < 2108) {
		try {
			$db->exec('ALTER TABLE ' . PREFIX . 'filter ADD COLUMN bot_reply smallint NOT NULL DEFAULT 0;');
			if (MEMCACHED) {
				$memcached->delete(DBNAME . '-' . PREFIX . "filter");
			}
		} catch (Exception $e) {
			// Column might already exist
		}
	}
	
	// Bot commands table - add custom bot commands feature
	if ($dbversion < 2109) {
		try {
			if (DBDRIVER === 0) { // MySQL
				$db->exec('CREATE TABLE IF NOT EXISTS ' . PREFIX . 'botcommands (id integer PRIMARY KEY AUTO_INCREMENT, command varchar(50) NOT NULL, response text NOT NULL, min_status smallint NOT NULL DEFAULT 0) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;');
			} else { // SQLite/PostgreSQL
				$db->exec('CREATE TABLE IF NOT EXISTS ' . PREFIX . 'botcommands (id INTEGER PRIMARY KEY AUTOINCREMENT, command varchar(50) NOT NULL, response text NOT NULL, min_status smallint NOT NULL DEFAULT 0);');
			}
			if (MEMCACHED) {
				$memcached->delete(DBNAME . '-' . PREFIX . "botcommands");
			}
		} catch (Exception $e) {
			// Table might already exist
		}
	}
	
	// Soft delete - add deleted column to messages table
	if ($dbversion < 2110) {
		try {
			$db->exec('ALTER TABLE ' . PREFIX . 'messages ADD COLUMN deleted smallint NOT NULL DEFAULT 0;');
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'messages_deleted ON ' . PREFIX . 'messages(deleted);');
		} catch (Exception $e) {
			// Column might already exist
		}
	}
	
	// Audit logging system - comprehensive action tracking
	if ($dbversion < 2111) {
		try {
			$db->exec('CREATE TABLE IF NOT EXISTS ' . PREFIX . 'audit_log (
				id ' . $primary . ',
				timestamp integer NOT NULL,
				actor varchar(50) NOT NULL,
				actor_status smallint NOT NULL,
				action varchar(50) NOT NULL,
				target varchar(50),
				target_status smallint,
				details text,
				ip_address varchar(45)
			)' . $diskengine . $charset . ';');
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'audit_timestamp ON ' . PREFIX . 'audit_log(timestamp);');
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'audit_actor ON ' . PREFIX . 'audit_log(actor);');
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'audit_action ON ' . PREFIX . 'audit_log(action);');
		} catch (Exception $e) {
			// Table might already exist
		}
	}
	
	// Username history - track nickname changes
	if ($dbversion < 2112) {
		try {
			$db->exec('CREATE TABLE IF NOT EXISTS ' . PREFIX . 'username_history (
				id ' . $primary . ',
				old_username varchar(50) NOT NULL,
				new_username varchar(50) NOT NULL,
				changed_date integer NOT NULL,
				changed_by varchar(50),
				reason text
			)' . $diskengine . $charset . ';');
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'username_old ON ' . PREFIX . 'username_history(old_username);');
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'username_new ON ' . PREFIX . 'username_history(new_username);');
		} catch (Exception $e) {
			// Table might already exist
		}
	}
	
	// User history - consolidated action log per user
	if ($dbversion < 2113) {
		try {
			$db->exec('CREATE TABLE IF NOT EXISTS ' . PREFIX . 'user_history (
				id ' . $primary . ',
				username varchar(50) NOT NULL,
				action_type varchar(50) NOT NULL,
				action_date integer NOT NULL,
				actor varchar(50) NOT NULL,
				details text,
				severity smallint DEFAULT 1,
				expired smallint DEFAULT 0
			)' . $diskengine . $charset . ';');
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'user_history_username ON ' . PREFIX . 'user_history(username);');
			$db->exec('CREATE INDEX IF NOT EXISTS ' . PREFIX . 'user_history_date ON ' . PREFIX . 'user_history(action_date);');
		} catch (Exception $e) {
			// Table might already exist
		}
	}
	
	// Filter metadata - track changes and ordering
	if ($dbversion < 2114) {
		try {
			$db->exec('ALTER TABLE ' . PREFIX . 'filter ADD COLUMN last_changed_by varchar(50);');
			$db->exec('ALTER TABLE ' . PREFIX . 'filter ADD COLUMN last_changed_date integer;');
			$db->exec('ALTER TABLE ' . PREFIX . 'filter ADD COLUMN filter_order integer DEFAULT 999;');
			$db->exec('ALTER TABLE ' . PREFIX . 'filter ADD COLUMN warn smallint DEFAULT 0;');
			$db->exec('ALTER TABLE ' . PREFIX . 'filter ADD COLUMN staff_only smallint DEFAULT 0;');
		} catch (Exception $e) {
			// Columns might already exist
		}
	}
	
	// Member inbox settings - control who can PM
	if ($dbversion < 2115) {
		try {
			$db->exec('ALTER TABLE ' . PREFIX . 'members ADD COLUMN inbox_level smallint DEFAULT 5;');
			// 1 = everyone, 3 = members+, 5 = staff+
		} catch (Exception $e) {
			// Column might already exist
		}
	}
	
	// AFK system - track away status
	if ($dbversion < 2116) {
		try {
			$db->exec('ALTER TABLE ' . PREFIX . 'sessions ADD COLUMN afk smallint NOT NULL DEFAULT 0;');
			$db->exec('ALTER TABLE ' . PREFIX . 'sessions ADD COLUMN afk_message text;');
		} catch (Exception $e) {
			// Columns might already exist
		}
	}
	
	// User history severity tracking
	if ($dbversion < 2117) {
		try {
			$db->exec('ALTER TABLE ' . PREFIX . 'user_history ADD COLUMN severity smallint DEFAULT 1;');
		} catch (Exception $e) {
			// Column might already exist
		}
	}
	
	update_setting('dbversion', DBVERSION);
	if ($msgencrypted !== MSGENCRYPTED) {
		if (!extension_loaded('sodium')) {
			send_fatal_error($I['sodiumextrequired']);
		}
		$result = $db->query('SELECT id, text FROM ' . PREFIX . 'messages;');
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'messages SET text=? WHERE id=?;');
		while ($message = $result->fetch(PDO::FETCH_ASSOC)) {
			if (MSGENCRYPTED) {
				$message['text'] = base64_encode(sodium_crypto_aead_aes256gcm_encrypt($message['text'], '', AES_IV, ENCRYPTKEY));
			} else {
				$message['text'] = sodium_crypto_aead_aes256gcm_decrypt(base64_decode($message['text']), null, AES_IV, ENCRYPTKEY);
			}
			$stmt->execute([$message['text'], $message['id']]);
		}
		$result = $db->query('SELECT id, text FROM ' . PREFIX . 'notes;');
		$stmt = $db->prepare('UPDATE ' . PREFIX . 'notes SET text=? WHERE id=?;');
		while ($message = $result->fetch(PDO::FETCH_ASSOC)) {
			if (MSGENCRYPTED) {
				$message['text'] = base64_encode(sodium_crypto_aead_aes256gcm_encrypt($message['text'], '', AES_IV, ENCRYPTKEY));
			} else {
				$message['text'] = sodium_crypto_aead_aes256gcm_decrypt(base64_decode($message['text']), null, AES_IV, ENCRYPTKEY);
			}
			$stmt->execute([$message['text'], $message['id']]);
		}
		update_setting('msgencrypted', (int) MSGENCRYPTED);
	}
	send_update($msg);
}

function get_setting($setting)
{
	global $db, $memcached;
	if (!MEMCACHED || !$value = $memcached->get(DBNAME . '-' . PREFIX . "settings-$setting")) {
		$stmt = $db->prepare('SELECT value FROM ' . PREFIX . 'settings WHERE setting=?;');
		$stmt->execute([$setting]);
		$stmt->bindColumn(1, $value);
		$stmt->fetch(PDO::FETCH_BOUND);
		if (MEMCACHED) {
			$memcached->set(DBNAME . '-' . PREFIX . "settings-$setting", $value);
		}
	}
	return $value;
}

function update_setting($setting, $value)
{
	global $db, $memcached;
	$stmt = $db->prepare('UPDATE ' . PREFIX . 'settings SET value=? WHERE setting=?;');
	$stmt->execute([$value, $setting]);
	if (MEMCACHED) {
		$memcached->set(DBNAME . '-' . PREFIX . "settings-$setting", $value);
	}
}

// ============================================================================
// PERMISSION SYSTEM - Centralized permission checking functions
// ============================================================================

/**
 * Get human-readable status name
 * @param int $status Status level
 * @return string Status name
 */
function get_status_name($status)
{
	$names = [
		0 => 'Banned',
		1 => 'Guest',
		2 => 'Applicant',
		3 => 'Member',
		4 => 'Member+',
		5 => 'Moderator',
		6 => 'Chat Admin',
		7 => 'Service Admin',
		8 => 'System Admin',
		10 => 'Bot'
	];
	return $names[$status] ?? 'Unknown';
}

/**
 * Log action to audit log
 * @param string $actor Username performing action
 * @param int $actor_status Status of actor
 * @param string $action Action type
 * @param string|null $target Target username (if applicable)
 * @param int|null $target_status Status of target (if applicable)
 * @param string|null $details Additional details
 */
function log_audit($actor, $actor_status, $action, $target = null, $target_status = null, $details = null)
{
	global $db;
	try {
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'audit_log (timestamp, actor, actor_status, action, target, target_status, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?);');
		$stmt->execute([time(), $actor, $actor_status, $action, $target, $target_status, $details, $_SERVER['REMOTE_ADDR'] ?? '']);
	} catch (Exception $e) {
		// Silently fail if audit log unavailable
	}
}

/**
 * Log action to user_history table for per-user tracking
 * @param string $username Target username
 * @param string $action_type Type of action (warning, kick, mute, nickname_change)
 * @param string $issued_by Who issued the action
 * @param string $reason Reason/details
 * @param int $duration Duration in seconds (0 for permanent/instant actions)
 */
function log_user_action($username, $action_type, $issued_by, $reason = '', $duration = 0)
{
	global $db;
	try {
		$stmt = $db->prepare('INSERT INTO ' . PREFIX . 'user_history (username, action_type, action_date, actor, details, expired) VALUES (?, ?, ?, ?, ?, 0);');
		$stmt->execute([$username, $action_type, time(), $issued_by, $reason]);
	} catch (Exception $e) {
		error_log("log_user_action failed: " . $e->getMessage());
	}
}

/**
 * Check if user can send to a specific channel
 * @param int $user_status User's status level
 * @param string $channel Channel identifier
 * @return bool Can send to channel
 */
function can_send_channel($user_status, $channel)
{
	// This Room - everyone can send
	if ($channel === 'room' || $channel === 'this_room') {
		return $user_status >= 1;
	}
	
	// Members channel - requires member (3+)
	if ($channel === 'members' || $channel === 's 31') {
		return $user_status >= 3;
	}
	
	// Staff channel - requires staff (5+)
	if ($channel === 'staff' || $channel === 's 48') {
		return $user_status >= 5;
	}
	
	// Admin channel - requires admin (6+)
	if ($channel === 'admin' || $channel === 's 56') {
		return $user_status >= 6;
	}
	
	// All (broadcast) - requires staff (5+)
	if ($channel === 'all' || $channel === 's 17') {
		return $user_status >= 5;
	}
	
	// Private messages - everyone can send
	if (str_starts_with($channel, 's ') || is_numeric($channel)) {
		return $user_status >= 1;
	}
	
	return false;
}

/**
 * Check if user can see messages from a specific channel
 * @param int $user_status User's status level
 * @param int $message_poststatus Message poststatus value
 * @return bool Can see message
 */
function can_see_channel($user_status, $message_poststatus)
{
	// Regular messages (1) - everyone can see
	if ($message_poststatus <= 1) {
		return true;
	}
	
	// Members channel (3) - members+ can see
	if ($message_poststatus === 3) {
		return $user_status >= 3;
	}
	
	// Staff channel (5) - staff+ can see
	if ($message_poststatus === 5) {
		return $user_status >= 5;
	}
	
	// Admin channel (6) - admins+ can see
	if ($message_poststatus === 6) {
		return $user_status >= 6;
	}
	
	// Private messages (9) - handled separately
	if ($message_poststatus === 9) {
		return true; // Checked elsewhere
	}
	
	return $user_status >= $message_poststatus;
}

/**
 * Check if actor can kick target
 * @param int $actor_status Actor's status level
 * @param int $target_status Target's status level
 * @return bool Can kick
 */
function can_kick($actor_status, $target_status)
{
	// Members (3) can kick guests (1)
	if ($actor_status >= 3 && $target_status === 1) {
		return true;
	}
	
	// Moderators (5) can kick guests, applicants, members
	if ($actor_status >= 5 && $target_status < 5) {
		return true;
	}
	
	// Chat Admins (6) can kick up to moderators
	if ($actor_status >= 6 && $target_status < 6) {
		return true;
	}
	
	// Service Admins (7) can kick up to chat admins
	if ($actor_status >= 7 && $target_status < 7) {
		return true;
	}
	
	// System Admins (8) can kick anyone except other system admins
	if ($actor_status >= 8 && $target_status < 8) {
		return true;
	}
	
	return false;
}

/**
 * Check if actor can delete target's messages
 * @param int $actor_status Actor's status level
 * @param int $target_status Target's status level
 * @return bool Can delete messages
 */
function can_delete_message($actor_status, $target_status)
{
	// Members (3) can delete guest/applicant messages if no mod present
	// (checked elsewhere via get_count_mods)
	
	// Moderators (5) can delete guest, applicant, member messages
	if ($actor_status >= 5 && $target_status < 5) {
		return true;
	}
	
	// Chat Admins (6) can delete up to moderator messages
	if ($actor_status >= 6 && $target_status < 6) {
		return true;
	}
	
	// Service Admins (7) can delete up to chat admin messages
	if ($actor_status >= 7 && $target_status < 7) {
		return true;
	}
	
	// System Admins (8) can delete any messages
	if ($actor_status >= 8) {
		return true;
	}
	
	return false;
}

/**
 * Check if actor can promote from current_status to new_status
 * @param int $actor_status Actor's status level
 * @param int $current_status Target's current status
 * @param int $new_status Target's desired status
 * @return bool Can promote
 */
function can_promote($actor_status, $current_status, $new_status)
{
	// Can't promote to higher than actor's own level
	if ($new_status >= $actor_status) {
		return false;
	}
	
	// Moderators (5) can promote guest (1) to applicant (2)
	if ($actor_status >= 5 && $current_status === 1 && $new_status === 2) {
		return true;
	}
	
	// Chat Admins (6) can promote applicant (2) to member (3)
	if ($actor_status >= 6 && $current_status === 2 && $new_status === 3) {
		return true;
	}
	
	// Chat Admins (6) can promote member (3) to moderator (5)
	if ($actor_status >= 6 && $current_status === 3 && $new_status === 5) {
		return true;
	}
	
	// Service Admins (7) can promote to chat admin (6)
	if ($actor_status >= 7 && $new_status === 6) {
		return true;
	}
	
	// System Admins (8) can promote to any level below them
	if ($actor_status >= 8 && $new_status < 8) {
		return true;
	}
	
	return false;
}

/**
 * Check if user can access a room
 * @param int $user_status User's status level
 * @param int $room_access_level Room's minimum access level
 * @return bool Can access room
 */
function can_access_room($user_status, $room_access_level)
{
	return $user_status >= $room_access_level;
}

/**
 * Check if sender can PM recipient
 * @param array $sender Sender user array (needs nickname, status)
 * @param array $recipient Recipient user array (needs nickname, status, online status, inbox_level)
 * @return bool Can send PM
 */
function can_pm($sender, $recipient)
{
	global $db;
	
	// Check if recipient ignores sender
	$stmt = $db->prepare('SELECT COUNT(*) FROM ' . PREFIX . 'ignored WHERE ign=? AND ignby=?;');
	$stmt->execute([$sender['nickname'], $recipient['nickname']]);
	if ($stmt->fetch(PDO::FETCH_NUM)[0] > 0) {
		return false;
	}
	
	// If recipient is online, allow PM
	if ($recipient['online'] ?? false) {
		return true;
	}
	
	// Check offline inbox settings
	$inbox_level = $recipient['inbox_level'] ?? 5; // Default: staff only
	
	// inbox_level 1 = everyone
	if ($inbox_level === 1) {
		return true;
	}
	
	// inbox_level 3 = members+ (3+)
	if ($inbox_level === 3 && $sender['status'] >= 3) {
		return true;
	}
	
	// inbox_level 5 = staff+ (5+)
	if ($inbox_level === 5 && $sender['status'] >= 5) {
		return true;
	}
	
	return false;
}

/**
 * Check if user can see deleted messages
 * @param int $user_status User's status level
 * @return bool Can see deleted messages
 */
function can_see_deleted_messages($user_status)
{
	return $user_status >= 7; // Service Admins+
}

/**
 * Check if user can change nickname
 * @param int $user_status User's status level
 * @return bool Can change nickname
 */
function can_change_nickname($user_status)
{
	// Guests (1) can change freely
	// Applicants (2) cannot change (locked after registration)
	// Members (3+) can change
	return $user_status === 1 || $user_status >= 3;
}

/**
 * Check if user can set font
 * @param int $user_status User's status level
 * @return bool Can set font
 */
function can_set_font($user_status)
{
	return $user_status >= 3; // Members+
}

/**
 * Check if user can create rooms
 * @param int $user_status User's status level
 * @return bool Can create rooms
 */
function can_create_rooms($user_status)
{
	return $user_status >= 5; // Moderators+
}

/**
 * Check if user can access setup page
 * @param int $user_status User's status level
 * @return bool Can access setup
 */
function can_access_setup($user_status)
{
	return $user_status >= 7; // Service Admins+
}

// configuration, defaults and internals

/**
 * Helper function to execute PDO statements with retry logic for database locks
 */
function db_execute_with_retry($stmt, $params = [], $max_retries = 3)
{
	$retry_count = 0;
	$success = false;
	
	while (!$success && $retry_count < $max_retries) {
		try {
			$stmt->execute($params);
			$success = true;
			return true;
		} catch (PDOException $e) {
			if ($e->getCode() === 'HY000' && strpos($e->getMessage(), 'database is locked') !== false) {
				$retry_count++;
				if ($retry_count < $max_retries) {
					usleep(50000 * $retry_count); // Exponential backoff: 50ms, 100ms, 150ms
					error_log('[DB RETRY] Database locked, retry ' . $retry_count . '/' . $max_retries);
				} else {
					error_log('[DB ERROR] Failed after ' . $max_retries . ' retries: ' . $e->getMessage());
					throw $e;
				}
			} else {
				throw $e;
			}
		}
	}
	return $success;
}

/**
 * Ensure bot_reply column exists in filter table
 * Called on every page load to guarantee column existence
 */
function ensure_bot_reply_column()
{
	global $db, $memcached;
	
	// Set error mode to exception temporarily
	$oldErrorMode = $db->getAttribute(PDO::ATTR_ERRMODE);
	$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		// Try to check if column exists by selecting it
		$db->query('SELECT bot_reply FROM ' . PREFIX . 'filter LIMIT 1;');
	} catch (PDOException $e) {
		// Column doesn't exist, create it
		try {
			$db->exec('ALTER TABLE ' . PREFIX . 'filter ADD COLUMN bot_reply smallint NOT NULL DEFAULT 0;');
			if (MEMCACHED) {
				$memcached->delete(DBNAME . '-' . PREFIX . "filter");
			}
		} catch (PDOException $e2) {
			// Failed to add column, might be a permission issue
		}
	}
	
	// Restore original error mode
	$db->setAttribute(PDO::ATTR_ERRMODE, $oldErrorMode);
}

function check_db()
{
	global $I, $db, $memcached;
	$options = [PDO::ATTR_ERRMODE => PDO::ERRMODE_WARNING, PDO::ATTR_PERSISTENT => PERSISTENT];
	try {
		if (DBDRIVER === 0) {
			if (!extension_loaded('pdo_mysql')) {
				send_fatal_error($I['pdo_mysqlextrequired']);
			}
			$db = new PDO('mysql:host=' . DBHOST . ';dbname=' . DBNAME . ';charset=utf8mb4', DBUSER, DBPASS, $options);
		} elseif (DBDRIVER === 1) {
			if (!extension_loaded('pdo_pgsql')) {
				send_fatal_error($I['pdo_pgsqlextrequired']);
			}
			$db = new PDO('pgsql:host=' . DBHOST . ';dbname=' . DBNAME, DBUSER, DBPASS, $options);
		} else {
			if (!extension_loaded('pdo_sqlite')) {
				send_fatal_error($I['pdo_sqliteextrequired']);
			}
			$db = new PDO('sqlite:' . SQLITEDBFILE, NULL, NULL, $options);
			// Set busy timeout to 5 seconds to handle concurrent writes
			$db->exec('PRAGMA busy_timeout = 5000');
			// Enable WAL mode for better concurrency
			$db->exec('PRAGMA journal_mode = WAL');
		}
	} catch (PDOException $e) {
		try {
			//Attempt to create database
			if (DBDRIVER === 0) {
				$db = new PDO('mysql:host=' . DBHOST, DBUSER, DBPASS, $options);
				if (false !== $db->exec('CREATE DATABASE ' . DBNAME)) {
					$db = new PDO('mysql:host=' . DBHOST . ';dbname=' . DBNAME . ';charset=utf8mb4', DBUSER, DBPASS, $options);
				} else {
					send_fatal_error($I['nodbsetup']);
				}
			} elseif (DBDRIVER === 1) {
				$db = new PDO('pgsql:host=' . DBHOST, DBUSER, DBPASS, $options);
				if (false !== $db->exec('CREATE DATABASE ' . DBNAME)) {
					$db = new PDO('pgsql:host=' . DBHOST . ';dbname=' . DBNAME, DBUSER, DBPASS, $options);
				} else {
					send_fatal_error($I['nodbsetup']);
				}
			} else {
				if (isset($_REQUEST['action']) && $_REQUEST['action'] === 'setup') {
					send_fatal_error($I['nodbsetup']);
				} else {
					send_fatal_error($I['nodb']);
				}
			}
		} catch (PDOException $e) {
			if (isset($_REQUEST['action']) && $_REQUEST['action'] === 'setup') {
				send_fatal_error($I['nodbsetup']);
			} else {
				send_fatal_error($I['nodb']);
			}
		}
	}
	if (MEMCACHED) {
		if (!extension_loaded('memcached')) {
			send_fatal_error($I['memcachedextrequired']);
		}
		$memcached = new Memcached();
		$memcached->addServer(MEMCACHEDHOST, MEMCACHEDPORT);
	}
	if (!isset($_REQUEST['action']) || $_REQUEST['action'] === 'setup') {
		if (!check_init()) {
			send_init();
		}
	} elseif ($_REQUEST['action'] === 'init') {
		init_chat();
	}
	
	// Always run database migrations on every load (wrapped in try-catch to prevent blocking)
	try {
		update_db();
		// Force check and add bot_reply column if missing
		ensure_bot_reply_column();
	} catch (Exception $e) {
		// Silently fail migrations to prevent site from breaking
	}
}

function load_fonts()
{
	return [
		'Arial'			=> "font-family:'Arial','Helvetica','sans-serif';",
		'Book Antiqua'		=> "font-family:'Book Antiqua','MS Gothic';",
		'Comic'			=> "font-family:'Comic Sans MS','Papyrus';",
		'Courier'		=> "font-family:'Courier New','Courier','monospace';",
		'Cursive'		=> "font-family:'Cursive','Papyrus';",
		'Fantasy'		=> "font-family:'Fantasy','Futura','Papyrus';",
		'Garamond'		=> "font-family:'Garamond','Palatino','serif';",
		'Georgia'		=> "font-family:'Georgia','Times New Roman','Times','serif';",
		'Serif'			=> "font-family:'MS Serif','New York','serif';",
		'System'		=> "font-family:'System','Chicago','sans-serif';",
		'Times New Roman'	=> "font-family:'Times New Roman','Times','serif';",
		'Verdana'		=> "font-family:'Verdana','Geneva','Arial','Helvetica','sans-serif';",
	];
}

function load_lang()
{
	global $I, $L, $language;
	$L = [
		'bg'	=> 'Български',
		'cz'	=> 'čeština',
		'de'	=> 'Deutsch',
		'en'	=> 'English',
		'es'	=> 'Español',
		'fr'	=> 'Français',
		'id'	=> 'Bahasa Indonesia',
		'it'	=> 'Italiano',
		'ru'	=> 'Русский',
		'tr'	=> 'Türkçe',
		'uk'	=> 'Українська',
		'zh_CN'	=> '简体中文',
	];
	if (isset($_REQUEST['lang']) && isset($L[$_REQUEST['lang']])) {
		$language = $_REQUEST['lang'];
		if (!isset($_COOKIE['language']) || $_COOKIE['language'] !== $language) {
			set_secure_cookie('language', $language);
		}
	} elseif (isset($_COOKIE['language']) && isset($L[$_COOKIE['language']])) {
		$language = $_COOKIE['language'];
	} else {
		$language = LANG;
		set_secure_cookie('language', $language);
	}
	include('lang_en.php'); //always include English
	if ($language !== 'en') {
		$T = [];
		include("lang_$language.php"); //replace with translation if available
		foreach ($T as $name => $translation) {
			$I[$name] = $translation;
		}
	}
}

function load_config()
{
	mb_internal_encoding('UTF-8');
	define('VERSION', '2.2.2'); // Script version
	//See changelog

	define('DBVERSION', 2117); // Database layout version (User history severity)
	//Paste other config below this line: 
	define('MSGENCRYPTED', false); // Store messages encrypted in the database to prevent other database users from reading them - true/false - visit the setup page after editing!
	define('ENCRYPTKEY_PASS', 'MY_SECRET_KEY'); // Recommended length: 32. Encryption key for messages
	define('AES_IV_PASS', '012345678912'); // Recommended length: 12. AES Encryption IV
	define('DBHOST', 'dbhost'); // Database host
	define('DBUSER', 'dbuser'); // Database user
	define('DBPASS', 'dbpass'); // Database password
	define('DBNAME', 'dbname'); // Database
	define('PERSISTENT', true); // Use persistent database conection true/false
	define('PREFIX', ''); // Prefix - Set this to a unique value for every chat, if you have more than 1 chats on the same database or domain - use only alpha-numeric values (A-Z, a-z, 0-9, or _) other symbols might break the queries
	define('MEMCACHED', false); // Enable/disable memcached caching true/false - needs memcached extension and a memcached server.
	if (MEMCACHED) {
		define('MEMCACHEDHOST', 'localhost'); // Memcached host
		define('MEMCACHEDPORT', '11211'); // Memcached port
	}
	define('DBDRIVER', 2); // Selects the database driver to use - 0=MySQL, 1=PostgreSQL, 2=sqlite
	if (DBDRIVER === 2) {
		define('SQLITEDBFILE', $_ENV['SQLITE_DB_PATH'] ?? getenv('SQLITE_DB_PATH') ?? 'super_chat.sqlite'); // Filepath of the sqlite database, if sqlite is used - make sure it is writable for the webserver user
	}
	define('COOKIENAME', PREFIX . 'chat_session'); // Cookie name storing the session information
	define('LANG', 'en'); // Default language

	// Bridge configuration for IRC integration
	define('BRIDGE_ENABLED', false); // Enable/disable IRC bridge integration
	define('BRIDGE_HOST', '127.0.0.1'); // IRC bridge host (should be localhost)
	define('BRIDGE_PORT', 6666); // IRC bridge port
	define('BRIDGE_AUTH_KEY', ''); // Shared secret key for bridge authentication (must match IRC config)

	if (MSGENCRYPTED) {
		if (version_compare(PHP_VERSION, '7.2.0') < 0) {
			die("You need at least PHP >= 7.2.x");
		}
		//Do not touch: Compute real keys needed by encryption functions
		if (strlen(ENCRYPTKEY_PASS) !== SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES) {
			define('ENCRYPTKEY', substr(hash("sha512/256", ENCRYPTKEY_PASS), 0, SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES));
		} else {
			define('ENCRYPTKEY', ENCRYPTKEY_PASS);
		}
		if (strlen(AES_IV_PASS) !== SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES) {
			define('AES_IV', substr(hash("sha512/256", AES_IV_PASS), 0, SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES));
		} else {
			define('AES_IV', AES_IV_PASS);
		}
	}
}