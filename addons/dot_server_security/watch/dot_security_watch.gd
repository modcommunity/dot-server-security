@tool
class_name DotSecurityWatch
extends Node

## Wires the guard to everything on the server worth watching.
##
## One node rather than five, because an operator adding a guard wants a guard,
## not a parts list. Every source is a separate toggle and every source is
## optional: a server with no dot-chat installed simply has the chat router
## half do nothing, and the dot-server chat path is watched instead.
##
## [b]Nothing here names dot-chat or dot-auth.[/b] Both are optional addons, and
## a script mentioning a [code]class_name[/code] the project does not have fails
## to parse and takes every script referencing it down with it — which for a
## security addon means the guard stops existing rather than stops watching one
## source. They are reached through [DotRegistry] and their signals connected by
## name.
##
## What each source gives the rule engine:
##
## [codeblock]
## dot-server chat     chat.message chat.duplicate chat.caps chat.link chat.refused
## dot-chat router     the same, plus chat.command
## the server          connect.attempt connect.rejected connect.churn
## RCON                rcon.auth_failed rcon.command
## the console         command.denied
## dot-auth            auth.failed auth.rejected
## [/codeblock]

const CHANNEL := "security"

@export_group("Wiring")

## The guard to report to. Defaults to whichever one is in [DotRegistry].
@export var guard_ref: DotNodeRef = null

@export_group("Sources")

## Watch text chat: the server's own path and dot-chat's router if present.
@export var watch_chat: bool = true

## Watch connections, rejections and reconnect churn.
@export var watch_connections: bool = true

## Watch RCON authentication failures. [b]Leave this on.[/b]
@export var watch_rcon: bool = true

## Watch commands refused for want of permission.
@export var watch_commands: bool = true

## Watch dot-auth, when it is installed.
@export var watch_auth: bool = true

var guard: DotSecurityManager = null
var server: DotServer = null

## subject -> Array of [text, unix_time], for the duplicate check.
var _recent_text: Dictionary = {}

## address -> unix time of last connect, for the churn check.
var _connected_at: Dictionary = {}

var _wired: PackedStringArray = PackedStringArray()


func _ready() -> void:
	if Engine.is_editor_hint():
		return

	if guard_ref == null:
		guard_ref = DotNodeRef.of_service(DotSecurityManager.SERVICE)

	if guard_ref.mode == DotNodeRef.Mode.REGISTRY \
			and DotRegistry.get_service(guard_ref.service) == null:
		var waited := await DotRegistry.await_service(guard_ref.service, 10.0)
		if not waited.ok:
			DotLog.warn(CHANNEL, "no security manager to report to")
			return

	guard = guard_ref.resolve_or_null(self, CHANNEL) as DotSecurityManager
	if guard == null:
		DotLog.warn(CHANNEL, "guard_ref did not resolve to a DotSecurityManager")
		return

	server = guard.server
	if server == null:
		DotLog.warn(CHANNEL, "the guard is not attached to a server yet")
		return

	_wire()

	DotLog.info(
		CHANNEL, "watching", {"sources": ", ".join(Array(_wired))}
	)


func _wire() -> void:
	if watch_chat:
		_wire_server_chat()
		_wire_chat_router()
	if watch_connections:
		_wire_connections()
	if watch_rcon:
		_wire_rcon()
	if watch_commands:
		_wire_commands()
	if watch_auth:
		_wire_auth()


# --- Chat ------------------------------------------------------------------

func _wire_server_chat() -> void:
	if server.chat == null:
		return

	server.chat.message_sent.connect(_on_server_message)
	server.chat.message_blocked.connect(_on_server_message_blocked)
	_wired.append("server chat")


func _on_server_message(
	session: DotClientSession, text: String, _team_only: bool
) -> void:
	_examine_message(session, text)


func _on_server_message_blocked(session: DotClientSession, reason: String) -> void:
	guard.report_session(
		DotSecurityEvent.CHAT_REFUSED, session, 1.0, {"reason": reason}
	)


## dot-chat's router, reached by registry name and connected by signal name.
func _wire_chat_router() -> void:
	var router := DotRegistry.get_service(&"dot_chat_router")
	if router == null or not is_instance_valid(router):
		return

	if router.has_signal("message_accepted"):
		router.connect("message_accepted", _on_router_message)
	if router.has_signal("message_refused"):
		router.connect("message_refused", _on_router_refused)
	if router.has_signal("command_entered"):
		router.connect("command_entered", _on_router_command)

	_wired.append("chat router")


func _on_router_message(message: Object, _recipients: PackedInt32Array) -> void:
	if message == null:
		return

	var peer := int(message.get("peer"))
	var text := str(message.get("text"))
	_examine_message(_session_for(peer), text)


func _on_router_refused(peer: int, code: String, _reason: String) -> void:
	guard.report_session(
		DotSecurityEvent.CHAT_REFUSED, _session_for(peer), 1.0, {"code": code}
	)


func _on_router_command(
	peer: int, command: String, _args: PackedStringArray, _raw: String
) -> void:
	guard.report_session(
		DotSecurityEvent.CHAT_COMMAND, _session_for(peer), 1.0,
		{"command": command}
	)


## Turns one message into every chat event it is an instance of.
##
## A message can be several at once — a shouted, repeated link is three — and
## each is counted separately, because an operator may care about one and not
## the others. Reporting only the "worst" would make the other two rules
## unable to fire.
func _examine_message(session: DotClientSession, text: String) -> void:
	if session == null:
		return

	guard.report_session(DotSecurityEvent.CHAT_MESSAGE, session, 1.0)

	var config := guard.config
	var subject := DotSecuritySubject.of_session(
		session, DotSecuritySubject.Scope.UID
	)

	if _is_duplicate(subject, text, config):
		guard.report_session(DotSecurityEvent.CHAT_DUPLICATE, session)

	if _is_shouting(text, config):
		guard.report_session(DotSecurityEvent.CHAT_CAPS, session)

	if _has_link(text, config):
		guard.report_session(DotSecurityEvent.CHAT_LINK, session)


func _is_duplicate(
	subject: String, text: String, config: DotSecurityConfig
) -> bool:
	var now := int(Time.get_unix_time_from_system())
	var needle := _normalise(text, config)

	var history: Array = _recent_text.get(subject, [])
	var live: Array = []
	var found := false

	for entry in history:
		var pair: Array = entry
		if now - int(pair[1]) > int(config.duplicate_memory_sec):
			continue
		live.append(pair)
		if str(pair[0]) == needle:
			found = true

	live.append([needle, now])

	if live.size() > config.duplicate_depth:
		live = live.slice(live.size() - config.duplicate_depth)

	_recent_text[subject] = live
	return found


func _normalise(text: String, config: DotSecurityConfig) -> String:
	if not config.duplicate_normalises:
		return text

	# Case, whitespace and punctuation removed. The spammer who adds a full stop
	# each time is the whole reason this is not an exact comparison.
	var out := ""
	for i in range(text.length()):
		var c := text[i]
		if c.is_valid_identifier() or (c >= "0" and c <= "9") \
				or (c >= "a" and c <= "z") or (c >= "A" and c <= "Z"):
			out += c.to_lower()
	return out


static func _is_shouting(text: String, config: DotSecurityConfig) -> bool:
	if text.length() < config.caps_min_length:
		return false

	var letters := 0
	var upper := 0

	for i in range(text.length()):
		var c := text[i]
		var lower := c.to_lower()
		var upper_c := c.to_upper()
		if lower == upper_c:
			# Not a cased character: a digit, a space, punctuation, or a script
			# with no case at all. Counting those would make every message in a
			# language without capitals count as shouting.
			continue
		letters += 1
		if c == upper_c:
			upper += 1

	if letters < config.caps_min_length:
		return false

	return float(upper) / float(letters) >= config.caps_ratio


static func _has_link(text: String, config: DotSecurityConfig) -> bool:
	var lowered := text.to_lower()

	for allowed in config.link_allow:
		if lowered.contains(String(allowed).to_lower()):
			return false

	for marker in config.link_markers:
		if lowered.contains(String(marker).to_lower()):
			return true

	return false


# --- Connections -----------------------------------------------------------

func _wire_connections() -> void:
	server.client_state_changed.connect(_on_client_state)
	server.client_disconnected.connect(_on_client_disconnected)
	_wired.append("connections")


func _on_client_state(session: DotClientSession) -> void:
	if session == null:
		return

	# CONNECTING is the only state every arrival passes through exactly once,
	# which is what makes it the attempt. Counting SPAWNED instead would miss
	# precisely the connections that never finish — the ones a flood is made of.
	if session.state == DotClientSession.State.CONNECTING:
		_connected_at[DotSecuritySubject.normalise_address(session.address)] = \
			int(Time.get_unix_time_from_system())
		guard.report_address(
			DotSecurityEvent.CONNECT_ATTEMPT, session.address, 1.0,
			{"uid": session.uid()}
		)
	elif session.state == DotClientSession.State.REJECTED:
		guard.report_address(
			DotSecurityEvent.CONNECT_REJECTED, session.address, 1.0,
			{"reason": session.reject_reason}
		)


func _on_client_disconnected(session: DotClientSession, _reason: String) -> void:
	if session == null:
		return

	var address := DotSecuritySubject.normalise_address(session.address)
	var began := int(_connected_at.get(address, 0))
	_connected_at.erase(address)

	if began <= 0:
		return

	var lasted := int(Time.get_unix_time_from_system()) - began

	# Churn is the pattern no single connection looks wrong in: every one is
	# legitimate, and the server is still being hammered. A session that reached
	# SPAWNED and played is not churn however short it was.
	if float(lasted) <= guard.config.churn_window_sec \
			and session.spawned_at <= 0:
		guard.report_address(
			DotSecurityEvent.CONNECT_CHURN, session.address, 1.0,
			{"lasted_sec": lasted}
		)


# --- RCON ------------------------------------------------------------------

func _wire_rcon() -> void:
	if server.rcon == null:
		return

	server.rcon.auth_failed.connect(_on_rcon_auth_failed)
	server.rcon.command_received.connect(_on_rcon_command)
	_wired.append("rcon")


func _on_rcon_auth_failed(address: String, attempts: int) -> void:
	guard.report_address(
		DotSecurityEvent.RCON_AUTH_FAILED, address, 1.0, {"attempts": attempts}
	)


func _on_rcon_command(address: String, command: String) -> void:
	guard.report_address(
		DotSecurityEvent.RCON_COMMAND, address, 1.0, {"command": command}
	)


# --- Commands --------------------------------------------------------------

## Text dot-server uses for a refusal that was about permission.
##
## [b]A string coupling, and the only one available.[/b] `command_executed` fires
## only after the permission check has passed, so it never sees a denial;
## `command_refused` sees every refusal and distinguishes them by this prefix
## alone. Matching it is therefore the only way to tell somebody probing for
## commands they do not hold from somebody mistyping one.
##
## The self-test asserts the prefix against the real dot-server rather than
## trusting this comment, because a comment does not fail when the wording
## changes and this would silently stop counting anything.
const REFUSAL_PERMISSION := "missing permission"


func _wire_commands() -> void:
	if server.console == null:
		return
	if not server.console.has_signal("command_refused"):
		return

	server.console.command_refused.connect(_on_command_refused)
	_wired.append("commands")


func _on_command_refused(ctx: DotCmdContext, reason: String) -> void:
	# Only a refusal about permission. An unknown command is somebody mistyping,
	# and counting it would fire the rule on ordinary use.
	if not reason.begins_with(REFUSAL_PERMISSION):
		return

	if ctx == null:
		return

	if ctx.session != null:
		guard.report_session(
			DotSecurityEvent.COMMAND_DENIED, ctx.session, 1.0,
			{"command": ctx.command}
		)
	elif ctx.address != "":
		guard.report_address(
			DotSecurityEvent.COMMAND_DENIED, ctx.address, 1.0,
			{"command": ctx.command}
		)


## The session behind a peer id, or null.
func _session_for(peer: int) -> DotClientSession:
	if server == null:
		return null
	return server.session_of(peer)


# --- Authentication --------------------------------------------------------

func _wire_auth() -> void:
	var auth := DotRegistry.get_service(&"dot_auth_server")
	if auth == null or not is_instance_valid(auth):
		return

	if auth.has_signal("rejected"):
		auth.connect("rejected", _on_auth_rejected)

	_wired.append("auth")


func _on_auth_rejected(reason: String, detail: String) -> void:
	# dot-auth reports why, not who — it has refused to establish an identity,
	# so there is not one yet. The address is taken from whichever session is
	# still mid-handshake, and when none is, the event is dropped rather than
	# attributed to nobody: a rule counting "somebody, somewhere failed" would
	# ban the next person to connect.
	for session in server.sessions():
		if session.state == DotClientSession.State.AUTHENTICATING:
			guard.report_address(
				DotSecurityEvent.AUTH_FAILED, session.address, 1.0,
				{"reason": reason, "detail": detail}
			)
			return


func describe_lines() -> PackedStringArray:
	var out := PackedStringArray()
	out.append("wired       %s" % (
		", ".join(Array(_wired)) if not _wired.is_empty() else "nothing"
	))
	out.append("tracking    %d chat histories, %d connections" % [
		_recent_text.size(), _connected_at.size()
	])
	return out
