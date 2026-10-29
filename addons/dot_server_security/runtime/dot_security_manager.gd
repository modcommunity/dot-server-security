@tool
class_name DotSecurityManager
extends Node

## The guard: counts what the watchers report, decides, and acts. Place one beside a [DotServer] and it attaches itself; registered as [code]dot_security[/code].
## A game reports its own events through [method report] too, which is why the event vocabulary is open.
## It ships in dry run: see [member DotSecurityConfig.dry_run].

const CHANNEL := "security"
const SERVICE := &"dot_security"

## A rule tripped. [param applied] is false in dry run or when withheld.
signal tripped(entry: DotSecurityLedger.Entry)

## A rule acted on somebody. Never emitted in dry run.
signal acted(subject: String, action: int, duration_sec: int, rule_id: StringName)

@export_group("Wiring")

## The server to guard. Defaults to whichever one is in [DotRegistry].
@export var server_ref: DotNodeRef = null

## How long to wait for that server, when it is found through the registry.
@export_range(0.0, 60.0, 0.5) var attach_timeout_sec: float = 10.0

@export_group("Configuration")

@export var config: DotSecurityConfig = null

## JSON layered over [member config]. Empty skips the file layer.
@export var config_file: String = "user://cfg/security.json"

## The rule set. Left null, the shipped defaults are used.
@export var policy: DotSecurityPolicy = null

var server: DotServer = null

## Whatever registered as `dot_moderation`, or null. Duck-typed; never named.
## Read through [method moderation_store]: this cached value may be stale on purpose, as a value latched at [method attach] is wrong on almost every server here.
var moderation: Object = null

var ledger: DotSecurityLedger = null

## event -> Array[DotSecurityRule], rebuilt whenever the policy changes.
var _by_event: Dictionary = {}

## rule_id -> DotSecurityWindow
var _windows: Dictionary = {}

## "rule_id|subject" -> [offence_count, last_trip_unix]
var _offences: Dictionary = {}

var _attached: bool = false
var _events_seen: int = 0
var _last_offence_sweep: int = 0


func _ready() -> void:
	if Engine.is_editor_hint():
		return

	if server_ref == null:
		server_ref = DotNodeRef.of_service(DotServer.SERVICE)

	# A guard placed beside a server is ready before that server has booted and registered itself,
	# so giving up here leaves a server unguarded with nothing in the log to say why.
	if server_ref.mode == DotNodeRef.Mode.REGISTRY \
			and DotRegistry.get_service(server_ref.service) == null:
		var waited := await DotRegistry.await_service(
			server_ref.service, attach_timeout_sec
		)
		if not waited.ok:
			DotLog.warn(
				CHANNEL,
				"no server to guard: nothing is being watched",
				{"service": String(server_ref.service)}
			)
			return

	var attached := attach()
	if not attached.ok:
		DotLog.warn(
			CHANNEL, "could not attach", {"detail": attached.error.message}
		)


func _exit_tree() -> void:
	DotRegistry.unregister_instance(SERVICE, self)



func attach() -> DotResult:
	if _attached:
		return DotResult.success(self)

	var resolved := server_ref.resolve(self)
	if not resolved.ok:
		return resolved.wrap("A security manager needs a server.")

	server = resolved.value as DotServer
	if server == null:
		return DotResult.fail(
			DotError.CODE_INVALID, "server_ref did not resolve to a DotServer."
		)

	if config == null:
		config = DotSecurityConfig.new()

	if config_file != "":
		var loaded := config.apply_json_file(config_file)
		if not loaded.ok:
			DotLog.warn(
				CHANNEL,
				"the security config file could not be read; using defaults",
				{"detail": loaded.error.message}
			)

	config.apply_env()
	config.apply_cli()

	var valid := config.validate()
	if not valid.ok:
		return valid

	if policy == null:
		policy = DotSecurityPolicy.defaults()

	var rules_loaded := policy.apply_json_file(config.rules_file)
	if not rules_loaded.ok:
		# Refused rather than partially applied. A rule file with a mistake in it
		# would otherwise leave some rules from the file and some from the
		# defaults, which is a rule set nobody wrote and nobody can reason about.
		DotLog.error(
			CHANNEL,
			"the rules file was refused; the shipped defaults are in force",
			{"detail": rules_loaded.error.message, "file": config.rules_file}
		)
		policy = DotSecurityPolicy.defaults()

	_reindex()

	if config.dump_rules_file != "":
		policy.save_json_file(config.dump_rules_file)

	ledger = DotSecurityLedger.new(config.ledger_size)

	moderation = DotRegistry.get_service(&"dot_moderation")

	DotRegistry.register(SERVICE, self)
	_register_console()
	_attached = true

	DotLog.info(
		CHANNEL,
		"guarding",
		{
			"rules": policy.enabled_rules().size(),
			"dry_run": is_dry_run(),
			"moderation": moderation_store() != null,
		}
	)

	if moderation == null:
		# Named once, at boot, because the difference is invisible afterwards: a gag still happens but does not survive a reconnect.
		# "not yet", rather than "none": a game's module publishes the store after the server boots, so this is the ordinary case.
		# `sec_status` asks again and says what is in force.
		DotLog.info(
			CHANNEL,
			"no moderation store yet: until one registers, punishments last only as "
			+ "long as the connection. sec_status says what is in force now"
		)

	return DotResult.success(self)


## The durable punishment store, looked up again if it was not there at [method attach].
## The guard almost always starts before the store exists (the game's module loads after the server boots), and latching null meant every gag and ban silently fell back to the session, undone by reconnecting (docs/rationale.md).
## Looked up again rather than every time; the cached value is dropped when a game change frees the store.
func moderation_store() -> Object:
	if moderation != null and is_instance_valid(moderation):
		return moderation

	moderation = DotRegistry.get_service(&"dot_moderation")
	return moderation


## Rebuilds the event index. Call after changing the policy at runtime.
func _reindex() -> void:
	_by_event.clear()

	for rule in policy.enabled_rules():
		var list: Array = _by_event.get(rule.event, [])
		list.append(rule)
		_by_event[rule.event] = list

		if not _windows.has(rule.id):
			_windows[rule.id] = DotSecurityWindow.new(rule.window_sec)
		else:
			(_windows[rule.id] as DotSecurityWindow).window_sec = rule.window_sec

		if config != null and config.warn_unknown_events \
				and not DotSecurityEvent.is_known(rule.event) \
				and not DotAntiCheatEvent.ALL.has(rule.event):
			# Almost always a typo. The symptom otherwise is a rule that never
			# fires, which looks exactly like one that is working and not needed.
			DotLog.warn(
				CHANNEL,
				"rule '%s' watches '%s', which no shipped watcher reports"
					% [rule.id, rule.event],
				{"hint": "a game reporting it itself is fine; a typo is not"}
			)



## Whether the guard is counting at all.
func is_enabled() -> bool:
	if not _attached or config == null or not config.enabled:
		return false
	if server != null and server.console != null:
		return server.console.get_bool("sv_security", true)
	return true


## Whether it is counting but not acting.
func is_dry_run() -> bool:
	if config == null:
		return true
	if server != null and server.console != null:
		return server.console.get_bool("sv_security_dryrun", config.dry_run)
	return config.dry_run


## Reports one event. The entry point for every watcher and for a game's own.
## Cheap when nothing watches the event: one dictionary lookup and a return.
func report(event: DotSecurityEvent) -> void:
	if event == null or not is_enabled():
		return

	var rules: Array = _by_event.get(event.name, [])
	if rules.is_empty():
		return

	_events_seen += 1

	for entry in rules:
		var rule: DotSecurityRule = entry
		_evaluate(rule, event)


## Convenience for a game: report by name against a session.
func report_session(
	event_name: StringName,
	session: DotClientSession,
	weight: float = 1.0,
	detail: Dictionary = {}
) -> void:
	if not is_enabled():
		return

	var rules: Array = _by_event.get(event_name, [])
	if rules.is_empty():
		return

	# Built per scope, because the subject depends on the rule: two rules on one event with different scopes
	# ("this account is spamming", "this address spams from a new account each time") are a supported arrangement.
	for entry in rules:
		var rule: DotSecurityRule = entry
		for subject in DotSecuritySubject.all_of_session(session, rule.scope):
			var event := DotSecurityEvent.make(event_name, subject, weight, detail)
			event.session = session
			if session != null:
				event.uid = session.uid()
				event.address = session.address
			_evaluate(rule, event)


## Reports against a bare address, for anything with no session behind it.
func report_address(
	event_name: StringName,
	address: String,
	weight: float = 1.0,
	detail: Dictionary = {}
) -> void:
	var event := DotSecurityEvent.make(
		event_name, DotSecuritySubject.for_address(address), weight, detail
	)
	event.address = address
	report(event)


func _evaluate(rule: DotSecurityRule, event: DotSecurityEvent) -> void:
	if event.subject == "":
		return

	var window: DotSecurityWindow = _windows.get(rule.id)
	if window == null:
		window = DotSecurityWindow.new(rule.window_sec)
		_windows[rule.id] = window

	var count := window.add(event.subject, event.weight)

	if count < float(rule.threshold):
		return

	var key := "%s|%s" % [rule.id, event.subject]
	var now := int(Time.get_unix_time_from_system())
	var state: Array = _offences.get(key, [0, 0])

	var last_trip := int(state[1])
	if last_trip > 0 and float(now - last_trip) < rule.cooldown_sec:
		# Inside the cooldown. Without this a rule whose action does not stop the
		# behaviour — a warning — trips on every subsequent event and walks its
		# whole ladder in one second, banning somebody over four messages.
		return

	# The offence counter decays on its own clock, which is not the window's.
	# The window is how fast the behaviour must be to count at all; this is how
	# long the server holds it against them.
	var offence := int(state[0])
	if last_trip > 0 and rule.offence_memory_sec > 0.0 \
			and float(now - last_trip) > rule.offence_memory_sec:
		offence = 0

	offence += 1
	_offences[key] = [offence, now]
	_sweep_offences(now)

	_act(rule, event, count, offence)


func _act(
	rule: DotSecurityRule,
	event: DotSecurityEvent,
	count: float,
	offence: int
) -> void:
	var step := rule.step_for(offence)
	var reason := rule.render_reason(count, offence)

	var entry := DotSecurityLedger.Entry.new()
	entry.at = int(Time.get_unix_time_from_system())
	entry.rule_id = rule.id
	entry.event = event.name
	entry.subject = event.subject
	entry.count = count
	entry.threshold = rule.threshold
	entry.window_sec = rule.window_sec
	entry.offence = offence
	entry.action = step.action
	entry.duration_sec = step.duration_sec
	entry.detail = event.session.display_name if event.session != null else ""

	var exemption := rule.exemption_for(event.session)

	if exemption != "":
		entry.withheld = exemption
	elif not DotSecuritySubject.may_act_on(event.subject):
		entry.withheld = "protected subject"
	elif is_dry_run():
		entry.withheld = "dry run"
	elif step.action == DotSecurityAction.Kind.NONE:
		entry.withheld = "rule counts only"
	else:
		var applied := DotSecurityAction.apply(
			step.action,
			event.subject,
			step.duration_sec,
			reason,
			"security:%s" % rule.id,
			moderation_store(),
			server,
			event.session
		)

		entry.applied = applied.ok
		if not applied.ok:
			entry.withheld = applied.error.message
		else:
			acted.emit(event.subject, step.action, step.duration_sec, rule.id)

	# The counter is cleared whatever happened, including in dry run: leaving it would trip the same rule on the next event
	# and report an escalation the behaviour did not earn, a thousand lines about one person.
	var window: DotSecurityWindow = _windows.get(rule.id)
	if window != null:
		window.clear_subject(event.subject)

	ledger.record(entry)
	tripped.emit(entry)

	_log(rule, entry)
	_notify(rule, step, entry, event, reason)


func _log(rule: DotSecurityRule, entry: DotSecurityLedger.Entry) -> void:
	var fields := {
		"rule": String(rule.id),
		"subject": entry.subject,
		"count": entry.count,
		"offence": entry.offence,
		"action": DotSecurityAction.kind_name(entry.action),
		"applied": entry.applied,
	}

	if entry.withheld != "":
		fields["withheld"] = entry.withheld

	if rule.loud:
		DotLog.info(CHANNEL, "rule tripped", fields)
	else:
		DotLog.debug(CHANNEL, "rule tripped", fields)


func _notify(
	rule: DotSecurityRule,
	step: DotSecurityStep,
	entry: DotSecurityLedger.Entry,
	event: DotSecurityEvent,
	reason: String
) -> void:
	if server == null or server.chat == null:
		return

	var message := step.message if step.message != "" else reason

	# A player silently unable to type concludes the server is broken. One line
	# naming what happened turns an automatic punishment into something they can
	# argue with, which is also what makes a bad rule visible to the operator.
	if config.notify_subject and entry.applied and event.session != null \
			and not DotSecurityAction.is_removal(step.action):
		server.chat.send_system_to(event.session, message)

	if not config.notify_admins:
		return

	var note := "[guard] %s: %s %s" % [
		DotSecuritySubject.describe(entry.subject),
		"would " if not entry.applied else "",
		DotSecurityStep.of(step.action, step.duration_sec).describe(),
	]

	for session in server.sessions():
		if session == event.session:
			continue
		if config.notify_flag != "" \
				and not session.permissions.has(config.notify_flag):
			continue
		server.chat.send_system_to(session, note)


## Drops offence records nothing could still escalate from.
## Bounded like the windows: one entry per rule per subject grows with every address that ever tripped anything.
func _sweep_offences(now: int) -> void:
	if now - _last_offence_sweep < 300:
		return
	_last_offence_sweep = now

	var stale: Array = []

	for key in _offences:
		var state: Array = _offences[key]
		var rule_id := String(key).split("|")[0]
		var rule := policy.find(StringName(rule_id))
		var memory := rule.offence_memory_sec if rule != null else 86400.0

		if memory > 0.0 and float(now - int(state[1])) > memory:
			stale.append(key)

	for key in stale:
		_offences.erase(key)



## How many offences a subject has on record for a rule.
func offences_for(rule_id: StringName, subject: String) -> int:
	var state: Array = _offences.get("%s|%s" % [rule_id, subject], [0, 0])
	return int(state[0])


## The current count in a rule's window, without recording anything.
func count_for(rule_id: StringName, subject: String) -> float:
	var window: DotSecurityWindow = _windows.get(rule_id)
	return window.peek(subject) if window != null else 0.0


## Forgets everything about a subject: counters and offence history.
## For after lifting a punishment by hand; otherwise the next event escalates from where the ladder left off and the person just forgiven is gagged again.
func forget(subject: String) -> int:
	var cleared := 0

	for rule_id in _windows:
		(_windows[rule_id] as DotSecurityWindow).clear_subject(subject)

	for key in _offences.keys():
		if String(key).ends_with("|" + subject):
			_offences.erase(key)
			cleared += 1

	return cleared


func forget_all() -> void:
	for rule_id in _windows:
		(_windows[rule_id] as DotSecurityWindow).clear()
	_offences.clear()


## Turns one rule on or off at runtime.
func set_rule_enabled(id: StringName, on: bool) -> DotResult:
	var rule := policy.find(id)
	if rule == null:
		return DotResult.fail(
			DotError.CODE_INVALID, "No rule called '%s'." % id
		)

	rule.enabled = on
	_reindex()
	return DotResult.success(rule)


## Rereads the rules file, so tuning does not need a restart.
func reload_rules() -> DotResult:
	var fresh := DotSecurityPolicy.defaults()
	var loaded := fresh.apply_json_file(config.rules_file)

	if not loaded.ok:
		return loaded.wrap("the rules in force are unchanged")

	policy = fresh
	_reindex()

	return DotResult.success(policy.enabled_rules().size())


## Registers the cvars and commands, waiting for the console if it is not up.
## A guard beside a server is ready before the console exists, and registering unconditionally silently left a working guard with no `sec_status`, `sec_why` or `sv_security` (docs/rationale.md).
func _register_console() -> void:
	if server == null:
		return

	if server.console != null:
		DotSecurityCommands.register(self, server.console)
		return

	# Registered the moment the console exists: state_changed fires through BOOTING after the console's own cvars exist,
	# and before server.cfg runs, so an operator can set sv_security in it.
	if not server.state_changed.is_connected(_on_server_state):
		server.state_changed.connect(_on_server_state)


func _on_server_state(_state: int) -> void:
	if server == null or server.console == null:
		return

	server.state_changed.disconnect(_on_server_state)
	DotSecurityCommands.register(self, server.console)



func describe() -> Dictionary:
	return {
		"enabled": is_enabled(),
		"dry_run": is_dry_run(),
		"rules": policy.rules.size() if policy != null else 0,
		"active_rules": policy.enabled_rules().size() if policy != null else 0,
		"events_seen": _events_seen,
		"moderation": moderation_store() != null,
		"tripped": ledger.total() if ledger != null else 0,
		"applied": ledger.applied_count() if ledger != null else 0,
	}


func describe_lines() -> PackedStringArray:
	var out := PackedStringArray()

	if not _attached:
		out.append("not attached to a server")
		return out

	out.append("state       %s%s" % [
		"on" if is_enabled() else "OFF",
		"  [dry run: counting, not acting]" if is_dry_run() else "",
	])
	out.append("rules       %d active of %d" % [
		policy.enabled_rules().size(), policy.rules.size()
	])
	out.append("store       %s" % (
		"dot-moderation (durable)" if moderation_store() != null
			else "session only (lost on reconnect)"
	))
	out.append("seen        %d events" % _events_seen)
	out.append("tripped     %d (%d applied)" % [
		ledger.total(), ledger.applied_count()
	])

	var tracked := 0
	for rule_id in _windows:
		tracked += (_windows[rule_id] as DotSecurityWindow).subject_count()
	out.append("tracking    %d subjects, %d offence records" % [
		tracked, _offences.size()
	])

	return out
