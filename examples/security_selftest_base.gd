extends Node

## Boots a guarded server and drives every rule, feed and detector; exits non-zero if any check fails.
## Rules use short windows and escalation is driven by reporting events directly (as a game does), so no assertion waits on wall-clock time.

const SELFTEST_ARG := "--selftest"

var server: DotServer
var guard: DotSecurityManager
var watch: DotSecurityWatch
var feeds: DotBanFeeds
var anticheat: DotAntiCheat

## Sections entered against sections that ran to their last line, and against this. A
## runtime error inside a section aborts that function and nothing says so; a section that
## bailed out early after a failed guard is counted as not finished on purpose.
const SECTIONS := 17

## Every check this suite runs, including the two at the end that compare the counts. The
## section counter cannot see a section that aborted after announcing itself — its remaining
## checks simply never run — and a total can. See docs/testing.md.
const CHECKS := 200

var _entered := 0
var _completed := 0
var _passed := 0
var _failed := 0


func _ready() -> void:
	var config := DotServerConfig.new()
	config.port = 0
	config.max_players = 16
	config.tickrate = 30
	config.rcon_password = ""
	config.hostname = "dot-server-security self-test"
	config.query_enabled = false
	config.a2s_enabled = false
	config.admins_path = "user://secexample/admins.json"
	config.bans_path = "user://secexample/bans.json"
	config.audit_log_path = "user://secexample/audit.jsonl"
	config.hibernate_when_empty = false
	config.startup_config = ""
	config.autoexec_config = ""

	server = DotServer.new()
	server.name = "Server"
	server.config = config
	server.config_file = ""
	server.auto_boot = false
	add_child(server)

	# The REAL dot-moderation, not a mock: the durable half of every action goes
	# through it, and a suite that stubbed it would be asserting against its own
	# idea of that addon rather than against the addon.
	var moderation := DotModerationManager.new()
	moderation.name = "Moderation"
	moderation.store = DotPunishmentStoreFile.new()
	moderation.store.path = "user://secexample/punishments.json"
	add_child(moderation)

	guard = DotSecurityManager.new()
	guard.name = "Security"
	guard.server_ref = DotNodeRef.of_path(NodePath("../Server"))
	guard.config = DotSecurityConfig.new()
	# No file layers: the suite must assert against what it set, not against
	# whatever an operator left in user://.
	guard.config_file = ""
	guard.config.rules_file = ""
	guard.config.dry_run = false
	guard.config.notify_admins = false
	# The suite invents event names on purpose; the warning about one no watcher
	# reports is correct and would drown the output.
	guard.config.warn_unknown_events = false
	add_child(guard)

	watch = DotSecurityWatch.new()
	watch.name = "Watch"
	watch.guard_ref = DotNodeRef.of_path(NodePath("../Security"))
	add_child(watch)

	anticheat = DotAntiCheat.new()
	anticheat.name = "AntiCheat"
	anticheat.guard_ref = DotNodeRef.of_path(NodePath("../Security"))
	anticheat.config = DotAntiCheatConfig.new()
	anticheat.config_file = ""
	anticheat.config.dry_run = false
	anticheat.config.max_horizontal_speed = 100.0
	anticheat.config.max_tick_distance = 50.0
	add_child(anticheat)

	var booted := await server.boot()
	if not booted.ok:
		printerr("boot failed: %s" % str(booted.error))
		get_tree().quit(1)
		return

	if _should_selftest():
		await _run_selftest()
		return

	var timer := Timer.new()
	timer.wait_time = 30.0
	timer.autostart = true
	timer.timeout.connect(func() -> void:
		DotLog.info("example", "still running", guard.describe()))
	add_child(timer)


func _should_selftest() -> bool:
	var args := OS.get_cmdline_user_args()
	if args.has(SELFTEST_ARG):
		return true
	if args.has("--serve"):
		return false
	return DotPlatform.is_headless()

## Overridden by the suite itself; the base only boots the guarded server.
func _run_selftest() -> void:
	pass


func _section(title: String) -> void:
	_entered += 1
	print(title)


## A section reached its last line. See [constant SECTIONS].
func _done() -> void:
	_completed += 1


func _check(what: String, passed: bool) -> void:
	if passed:
		_passed += 1
		print("  %-56s ok" % what)
	else:
		_failed += 1
		print("  %-56s FAILED" % what)


func _run(line: String) -> String:
	var lines := PackedStringArray()
	var ctx := DotCmdContext.console("", PackedStringArray())
	ctx.reply_sink = func(text: String) -> void: lines.append(text)
	server.console.execute(line, ctx)
	return "\n".join(lines)


## A rule with a short window, so the suite does not wait on wall-clock time.
func _rule(id: StringName, event: StringName, threshold: int) -> DotSecurityRule:
	var rule := DotSecurityRule.of(id, event, threshold, 5.0)
	rule.cooldown_sec = 0.0
	rule.exempt_flags = PackedStringArray()
	rule.steps = [DotSecurityStep.of(DotSecurityAction.Kind.WARN)]
	return rule


func _report(event: StringName, subject: String, times: int = 1) -> void:
	for _i in range(times):
		guard.report(DotSecurityEvent.make(event, subject))



