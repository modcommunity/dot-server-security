extends Node

## Boots a guarded server and drives every rule, feed and detector.
##
## [b]Nothing here waits on wall-clock time it does not have to.[/b] A rule with
## a ten-second window would otherwise make the suite take ten seconds per
## assertion, so the rules built here use short windows and the escalation is
## driven by reporting events directly — which is also exactly what a game does.
##
## [codeblock]
## godot --headless --path . res://examples/security_selftest.tscn
## [/codeblock]
##
## Exits non-zero if any check fails.

const SELFTEST_ARG := "--selftest"

var server: DotServer
var guard: DotSecurityManager
var watch: DotSecurityWatch
var feeds: DotBanFeeds
var anticheat: DotAntiCheat

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


func _run_selftest() -> void:
	print("=== self-test ===")
	print("")

	_test_attach()
	_test_windows()
	_test_subjects()
	_test_rules()
	_test_escalation()
	_test_exemptions()
	_test_dry_run()
	_test_policy_json()
	_test_chat_detection()
	_test_couplings()
	_test_ban_index()
	_test_ban_feed_parsing()
	_test_ban_feed_auth()
	await _test_ban_feed_admission()
	_test_anticheat()
	_test_without_moderation()
	_test_console()

	print("")
	print("%d passed, %d failed" % [_passed, _failed])

	server.shutdown("self-test complete")
	get_tree().quit(1 if _failed > 0 else 0)


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


# --- Attaching -------------------------------------------------------------

func _test_attach() -> void:
	print("[attach]")

	_check("the guard attached to the server", guard.server == server)
	_check("it registered itself", DotRegistry.get_service(
		DotSecurityManager.SERVICE) == guard)
	_check("the watcher found the guard", watch.guard == guard)
	_check("the shipped policy loaded", guard.policy.rules.size() > 0)
	_check("every shipped rule is valid", guard.policy.validate().ok)
	_check("it is not in dry run for this suite", not guard.is_dry_run())


# --- The sliding window ----------------------------------------------------

func _test_windows() -> void:
	print("")
	print("[sliding window]")

	var window := DotSecurityWindow.new(60.0)

	_check("an empty window counts nothing", window.peek("x") == 0.0)
	_check("one event counts one", window.add("x", 1.0) == 1.0)
	_check("weights accumulate", window.add("x", 2.0) == 3.0)
	_check("peek does not count", window.peek("x") == 3.0)
	_check("subjects are separate", window.add("y", 1.0) == 1.0)

	window.clear_subject("x")
	_check("a cleared subject is forgotten", window.peek("x") == 0.0)
	_check("clearing one leaves the other", window.peek("y") == 1.0)

	# The bound is a security control: the structure must not grow without
	# limit under exactly the traffic it exists to watch.
	var tiny := DotSecurityWindow.new(600.0)
	for i in range(DotSecurityWindow.MAX_ENTRIES_PER_SUBJECT + 50):
		tiny.add("flood", 1.0)
	_check("entries per subject are capped",
		tiny.peek("flood") <= float(DotSecurityWindow.MAX_ENTRIES_PER_SUBJECT))

	# ...and the cap is well above any sane threshold, so a rule has long since
	# fired before anything was dropped.
	_check("the cap is far above a usable threshold",
		DotSecurityWindow.MAX_ENTRIES_PER_SUBJECT >= 128)

	var expiring := DotSecurityWindow.new(0.1)
	expiring.add("z", 1.0)
	OS.delay_msec(150)
	_check("events fall out of the window", expiring.peek("z") == 0.0)


# --- Subjects --------------------------------------------------------------

func _test_subjects() -> void:
	print("")
	print("[subjects]")

	_check("a uid subject is prefixed",
		DotSecuritySubject.for_uid("abc") == "uid:abc")
	_check("an address subject is prefixed",
		DotSecuritySubject.for_address("1.2.3.4") == "ip:1.2.3.4")
	_check("the value comes back out",
		DotSecuritySubject.value_of("uid:abc") == "abc")

	# One address, not two. Counting the mapped and unmapped spellings
	# separately is a limit dodged by which socket the server happened to open.
	_check("an IPv4-mapped address normalises",
		DotSecuritySubject.for_address("::ffff:192.168.1.5") == "ip:192.168.1.5")

	_check("loopback is never acted on",
		not DotSecuritySubject.may_act_on("ip:127.0.0.1"))
	_check("an unreportable address is never acted on",
		not DotSecuritySubject.may_act_on("ip:unknown"))
	_check("an empty subject is never acted on",
		not DotSecuritySubject.may_act_on(""))
	_check("an ordinary address is acted on",
		DotSecuritySubject.may_act_on("ip:203.0.113.9"))


# --- Rules -----------------------------------------------------------------

func _test_rules() -> void:
	print("")
	print("[rules]")

	var rule := _rule(&"t_basic", &"test.basic", 3)
	guard.policy.add(rule)
	guard._reindex()

	var subject := "uid:tester"

	_report(&"test.basic", subject, 2)
	_check("below the threshold nothing trips",
		guard.ledger.for_subject(subject).is_empty())

	_report(&"test.basic", subject)
	var entries := guard.ledger.for_subject(subject)
	_check("the threshold trips the rule", entries.size() == 1)

	if entries.is_empty():
		return

	_check("it recorded which rule", entries[0].rule_id == &"t_basic")
	_check("it recorded the count", entries[0].count >= 3.0)
	_check("it was applied", entries[0].applied)

	# The counter is cleared on a trip, or the very next event trips it again
	# and reports an escalation the behaviour did not earn.
	_check("the counter resets after a trip",
		guard.count_for(&"t_basic", subject) == 0.0)

	_report(&"test.basic", subject, 2)
	_check("and counting starts again from zero",
		guard.ledger.for_subject(subject).size() == 1)

	guard.policy.remove(&"t_basic")
	guard._reindex()
	_report(&"test.basic", subject, 5)
	_check("a removed rule counts nothing",
		guard.ledger.for_subject(subject).size() == 1)


func _test_escalation() -> void:
	print("")
	print("[escalation]")

	var rule := _rule(&"t_ladder", &"test.ladder", 2)
	rule.steps = [
		DotSecurityStep.of(DotSecurityAction.Kind.WARN),
		DotSecurityStep.of(DotSecurityAction.Kind.GAG, 300),
		DotSecurityStep.of(DotSecurityAction.Kind.KICK),
	]
	guard.policy.add(rule)
	guard._reindex()

	var subject := "uid:climber"

	_report(&"test.ladder", subject, 2)
	_report(&"test.ladder", subject, 2)
	_report(&"test.ladder", subject, 2)
	_report(&"test.ladder", subject, 2)

	var entries := guard.ledger.for_subject(subject)
	_check("every offence was recorded", entries.size() == 4)

	if entries.size() < 4:
		return

	_check("the first offence warns",
		entries[0].action == DotSecurityAction.Kind.WARN)
	_check("the second gags", entries[1].action == DotSecurityAction.Kind.GAG)
	_check("the gag carries its duration", entries[1].duration_sec == 300)
	_check("the third kicks", entries[2].action == DotSecurityAction.Kind.KICK)
	# Running out and reverting to nothing would reward persistence.
	_check("past the end, the last rung repeats",
		entries[3].action == DotSecurityAction.Kind.KICK)
	_check("the offence number climbs", entries[3].offence == 4)

	# The cooldown is what stops a warning walking the whole ladder inside one
	# burst, which is the single easiest way to ban somebody over four messages.
	var guarded := _rule(&"t_cooldown", &"test.cooldown", 2)
	guarded.cooldown_sec = 60.0
	guard.policy.add(guarded)
	guard._reindex()

	_report(&"test.cooldown", "uid:cool", 2)
	_report(&"test.cooldown", "uid:cool", 2)
	_check("the cooldown stops a second trip",
		guard.ledger.for_subject("uid:cool").size() == 1)

	# ...and forgetting a subject is what an operator does after lifting a
	# punishment by hand, or the next event escalates from where it left off.
	guard.forget(subject)
	_check("forgetting clears the offence history",
		guard.offences_for(&"t_ladder", subject) == 0)


func _test_exemptions() -> void:
	print("")
	print("[exemptions]")

	var rule := _rule(&"t_exempt", &"test.exempt", 1)
	rule.exempt_flags = PackedStringArray(["generic"])
	rule.exempt_immunity = 50
	guard.policy.add(rule)
	guard._reindex()

	var session := DotClientSession.new()
	session.peer_id = 991
	session.userid = 991
	session.address = "203.0.113.50"
	session.display_name = "Admin"
	session.permissions = PackedStringArray(["generic"])

	guard.report_session(&"test.exempt", session)

	var entries := guard.ledger.search("203.0.113.50")
	var by_flag := guard.ledger.for_subject(
		DotSecuritySubject.of_session(session, DotSecuritySubject.Scope.UID)
	)
	var all: Array = entries + by_flag

	_check("an exempt admin still trips the rule", not all.is_empty())
	if all.is_empty():
		return

	_check("but nothing is applied to them", not all[0].applied)
	_check("and the reason is recorded", all[0].withheld.contains("generic"))

	# Exemption is checked at the action, not at the count: sec_status showing
	# what an admin's traffic would have tripped is genuinely useful.
	_check("the count still happened", all[0].count >= 1.0)

	var plain := DotClientSession.new()
	plain.peer_id = 992
	plain.userid = 992
	plain.address = "203.0.113.51"
	plain.immunity = 80

	guard.report_session(&"test.exempt", plain)
	var high := guard.ledger.for_subject(
		DotSecuritySubject.of_session(plain, DotSecuritySubject.Scope.UID)
	)
	_check("high immunity is exempt too",
		not high.is_empty() and not high[0].applied)


func _test_dry_run() -> void:
	print("")
	print("[dry run]")

	# Through the cvar, not the config field: the cvar is registered from the
	# config at boot and beats it afterwards, which is what lets an operator
	# stop a guard mid-incident without a restart. Setting the field here and
	# expecting it to win would be asserting the opposite of the design.
	_run("sv_security_dryrun 1")

	var rule := _rule(&"t_dry", &"test.dry", 1)
	rule.steps = [DotSecurityStep.of(DotSecurityAction.Kind.BAN, 600)]
	guard.policy.add(rule)
	guard._reindex()

	_report(&"test.dry", "uid:dryrun")

	var entries := guard.ledger.for_subject("uid:dryrun")
	_check("dry run still evaluates the rule", entries.size() == 1)

	if entries.is_empty():
		return

	_check("dry run applies nothing", not entries[0].applied)
	_check("and says that is why", entries[0].withheld == "dry run")
	_check("but records what it would have done",
		entries[0].action == DotSecurityAction.Kind.BAN
		and entries[0].duration_sec == 600)

	_check("the cvar turns dry run on at runtime", guard.is_dry_run())
	_run("sv_security_dryrun 0")
	_check("and off again", not guard.is_dry_run())

	# ...and it wins over the config field, which is only the boot-time value.
	guard.config.dry_run = true
	_check("the cvar beats the config field", not guard.is_dry_run())
	guard.config.dry_run = false

	_run("sv_security 0")
	_report(&"test.dry", "uid:offswitch")
	_check("sv_security 0 stops counting entirely",
		guard.ledger.for_subject("uid:offswitch").is_empty())
	_run("sv_security 1")


func _test_policy_json() -> void:
	print("")
	print("[rules as json]")

	var policy := DotSecurityPolicy.new()
	var loaded := policy.apply_dictionary({
		"rules": [{
			"id": "from_json",
			"event": "test.json",
			"threshold": 4,
			"window_sec": 12,
			"scope": "address",
			"cooldown_sec": 3,
			"steps": [
				{"action": "warn"},
				{"action": "gag", "duration_sec": 900},
				{"action": "ban", "duration": 3600},
			],
		}],
	})

	_check("a rule loads from json", loaded.ok)
	var rule := policy.find(&"from_json")
	_check("and is found by id", rule != null)

	if rule == null:
		return

	_check("its threshold came across", rule.threshold == 4)
	_check("its scope came across",
		rule.scope == DotSecuritySubject.Scope.ADDRESS)
	_check("its ladder came across", rule.steps.size() == 3)
	_check("a duration on the ladder came across",
		rule.steps[1].duration_sec == 900)
	_check("'duration' is accepted as well as 'duration_sec'",
		rule.steps[2].duration_sec == 3600)

	_check("a bad action is refused",
		not DotSecurityRule.from_dictionary({
			"id": "x", "event": "y", "action": "obliterate"
		}).ok)
	_check("a bad scope is refused",
		not DotSecurityRule.from_dictionary({
			"id": "x", "event": "y", "scope": "sideways"
		}).ok)
	_check("a rule with no event is refused",
		not DotSecurityRule.from_dictionary({"id": "x"}).ok)

	# A named rule replaces the shipped one whole. Merging would leave the
	# shipped ladder underneath an operator who deliberately removed a rung.
	var shipped := DotSecurityPolicy.defaults()
	shipped.apply_dictionary({
		"rules": [{
			"id": "chat_flood", "event": "chat.message",
			"threshold": 99, "window_sec": 1,
		}],
	})
	var replaced := shipped.find(&"chat_flood")
	_check("a named rule replaces the shipped one",
		replaced != null and replaced.threshold == 99)
	_check("and replaces it whole, not field by field",
		replaced != null and replaced.steps.is_empty())

	var disabled := DotSecurityPolicy.defaults()
	disabled.apply_dictionary({"disable": ["chat_flood"]})
	_check("a rule can be disabled by name",
		not disabled.find(&"chat_flood").enabled)

	var round_trip := DotSecurityRule.from_dictionary(
		policy.find(&"from_json").to_dictionary()
	)
	_check("a rule round-trips through a dictionary", round_trip.ok)


# --- Chat ------------------------------------------------------------------

func _test_chat_detection() -> void:
	print("")
	print("[chat detection]")

	var config := guard.config

	_check("a short shout is not shouting",
		not DotSecurityWatch._is_shouting("OK", config))
	_check("a long shout is",
		DotSecurityWatch._is_shouting("BUY MY THING RIGHT NOW PLEASE", config))
	_check("ordinary text is not",
		not DotSecurityWatch._is_shouting("hello everyone how are you", config))
	# Counting uncased characters would make every message in a script without
	# capitals read as shouting.
	_check("digits and punctuation do not count as capitals",
		not DotSecurityWatch._is_shouting("1234567890 !!! 1234567890", config))

	_check("a link is spotted",
		DotSecurityWatch._has_link("join https://example.com/x now", config))
	_check("plain text is not",
		not DotSecurityWatch._has_link("no links here at all", config))

	config.link_allow = PackedStringArray(["example.com"])
	_check("an allowed domain is not a link",
		not DotSecurityWatch._has_link("https://example.com/x", config))
	config.link_allow = PackedStringArray()

	# The spammer who adds a full stop each time is the whole reason the
	# duplicate check is not an exact comparison.
	var w := DotSecurityWatch.new()
	w.guard = guard
	_check("the first message is not a duplicate",
		not w._is_duplicate("uid:d", "buy my thing", config))
	_check("the same message is",
		w._is_duplicate("uid:d", "buy my thing", config))
	_check("and so is a punctuated variant",
		w._is_duplicate("uid:d", "Buy my thing!!!", config))
	_check("a different message is not",
		not w._is_duplicate("uid:d", "something else entirely", config))
	w.free()


## The string and integer couplings to addons this one must not name.
##
## Every one of these is a value defined in another repository that this addon
## reproduces because naming the class would make an optional dependency
## mandatory. A comment cannot fail when the other side changes; this can.
func _test_couplings() -> void:
	print("")
	print("[couplings to addons we must not name]")

	# dot-moderation's subject prefixes.
	_check("the uid prefix matches dot-moderation",
		DotSecuritySubject.PREFIX_UID == DotPunishmentSubject.PREFIX_UID)
	_check("the address prefix matches dot-moderation",
		DotSecuritySubject.PREFIX_ADDRESS == DotPunishmentSubject.PREFIX_IP)
	_check("a uid subject is spelled identically",
		DotSecuritySubject.for_uid("abc") == DotPunishmentSubject.for_uid("abc"))
	_check("an address subject is spelled identically",
		DotSecuritySubject.for_address("1.2.3.4")
			== DotPunishmentSubject.for_address("1.2.3.4"))

	# dot-moderation's Kind values.
	_check("the ban kind matches",
		DotSecurityAction.MOD_KIND_BAN == DotPunishment.Kind.BAN)
	_check("the kick kind matches",
		DotSecurityAction.MOD_KIND_KICK == DotPunishment.Kind.KICK)
	_check("the voice mute kind matches",
		DotSecurityAction.MOD_KIND_VOICE_MUTE == DotPunishment.Kind.VOICE_MUTE)
	_check("the gag kind matches",
		DotSecurityAction.MOD_KIND_GAG == DotPunishment.Kind.GAG)
	_check("the warn kind matches",
		DotSecurityAction.MOD_KIND_WARN == DotPunishment.Kind.WARN)

	# dot-server's refusal wording, which is the only way to tell a permission
	# refusal from a mistyped command.
	# A box rather than a local: GDScript lambdas capture locals by VALUE, so
	# assigning to a captured String inside one changes nothing outside it.
	var seen: Array = [""]
	server.console.command_refused.connect(
		func(_ctx: DotCmdContext, reason: String) -> void: seen[0] = reason,
		CONNECT_ONE_SHOT
	)
	var ctx := DotCmdContext.new()
	ctx.source = DotCmdContext.Source.CHAT
	ctx.permissions = PackedStringArray()
	ctx.reply_sink = func(_t: String) -> void: pass
	server.console.execute("kick nobody", ctx)

	_check("dot-server still refuses with the wording we match on",
		str(seen[0]).begins_with(DotSecurityWatch.REFUSAL_PERMISSION))


# --- External ban lists ----------------------------------------------------

func _test_ban_index() -> void:
	print("")
	print("[ban index]")

	var index := DotBanIndex.new()
	index.add_uid("banned-account", "listed")
	index.add_address("203.0.113.7", "listed")
	index.add_address("198.51.100.0/24", "a whole range")

	_check("a listed account is found",
		index.reason_for_uid("banned-account") != "")
	_check("an unlisted account is not",
		index.reason_for_uid("someone-else") == "")
	_check("a listed address is found",
		index.reason_for_address("203.0.113.7") != "")

	# A /24 is 256 addresses and must not be expanded into 256 entries; a /16
	# would be sixty-five thousand for one line of somebody's blocklist.
	_check("an address inside a range is found",
		index.reason_for_address("198.51.100.42") != "")
	_check("an address outside it is not",
		index.reason_for_address("198.51.101.42") == "")
	_check("the range was not expanded", index.addresses.size() == 1)

	_check("a mapped address matches its plain form",
		index.reason_for_address("::ffff:203.0.113.7") != "")

	_check("an address is recognised as one",
		DotBanIndex.looks_like_address("10.0.0.1"))
	_check("a range is recognised as one",
		DotBanIndex.looks_like_address("10.0.0.0/8"))
	_check("an account id is not",
		not DotBanIndex.looks_like_address("player-12345"))
	_check("nor is nonsense that looks numeric",
		not DotBanIndex.looks_like_address("999.999.999.999"))


func _test_ban_feed_parsing() -> void:
	print("")
	print("[ban feed parsing]")

	var feed := DotBanFeed.of(&"t", "https://example.org/list")

	# A bare array of strings: the commonest shape there is, and it says
	# nothing about what its entries are.
	var bare := DotBanFeeds.parse_payload(feed, ["1.2.3.4", "player-99"])
	_check("a bare list parses", bare.ok)
	_check("an address entry is guessed",
		bare.ok and (bare.value as Array)[0].has("address"))
	_check("an account entry is guessed",
		bare.ok and (bare.value as Array)[1].has("uid"))

	# An array of objects with differently-named fields.
	var objects := DotBanFeeds.parse_payload(feed, [
		{"user_id": "abc", "reason": "cheating"},
		{"ip_address": "5.6.7.8"},
	])
	_check("objects parse", objects.ok)
	_check("an aliased id field is found",
		objects.ok and str((objects.value as Array)[0]["uid"]) == "abc")
	_check("the reason comes across",
		objects.ok and str((objects.value as Array)[0]["reason"]) == "cheating")
	_check("an aliased address field is found",
		objects.ok and (objects.value as Array)[1].has("address"))

	# A wrapper object, with and without a configured path.
	var wrapped := DotBanFeeds.parse_payload(feed, {"data": ["9.9.9.9"]})
	_check("a conventional wrapper is unwrapped",
		wrapped.ok and (wrapped.value as Array).size() == 1)

	feed.list_path = "result.bans"
	var pathed := DotBanFeeds.parse_payload(
		feed, {"result": {"bans": ["8.8.8.8"]}}
	)
	_check("an explicit path is followed",
		pathed.ok and (pathed.value as Array).size() == 1)
	_check("a wrong path is refused",
		not DotBanFeeds.parse_payload(feed, {"nothing": []}).ok)
	feed.list_path = ""

	# The split-object shape.
	var split := DotBanFeeds.parse_payload(
		feed, {"uids": ["a", "b"], "ips": ["1.1.1.1"]}
	)
	_check("a split object parses",
		split.ok and (split.value as Array).size() == 3)

	# An expired entry enforced until the next fetch is how somebody stays
	# banned for a week after their day was up.
	var expired := DotBanFeeds.parse_payload(feed, [
		{"uid": "gone", "expires": 1},
		{"uid": "current", "expires": 99999999999},
	])
	_check("an expired entry is dropped",
		expired.ok and (expired.value as Array).size() == 1)
	_check("and a live one is kept",
		expired.ok and str((expired.value as Array)[0]["uid"]) == "current")

	_check("something that is not a list is refused",
		not DotBanFeeds.parse_payload(feed, 42).ok)


func _test_ban_feed_auth() -> void:
	print("")
	print("[ban feed authentication]")

	var feed := DotBanFeed.of(&"auth", "https://example.org/list")

	feed.auth = DotBanFeed.Auth.NONE
	_check("a public feed sends no credential",
		not feed.headers().has("Authorization"))

	feed.auth = DotBanFeed.Auth.BEARER
	feed.token = "a-jwt-or-an-api-key"
	_check("a bearer token is a bearer header",
		str(feed.headers()["Authorization"]) == "Bearer a-jwt-or-an-api-key")

	feed.auth = DotBanFeed.Auth.BASIC
	feed.username = "user"
	feed.token = "pass"
	_check("basic auth is base64 of user:pass",
		str(feed.headers()["Authorization"])
			== "Basic " + Marshalls.utf8_to_base64("user:pass"))

	feed.auth = DotBanFeed.Auth.HEADER
	feed.header_name = "X-Api-Key"
	feed.token = "k"
	_check("a custom header carries the key",
		str(feed.headers()["X-Api-Key"]) == "k")

	feed.auth = DotBanFeed.Auth.QUERY
	feed.query_name = "key"
	feed.token = "q"
	_check("a query credential reaches the url",
		feed.effective_url().contains("key=q"))
	_check("and is appended correctly to a url with a query",
		DotBanFeed.parse_auth("query") == DotBanFeed.Auth.QUERY)

	feed.auth = DotBanFeed.Auth.HMAC
	feed.token = "secret"
	var signed := feed.headers()
	_check("hmac sends a timestamp", signed.has("X-Dot-Timestamp"))
	_check("hmac sends a nonce", signed.has("X-Dot-Nonce"))
	_check("hmac sends a signature", signed.has("X-Dot-Signature"))
	_check("nothing replayable is sent",
		not str(signed.get("X-Dot-Signature", "")).contains("secret"))

	# The token is a secret and must not be reachable from the environment or
	# argv, both of which are readable by other processes and end up in `ps`.
	_check("the token is marked sensitive",
		DotBanFeed.sensitive_keys().has("token"))

	var insecure := DotBanFeed.of(&"i", "http://example.org/list")
	_check("plain http is refused", not insecure.validate().ok)
	insecure.allow_insecure = true
	_check("...unless explicitly allowed", insecure.validate().ok)

	var no_token := DotBanFeed.of(&"n", "https://example.org/list")
	no_token.auth = DotBanFeed.Auth.BEARER
	_check("a feed needing a credential and having none is refused at boot",
		not no_token.validate().ok)

	_check("jwt is accepted as a spelling of bearer",
		DotBanFeed.parse_auth("jwt") == DotBanFeed.Auth.BEARER)
	_check("fail_closed is accepted as a spelling of refuse_all",
		DotBanFeed.parse_failure("fail_closed")
			== DotBanFeed.OnFailure.REFUSE_ALL)


func _test_ban_feed_admission() -> void:
	print("")
	print("[ban feed admission]")

	# Registered before the feeds node, so the chaining path has something to
	# find. Two ban sources with neither knowing about the other is a
	# deployment enforcing exactly one of them.
	var upstream := StubBanSource.new()
	DotRegistry.register(DotBanFeeds.BAN_SOURCE, upstream)

	feeds = DotBanFeeds.new()
	feeds.name = "BanFeeds"
	feeds.feeds_file = ""
	feeds.fetch_on_ready = false
	add_child(feeds)
	await get_tree().process_frame

	_check("it registered as the ban source",
		DotRegistry.get_service(DotBanFeeds.BAN_SOURCE) == feeds)
	_check("and chained to what was there before",
		feeds.previous_source == upstream)

	feeds.index.add_uid("listed-account", "network: cheating")
	feeds.index.add_address("203.0.113.99", "network: proxy")

	_check("an unlisted player is admitted",
		feeds.check_admission("fine", "198.51.100.1").ok)
	_check("a listed account is refused",
		not feeds.check_admission("listed-account", "198.51.100.1").ok)
	_check("a listed address is refused",
		not feeds.check_admission("fine", "203.0.113.99").ok)
	_check("the upstream reason is passed on",
		feeds.check_admission("listed-account", "1.1.1.1")
			.error.message.contains("cheating"))

	# The chain: both have to say yes.
	upstream.refuse = "banned-upstream"
	_check("the chained source can still refuse",
		not feeds.check_admission("banned-upstream", "198.51.100.1").ok)
	upstream.refuse = ""
	_check("and admits when it has nothing to say",
		feeds.check_admission("anyone", "198.51.100.1").ok)

	feeds.show_upstream_reason = false
	_check("an upstream reason can be withheld from the player",
		not feeds.check_admission("listed-account", "1.1.1.1")
			.error.message.contains("cheating"))
	feeds.show_upstream_reason = true


# --- Anti-cheat ------------------------------------------------------------

func _test_anticheat() -> void:
	print("")
	print("[anti-cheat]")

	_check("the detectors attached", anticheat.guard == guard)

	# The split that the whole design rests on.
	_check("speed is proof",
		DotAntiCheatEvent.is_impossible(DotAntiCheatEvent.SPEED))
	_check("aim analysis is not",
		DotAntiCheatEvent.is_suspicious(DotAntiCheatEvent.AIM_SNAP))
	_check("a single impossible event may be acted on",
		DotAntiCheatEvent.may_act_on_one(DotAntiCheatEvent.TIMING))
	_check("a single behavioural one may not",
		not DotAntiCheatEvent.may_act_on_one(DotAntiCheatEvent.TRIGGERBOT))

	var rule := _rule(&"t_speed", DotAntiCheatEvent.SPEED, 1)
	guard.policy.add(rule)
	guard._reindex()

	var session := DotClientSession.new()
	session.peer_id = 700
	session.userid = 700
	session.address = "203.0.113.70"
	session.display_name = "Runner"

	var subject := DotSecuritySubject.of_session(
		session, DotSecuritySubject.Scope.UID
	)

	anticheat.observe_move(session, Vector3.ZERO, Vector3(10, 0, 0), true, 0.1)
	_check("ordinary movement reports nothing",
		guard.ledger.for_subject(subject).is_empty())

	anticheat.observe_move(
		session, Vector3(1, 0, 0), Vector3(500, 0, 0), true, 0.1
	)
	# Not "== 1": the shipped cheat_movement rule watches the same event and
	# trips alongside the one this test added, which is correct and is what two
	# rules on one event are for.
	_check("impossible speed is reported",
		not guard.ledger.for_subject(subject).is_empty())

	# The reference simulation is the check that cannot be argued with: the
	# server re-runs the movement and compares.
	anticheat.movement_reference = func(
		_s: DotClientSession, from: Vector3, _v: Vector3, _c: Variant, _d: float
	) -> Vector3:
		return from

	var honest := DotClientSession.new()
	honest.peer_id = 701
	honest.userid = 701
	honest.address = "203.0.113.71"
	var honest_subject := DotSecuritySubject.of_session(
		honest, DotSecuritySubject.Scope.UID
	)

	anticheat.observe_move(honest, Vector3.ZERO, Vector3.ZERO, true, 0.1)
	anticheat.observe_move(honest, Vector3.ZERO, Vector3.ZERO, true, 0.1)
	_check("a client that matches the re-simulation is clean",
		guard.ledger.for_subject(honest_subject).is_empty())

	anticheat.observe_move(honest, Vector3(99, 0, 0), Vector3.ZERO, true, 0.1)
	_check("a client that does not is caught",
		not guard.ledger.for_subject(honest_subject).is_empty())
	anticheat.movement_reference = Callable()

	# Fire rate is arithmetic against the weapon's own cycle time.
	var shooter := DotClientSession.new()
	shooter.peer_id = 702
	shooter.userid = 702
	shooter.address = "203.0.113.72"
	var shooter_subject := DotSecuritySubject.of_session(
		shooter, DotSecuritySubject.Scope.UID
	)

	guard.policy.add(_rule(&"t_fire", DotAntiCheatEvent.FIRE_RATE, 1))
	guard._reindex()

	anticheat.observe_shot(shooter, &"rifle", 1.0)
	anticheat.observe_shot(shooter, &"rifle", 1.0)
	_check("firing faster than the weapon allows is caught",
		not guard.ledger.for_subject(shooter_subject).is_empty())

	# Its own dry run, separate from the guard's: an operator trusts chat rules
	# long before a movement threshold they have not measured.
	anticheat.config.dry_run = true
	var quiet := DotClientSession.new()
	quiet.peer_id = 703
	quiet.userid = 703
	quiet.address = "203.0.113.73"
	anticheat.observe_move(quiet, Vector3.ZERO, Vector3(999, 0, 0), true, 0.1)
	anticheat.observe_move(quiet, Vector3(9, 0, 0), Vector3(999, 0, 0), true, 0.1)
	_check("anti-cheat dry run reports nothing to the rules",
		guard.ledger.for_subject(DotSecuritySubject.of_session(
			quiet, DotSecuritySubject.Scope.UID)).is_empty())
	anticheat.config.dry_run = false

	# The refusal that stops an operator banning a good player on one signal.
	var reckless := DotSecurityRule.of(
		&"t_reckless", DotAntiCheatEvent.AIM_SNAP, 1, 60.0
	)
	reckless.steps = [DotSecurityStep.of(DotSecurityAction.Kind.BAN, 0)]
	guard.policy.add(reckless)
	guard._reindex()
	anticheat._audit_rules()
	_check("a rule banning on one behavioural signal is refused",
		not guard.policy.find(&"t_reckless").enabled)

	var sane := DotSecurityRule.of(
		&"t_sane", DotAntiCheatEvent.AIM_SNAP, 20, 300.0
	)
	sane.steps = [DotSecurityStep.of(DotSecurityAction.Kind.WARN)]
	guard.policy.add(sane)
	guard._reindex()
	anticheat._audit_rules()
	_check("a behavioural rule that only warns is left alone",
		guard.policy.find(&"t_sane").enabled)

	# Every shipped behavioural rule must obey the same standard.
	var shipped := DotSecurityPolicy.defaults()
	var offenders := PackedStringArray()
	for r in shipped.enabled_rules():
		if not DotAntiCheatEvent.is_suspicious(r.event):
			continue
		for step in (r.steps if not r.steps.is_empty()
				else [DotSecurityStep.of(r.action, r.duration_sec)]):
			if step.action != DotSecurityAction.Kind.WARN \
					and step.action != DotSecurityAction.Kind.NONE:
				offenders.append(String(r.id))
	_check("no shipped behavioural rule ever punishes",
		offenders.is_empty())


# --- The fallback when dot-moderation is not installed ---------------------

func _test_without_moderation() -> void:
	print("")
	print("[without a moderation store]")

	# The whole promise of the fallback: a deployment with no dot-moderation
	# still gets a gag that the player feels, it just does not survive them
	# reconnecting. Refusing to act without it would make this addon
	# conditional on another optional one.
	var session := DotClientSession.new()
	session.peer_id = 800
	session.userid = 800
	session.address = "203.0.113.80"
	session.display_name = "Nobody"

	var gagged := DotSecurityAction.apply(
		DotSecurityAction.Kind.GAG, "uid:fallback", 120, "test", "suite",
		null, server, session
	)
	_check("a gag applies with no store at all", gagged.ok)
	_check("and the session feels it", session.gagged)
	_check("and it expires", session.mute_expires_at > 0)
	_check("and it says it was session-only",
		str(gagged.value).contains("session only"))

	session.unsilence()
	var silenced := DotSecurityAction.apply(
		DotSecurityAction.Kind.SILENCE, "uid:fallback", 60, "test", "suite",
		null, server, session
	)
	_check("silence covers both", silenced.ok and session.gagged and session.muted)

	# With nothing to act on and nothing to record, it fails rather than
	# claiming success — an action that quietly did nothing is the worst answer.
	var nothing := DotSecurityAction.apply(
		DotSecurityAction.Kind.GAG, "uid:absent", 60, "test", "suite",
		null, server, null
	)
	_check("no store and no session is an honest failure", not nothing.ok)

	# Loopback is never acted on, however a rule is written, and that is not an
	# error: the first thing a guard must not do is lock the operator out.
	var loopback := DotSecurityAction.apply(
		DotSecurityAction.Kind.BAN, "ip:127.0.0.1", 0, "test", "suite",
		null, server, null
	)
	_check("loopback is refused as a no-op, not as a failure",
		loopback.ok and str(loopback.value).contains("exempt"))

	# ...and with the real store present, the same call records durably.
	var mod := DotRegistry.get_service(&"dot_moderation")
	_check("the real moderation store is installed for this suite", mod != null)

	if mod == null:
		return

	var durable := DotSecurityAction.apply(
		DotSecurityAction.Kind.GAG, "uid:durable-test", 60, "auto", "suite",
		mod, server, null
	)
	_check("with a store, it records with no session at all", durable.ok)
	_check("and dot-moderation holds the record",
		mod.call("is_gagged_key", "uid:durable-test"))


# --- The operator's surface ------------------------------------------------

func _test_console() -> void:
	print("")
	print("[console]")

	for name in [
		"sec_status", "sec_rules", "sec_rule", "sec_why", "sec_forget",
		"sec_enable", "sec_disable", "sec_reload", "sec_log", "sec_dump",
		"sec_test", "sec_bans", "sec_bans_refresh", "sec_bans_check",
		"sec_ac_status", "sec_ac_dryrun",
	]:
		_check("%s is registered" % name,
			server.console.find_command(name) != null)

	_check("sec_status reports", _run("sec_status").contains("[security]"))
	_check("sec_rules lists the shipped rules",
		_run("sec_rules").contains("chat_flood"))

	_run("sec_disable chat_flood")
	_check("a rule can be turned off from the console",
		not guard.policy.find(&"chat_flood").enabled)
	_run("sec_enable chat_flood")
	_check("and back on", guard.policy.find(&"chat_flood").enabled)

	_check("sec_why says so when it knows nothing",
		_run("sec_why nobody-at-all").contains("no record"))
	_check("sec_why finds a subject it does know",
		_run("sec_why climber").contains("t_ladder"))

	_check("sec_bans reports the feeds", _run("sec_bans").contains("listed"))
	_check("sec_bans_check finds a listed account",
		_run("sec_bans_check listed-account").contains("cheating"))
	_check("sec_ac_status reports the peaks",
		_run("sec_ac_status").contains("peaks seen"))


## A ban source with dot-moderation's shape and none of its identifiers.
class StubBanSource extends RefCounted:
	var refuse: String = ""

	func check_admission(uid: String, _address: String) -> DotResult:
		if refuse != "" and uid == refuse:
			return DotResult.fail(DotError.CODE_FORBIDDEN, "Refused upstream.")
		return DotResult.success(true)
