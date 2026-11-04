extends "res://examples/security_selftest_base.gd"

## Core rule, window, policy and chat sections of the suite.


func _test_attach() -> void:
	_section("[attach]")

	_check("the guard attached to the server", guard.server == server)
	_check("it registered itself", DotRegistry.get_service(
		DotSecurityManager.SERVICE) == guard)
	_check("the watcher found the guard", watch.guard == guard)
	_check("the shipped policy loaded", guard.policy.rules.size() > 0)
	_check("every shipped rule is valid", guard.policy.validate().ok)
	_check("it is not in dry run for this suite", not guard.is_dry_run())
	_done()



func _test_windows() -> void:
	print("")
	_section("[sliding window]")

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
	_done()



func _test_subjects() -> void:
	print("")
	_section("[subjects]")

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
	_done()



func _test_rules() -> void:
	print("")
	_section("[rules]")

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
	_done()


func _test_escalation() -> void:
	print("")
	_section("[escalation]")

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
	_done()


func _test_exemptions() -> void:
	print("")
	_section("[exemptions]")

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
	_done()


func _test_dry_run() -> void:
	print("")
	_section("[dry run]")

	# Through the cvar, not the config field: the cvar beats the config after boot, which is what lets an operator
	# stop a guard mid-incident without a restart.
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
	_done()


func _test_policy_json() -> void:
	print("")
	_section("[rules as json]")

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
	_done()



func _test_chat_detection() -> void:
	print("")
	_section("[chat detection]")

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
	_done()


## The string and integer couplings to addons this one must not name.
## Each is a value defined in another repository and reproduced here; a comment cannot fail when the other side changes, this can.
func _test_couplings() -> void:
	print("")
	_section("[couplings to addons we must not name]")

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

	# dot-server's refusal wording, the only way to tell a permission refusal from a mistyped command.
	# A box rather than a local: lambdas capture locals by VALUE, so assigning to a captured String changes nothing outside.
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
	_done()



