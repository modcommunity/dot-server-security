class_name DotSecurityCommands
extends RefCounted

## The operator's view of the guard, as console commands and two cvars.
##
## [b]`sec_why` is the one that matters.[/b] An automatic punishment nobody can
## explain gets lifted blindly or refused blindly, and after the second time the
## operator turns the guard off. This answers which rule, which event, how many
## in how long, which rung of the ladder, and whether it was applied or only
## would have been.

const CHANNEL := "security"


static func register(guard: DotSecurityManager, console: DotConsole) -> void:
	_register_cvars(guard, console)
	_register_status(guard, console)
	_register_rules(guard, console)
	_register_subjects(guard, console)
	_register_bans(guard, console)
	_register_anticheat(guard, console)


# --- External ban lists ----------------------------------------------------
#
# Reached through the registry rather than held, because the feeds are a
# separate node an operator may not have added at all.

static func _bans() -> DotBanFeeds:
	return DotRegistry.get_service(DotBanFeeds.SERVICE) as DotBanFeeds


static func _register_bans(_guard: DotSecurityManager, console: DotConsole) -> void:
	console.command(
		"sec_bans",
		func(ctx: DotCmdContext) -> void:
			var feeds := _bans()
			if feeds == null:
				ctx.reply("No ban feeds are configured.")
				return
			ctx.reply("[ban feeds]")
			ctx.reply_lines(feeds.describe_lines()),
		"Show the external ban lists and when each was last fetched."
	)

	console.command(
		"sec_bans_refresh",
		func(ctx: DotCmdContext) -> void:
			var feeds := _bans()
			if feeds == null:
				ctx.reply("No ban feeds are configured.")
				return

			var id := ctx.arg(0)

			if id == "":
				ctx.reply("Refreshing every feed.")
				feeds.fetch_all()
				return

			var feed := feeds.find(StringName(id))
			if feed == null:
				ctx.reply("No feed called '%s'." % id)
				return

			ctx.reply("Refreshing '%s'." % id)
			feeds.fetch(feed),
		"Fetch the ban lists now. sec_bans_refresh [feed]",
		DotAdminFlags.CONFIG
	)

	console.command(
		"sec_bans_check",
		func(ctx: DotCmdContext) -> void:
			var feeds := _bans()
			if feeds == null:
				ctx.reply("No ban feeds are configured.")
				return

			var who := ctx.arg(0)
			if who == "":
				ctx.reply("sec_bans_check <uid|address>")
				return

			# Both, because an operator types one string and does not
			# necessarily know which kind the feed lists it as.
			var by_uid := feeds.index.reason_for_uid(who)
			var by_address := feeds.index.reason_for_address(who)

			if by_uid == "" and by_address == "":
				ctx.reply("'%s' is on none of the lists." % who)
				return

			if by_uid != "":
				ctx.reply("account: %s" % by_uid)
			if by_address != "":
				ctx.reply("address: %s" % by_address),
		"Ask whether somebody is on a fetched ban list. sec_bans_check <who>",
		DotAdminFlags.GENERIC
	)


# --- Anti-cheat ------------------------------------------------------------

static func _anticheat() -> DotAntiCheat:
	return DotRegistry.get_service(DotAntiCheat.SERVICE) as DotAntiCheat


static func _register_anticheat(
	_guard: DotSecurityManager, console: DotConsole
) -> void:
	console.command(
		"sec_ac_status",
		func(ctx: DotCmdContext) -> void:
			var ac := _anticheat()
			if ac == null:
				ctx.reply("No anti-cheat detectors are running.")
				return
			ctx.reply("[anti-cheat]")
			ctx.reply_lines(ac.describe_lines()),
		"Show the detectors, what they have seen, and the peaks to set "
			+ "thresholds from."
	)

	console.command(
		"sec_ac_dryrun",
		func(ctx: DotCmdContext) -> void:
			var ac := _anticheat()
			if ac == null:
				ctx.reply("No anti-cheat detectors are running.")
				return

			if ctx.argc() == 0:
				ctx.reply("Anti-cheat dry run is %s."
					% ("on" if ac.config.dry_run else "off"))
				return

			ac.config.dry_run = ctx.arg_bool(0, true)
			ctx.reply("Anti-cheat dry run is now %s."
				% ("on" if ac.config.dry_run else "off")),
		"Report detections without reporting them to the rules. "
			+ "sec_ac_dryrun [0|1]",
		DotAdminFlags.CONFIG
	)


static func _register_cvars(guard: DotSecurityManager, console: DotConsole) -> void:
	# Live rather than startup-only. An operator turns a guard off while the
	# thing it is doing wrong is happening, and one that needs a restart arrives
	# after they have already been driven to uninstall it.
	console.cvar(
		"sv_security",
		"1" if guard.config.enabled else "0",
		"Watch for abuse. 0 counts nothing and acts on nothing.",
		DotConVar.FLAG_ARCHIVE | DotConVar.FLAG_NOTIFY
	)

	console.cvar(
		"sv_security_dryrun",
		"1" if guard.config.dry_run else "0",
		"Count and log, never punish. The setting to leave on while tuning.",
		DotConVar.FLAG_ARCHIVE | DotConVar.FLAG_NOTIFY
	)


static func _register_status(guard: DotSecurityManager, console: DotConsole) -> void:
	console.command(
		"sec_status",
		func(ctx: DotCmdContext) -> void:
			ctx.reply("[security]")
			ctx.reply_lines(guard.describe_lines())

			var recent := guard.ledger.recent(10)
			if recent.is_empty():
				ctx.reply("")
				ctx.reply("nothing has tripped yet")
				return

			ctx.reply("")
			ctx.reply("[last %d]" % recent.size())
			for entry in recent:
				ctx.reply("  " + entry.describe()),
		"Show what the guard is doing and what has tripped lately."
	)

	console.command(
		"sec_log",
		func(ctx: DotCmdContext) -> void:
			var count := ctx.arg_int(0, 30)
			var recent := guard.ledger.recent(maxi(1, count))

			if recent.is_empty():
				ctx.reply("Nothing has tripped.")
				return

			for entry in recent:
				ctx.reply(entry.describe()),
		"Print the last N decisions. sec_log [count]",
		DotAdminFlags.GENERIC
	)


static func _register_rules(guard: DotSecurityManager, console: DotConsole) -> void:
	console.command(
		"sec_rules",
		func(ctx: DotCmdContext) -> void:
			var lines := guard.policy.describe_lines()
			if lines.is_empty():
				ctx.reply("No rules are configured.")
				return
			ctx.reply_lines(lines),
		"List every rule and what it does."
	)

	console.command(
		"sec_rule",
		func(ctx: DotCmdContext) -> void:
			var id := StringName(ctx.arg(0))
			var rule := guard.policy.find(id)

			if rule == null:
				ctx.reply("No rule called '%s'. Try sec_rules." % id)
				return

			ctx.reply(JSON.stringify(rule.to_dictionary(), "  ")),
		"Print one rule as the JSON an operator would write. sec_rule <id>",
		DotAdminFlags.GENERIC
	)

	console.command(
		"sec_enable",
		func(ctx: DotCmdContext) -> void:
			var res := guard.set_rule_enabled(StringName(ctx.arg(0)), true)
			if not res.ok:
				ctx.reply_error(res)
				return
			ctx.reply("Rule '%s' is on." % ctx.arg(0)),
		"Turn one rule on. sec_enable <id>",
		DotAdminFlags.GENERIC
	)

	console.command(
		"sec_disable",
		func(ctx: DotCmdContext) -> void:
			var res := guard.set_rule_enabled(StringName(ctx.arg(0)), false)
			if not res.ok:
				ctx.reply_error(res)
				return
			ctx.reply("Rule '%s' is off." % ctx.arg(0)),
		"Turn one rule off. sec_disable <id>",
		DotAdminFlags.GENERIC
	)

	console.command(
		"sec_reload",
		func(ctx: DotCmdContext) -> void:
			var res := guard.reload_rules()
			if not res.ok:
				ctx.reply_error(res)
				return
			ctx.reply("Reloaded: %d rules active." % int(res.value)),
		"Reread the rules file, so tuning does not need a restart.",
		DotAdminFlags.CONFIG
	)

	console.command(
		"sec_dump",
		func(ctx: DotCmdContext) -> void:
			var path := ctx.arg(0, guard.config.rules_file)
			var res := guard.policy.save_json_file(path)
			if not res.ok:
				ctx.reply_error(res)
				return
			ctx.reply("Wrote the effective rule set to %s." % path),
		"Write the rules in force to a file, to copy and edit. sec_dump [path]",
		DotAdminFlags.CONFIG
	)


static func _register_subjects(guard: DotSecurityManager, console: DotConsole) -> void:
	console.command(
		"sec_why",
		func(ctx: DotCmdContext) -> void:
			var needle := ctx.rest(0).strip_edges()

			if needle == "":
				ctx.reply("sec_why <name, account or address>")
				return

			var found := guard.ledger.search(needle)

			if found.is_empty():
				ctx.reply("The guard has no record matching '%s'." % needle)
				return

			ctx.reply("%d record(s) matching '%s':" % [found.size(), needle])
			for entry in found:
				ctx.reply("  " + entry.describe()),
		"Explain what the guard did to somebody, and why. sec_why <who>",
		DotAdminFlags.GENERIC
	)

	console.command(
		"sec_forget",
		func(ctx: DotCmdContext) -> void:
			var target := ctx.rest(0).strip_edges()

			if target == "":
				ctx.reply("sec_forget <subject|all>")
				return

			if target.to_lower() == "all":
				guard.forget_all()
				ctx.reply("Forgot every counter and every offence.")
				return

			# Accepts a bare uid or address as well as a prefixed subject,
			# because an operator reads a name out of `status` and types that.
			var subjects := PackedStringArray([target])
			if not DotSecuritySubject.is_uid(target) \
					and not DotSecuritySubject.is_address(target):
				subjects = PackedStringArray([
					DotSecuritySubject.for_uid(target),
					DotSecuritySubject.for_address(target),
				])

			var cleared := 0
			for subject in subjects:
				cleared += guard.forget(subject)

			# Said plainly, because this is what an operator runs after lifting a
			# punishment by hand: without it the next event escalates from where
			# the ladder left off and the person they just forgave is gagged
			# again for one message.
			ctx.reply("Cleared %d offence record(s) and every counter for %s."
				% [cleared, target]),
		"Forget a subject's counters and offence history. sec_forget <who|all>",
		DotAdminFlags.GENERIC
	)

	console.command(
		"sec_test",
		func(ctx: DotCmdContext) -> void:
			var event_name := ctx.arg(0)
			var who := ctx.arg(1)
			var times := maxi(1, ctx.arg_int(2, 1))

			if event_name == "" or who == "":
				ctx.reply("sec_test <event> <uid|address> [times]")
				ctx.reply("Events: %s" % ", ".join(
					Array(DotSecurityEvent.KNOWN).map(func(n): return String(n))
				))
				return

			var subject := who
			if not DotSecuritySubject.is_uid(who) \
					and not DotSecuritySubject.is_address(who):
				subject = DotSecuritySubject.for_uid(who)

			for _i in range(times):
				guard.report(DotSecurityEvent.make(
					StringName(event_name), subject, 1.0, {"source": "sec_test"}
				))

			ctx.reply("Reported %s x%d against %s." % [event_name, times, subject])
			ctx.reply("sec_status shows what it did."),
		"Feed the guard synthetic events, to check a rule fires. "
			+ "sec_test <event> <who> [times]",
		DotAdminFlags.CHEATS
	)
