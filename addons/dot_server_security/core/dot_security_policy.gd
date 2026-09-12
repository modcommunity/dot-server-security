@tool
class_name DotSecurityPolicy
extends Resource

## The rule set, and the defaults an operator starts from.
##
## [b]The shipped rules are deliberately timid.[/b] Every threshold here is one
## that an ordinary busy server will not reach and every first step is a warning.
## A guard that punishes a friendly community on its defaults is a guard that gets
## turned off, and a server with the addon installed and disabled is less safe
## than one that never installed it — because somebody believes it is protected.
##
## The ladders go somewhere, though. A subject that keeps going past a warning
## reaches a gag, then a long gag, then removal, which is what an operator wanted
## when they installed this and what they should not have to write themselves.
##
## Rules are replaced or extended from JSON, which is the surface that matters:
## a rule an operator can only express by editing GDScript is one most operators
## will never change.

## Rules, in the order they were added. Order does not affect evaluation.
@export var rules: Array[DotSecurityRule] = []


# --- The shipped set -------------------------------------------------------

## Every default rule. Each one is separately disable-able by id.
static func defaults() -> DotSecurityPolicy:
	var policy := DotSecurityPolicy.new()

	for rule in [
		_chat_flood(),
		_chat_repeat(),
		_chat_shouting(),
		_chat_links(),
		_chat_refused(),
		_command_denied(),
		_connect_flood(),
		_connect_churn(),
		_auth_failures(),
		_rcon_bruteforce(),
		_cheat_impossible(),
		_cheat_timing(),
		_cheat_fire_rate(),
		_cheat_reach(),
		_cheat_integrity(),
		_cheat_aim(),
		_cheat_trigger(),
	]:
		policy.rules.append(rule)

	return policy


## Six messages in ten seconds. The rule everybody installs this for.
static func _chat_flood() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"chat_flood", DotSecurityEvent.CHAT_MESSAGE, 6, 10.0
	)
	rule.scope = DotSecuritySubject.Scope.UID
	rule.cooldown_sec = 15.0
	rule.offence_memory_sec = 3600.0
	rule.reason = "Sending messages too quickly ({count} in {window}s)"
	rule.steps = [
		DotSecurityStep.of(
			DotSecurityAction.Kind.WARN, 0, "Slow down — you are sending messages very fast."
		),
		DotSecurityStep.of(DotSecurityAction.Kind.GAG, 300),
		DotSecurityStep.of(DotSecurityAction.Kind.GAG, 1800),
		DotSecurityStep.of(DotSecurityAction.Kind.KICK),
	]
	return rule


## The same line over and over, which a rate limit alone does not catch.
static func _chat_repeat() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"chat_repeat", DotSecurityEvent.CHAT_DUPLICATE, 3, 30.0
	)
	rule.scope = DotSecuritySubject.Scope.UID
	rule.cooldown_sec = 30.0
	rule.reason = "Repeating the same message ({count} times in {window}s)"
	rule.steps = [
		DotSecurityStep.of(
			DotSecurityAction.Kind.WARN, 0, "Please stop repeating yourself."
		),
		DotSecurityStep.of(DotSecurityAction.Kind.GAG, 600),
		DotSecurityStep.of(DotSecurityAction.Kind.GAG, 3600),
	]
	return rule


## Shouting. Off by default — plenty of communities simply do not mind.
static func _chat_shouting() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"chat_shouting", DotSecurityEvent.CHAT_CAPS, 4, 60.0
	)
	rule.enabled = false
	rule.scope = DotSecuritySubject.Scope.UID
	rule.cooldown_sec = 60.0
	rule.reason = "Shouting ({count} messages in {window}s)"
	rule.steps = [
		DotSecurityStep.of(DotSecurityAction.Kind.WARN, 0, "Please stop shouting."),
		DotSecurityStep.of(DotSecurityAction.Kind.GAG, 300),
	]
	return rule


## Link spam. Two links in a minute from one account is an advertiser.
static func _chat_links() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"chat_links", DotSecurityEvent.CHAT_LINK, 3, 60.0
	)
	rule.enabled = false
	rule.scope = DotSecuritySubject.Scope.UID
	rule.cooldown_sec = 60.0
	rule.reason = "Posting links ({count} in {window}s)"
	rule.steps = [
		DotSecurityStep.of(DotSecurityAction.Kind.WARN),
		DotSecurityStep.of(DotSecurityAction.Kind.GAG, 1800),
		DotSecurityStep.of(DotSecurityAction.Kind.KICK),
	]
	return rule


## Somebody hammering a chat limit they have already been told about.
static func _chat_refused() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"chat_refused", DotSecurityEvent.CHAT_REFUSED, 10, 30.0
	)
	rule.scope = DotSecuritySubject.Scope.UID
	rule.cooldown_sec = 30.0
	rule.reason = "Ignoring the chat limits ({count} refusals in {window}s)"
	rule.steps = [
		DotSecurityStep.of(DotSecurityAction.Kind.WARN),
		DotSecurityStep.of(DotSecurityAction.Kind.GAG, 600),
	]
	return rule


## Probing for commands they do not hold.
##
## The innocent version happens once. The other version happens fifty times.
static func _command_denied() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"command_probing", DotSecurityEvent.COMMAND_DENIED, 8, 30.0
	)
	rule.scope = DotSecuritySubject.Scope.UID
	rule.cooldown_sec = 60.0
	rule.reason = "Repeatedly running commands they do not hold ({count} in {window}s)"
	rule.steps = [
		DotSecurityStep.of(DotSecurityAction.Kind.WARN),
		DotSecurityStep.of(DotSecurityAction.Kind.KICK),
	]
	return rule


## Connection flood, per address, because there is no identity yet.
static func _connect_flood() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"connect_flood", DotSecurityEvent.CONNECT_ATTEMPT, 10, 20.0
	)
	rule.scope = DotSecuritySubject.Scope.ADDRESS
	rule.cooldown_sec = 30.0
	rule.offence_memory_sec = 86400.0
	# No grace and no flag exemption: the attacker is new by definition and has
	# no session to hold a permission on.
	rule.grace_sec = 0.0
	rule.exempt_flags = PackedStringArray()
	rule.reason = "Connecting too often ({count} attempts in {window}s)"
	rule.steps = [
		DotSecurityStep.of(DotSecurityAction.Kind.BAN, 300),
		DotSecurityStep.of(DotSecurityAction.Kind.BAN, 3600),
		DotSecurityStep.of(DotSecurityAction.Kind.BAN, 86400),
	]
	return rule


## Join, leave, join, leave. Every individual connection is legitimate.
static func _connect_churn() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"connect_churn", DotSecurityEvent.CONNECT_CHURN, 6, 120.0
	)
	rule.scope = DotSecuritySubject.Scope.ADDRESS
	rule.cooldown_sec = 120.0
	rule.exempt_flags = PackedStringArray()
	rule.reason = "Reconnecting repeatedly without playing ({count} in {window}s)"
	rule.steps = [
		DotSecurityStep.of(DotSecurityAction.Kind.BAN, 600),
		DotSecurityStep.of(DotSecurityAction.Kind.BAN, 7200),
	]
	return rule


## Authentication that keeps failing from one address.
static func _auth_failures() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"auth_failures", DotSecurityEvent.AUTH_FAILED, 8, 60.0
	)
	rule.scope = DotSecuritySubject.Scope.ADDRESS
	rule.cooldown_sec = 60.0
	rule.offence_memory_sec = 86400.0
	rule.exempt_flags = PackedStringArray()
	rule.reason = "Authentication failed {count} times in {window}s"
	rule.steps = [
		DotSecurityStep.of(DotSecurityAction.Kind.BAN, 900),
		DotSecurityStep.of(DotSecurityAction.Kind.BAN, 86400),
	]
	return rule


## A password spray against the remote console.
##
## [b]The most valuable rule here and the only one whose first step removes.[/b]
## dot-server already locks an address out after `rcon_max_failures`, but that
## lockout is per-process and forgotten on restart; this is what turns a spray
## into a record that outlives it. Nobody mistypes an RCON password five times.
static func _rcon_bruteforce() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"rcon_bruteforce", DotSecurityEvent.RCON_AUTH_FAILED, 5, 300.0
	)
	rule.scope = DotSecuritySubject.Scope.ADDRESS
	rule.cooldown_sec = 60.0
	rule.offence_memory_sec = 604800.0
	rule.exempt_flags = PackedStringArray()
	rule.reason = "Wrong RCON password {count} times in {window}s"
	rule.steps = [
		DotSecurityStep.of(DotSecurityAction.Kind.BAN, 3600),
		DotSecurityStep.of(DotSecurityAction.Kind.BAN, 0),
	]
	return rule


# --- Anti-cheat ------------------------------------------------------------
#
# Two kinds of rule, and the split is the whole of the honesty here.
#
# The IMPOSSIBLE ones act, because the server did the arithmetic: the client
# claimed something the game cannot produce. The BEHAVIOURAL ones only ever warn
# and tell the admins, because every one of them also describes a very good
# player on a very good day — and a community remembers a wrongly banned good
# player far longer than it remembers a cheat. DotAntiCheat refuses at boot to
# let a behavioural rule punish on a single detection; these are what it expects
# to find instead.
#
# None of them fire at all until an operator has measured their game: the
# envelope thresholds in DotAntiCheatConfig ship at 0, which is off, and the
# detector ships in its own dry run besides.

## Movement the movement code could not have produced.
static func _cheat_impossible() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"cheat_movement", DotAntiCheatEvent.SPEED, 5, 30.0
	)
	rule.scope = DotSecuritySubject.Scope.UID
	rule.cooldown_sec = 10.0
	rule.offence_memory_sec = 86400.0
	rule.reason = "Impossible movement ({count} in {window}s)"
	rule.steps = [
		DotSecurityStep.of(DotSecurityAction.Kind.WARN),
		DotSecurityStep.of(DotSecurityAction.Kind.KICK),
		DotSecurityStep.of(DotSecurityAction.Kind.BAN, 86400),
	]
	return rule


## More simulated time claimed than has elapsed: a speed hack or a timer cheat.
static func _cheat_timing() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"cheat_timing", DotAntiCheatEvent.TIMING, 3, 300.0
	)
	rule.scope = DotSecuritySubject.Scope.UID
	rule.cooldown_sec = 30.0
	rule.offence_memory_sec = 86400.0
	rule.reason = "Client clock does not match the server ({count} in {window}s)"
	rule.steps = [
		DotSecurityStep.of(DotSecurityAction.Kind.WARN),
		DotSecurityStep.of(DotSecurityAction.Kind.KICK),
		DotSecurityStep.of(DotSecurityAction.Kind.BAN, 86400),
	]
	return rule


## Firing faster than the weapon's own cycle time.
static func _cheat_fire_rate() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"cheat_fire_rate", DotAntiCheatEvent.FIRE_RATE, 8, 60.0
	)
	rule.scope = DotSecuritySubject.Scope.UID
	rule.cooldown_sec = 30.0
	rule.reason = "Firing faster than the weapon allows ({count} in {window}s)"
	rule.steps = [
		DotSecurityStep.of(DotSecurityAction.Kind.WARN),
		DotSecurityStep.of(DotSecurityAction.Kind.KICK),
		DotSecurityStep.of(DotSecurityAction.Kind.BAN, 86400),
	]
	return rule


## Hitting things further away than the weapon reaches.
static func _cheat_reach() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"cheat_reach", DotAntiCheatEvent.REACH, 8, 60.0
	)
	rule.scope = DotSecuritySubject.Scope.UID
	rule.cooldown_sec = 30.0
	rule.reason = "Hitting beyond the weapon's reach ({count} in {window}s)"
	rule.steps = [
		DotSecurityStep.of(DotSecurityAction.Kind.WARN),
		DotSecurityStep.of(DotSecurityAction.Kind.KICK),
	]
	return rule


## A client that is not running what it says it is.
##
## The one rule whose threshold is 1, and it is allowed to be: the client either
## reported an accepted build hash or it did not, and there is no good day on
## which a legitimate player reports a hash the operator never published.
static func _cheat_integrity() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"cheat_integrity", DotAntiCheatEvent.INTEGRITY, 1, 60.0
	)
	rule.scope = DotSecuritySubject.Scope.UID
	rule.cooldown_sec = 0.0
	rule.reason = "This client is not running an accepted build"
	rule.steps = [DotSecurityStep.of(DotSecurityAction.Kind.KICK)]
	return rule


## Aim that snaps onto targets. [b]Reports; never punishes.[/b]
static func _cheat_aim() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"cheat_aim_snap", DotAntiCheatEvent.AIM_SNAP, 20, 300.0
	)
	rule.scope = DotSecuritySubject.Scope.UID
	rule.cooldown_sec = 300.0
	rule.reason = "Aim snapped onto a target {count} times in {window}s"
	# WARN and nothing else, deliberately. This is a signal for a human to look
	# at a demo, not a verdict — and the ladder does not continue, because a
	# ladder is exactly how a behavioural signal turns into a wrongful ban.
	rule.steps = [DotSecurityStep.of(DotSecurityAction.Kind.WARN)]
	return rule


## Firing inside human reaction time. Reports; never punishes.
static func _cheat_trigger() -> DotSecurityRule:
	var rule := DotSecurityRule.of(
		&"cheat_triggerbot", DotAntiCheatEvent.TRIGGERBOT, 15, 300.0
	)
	rule.scope = DotSecuritySubject.Scope.UID
	rule.cooldown_sec = 300.0
	rule.reason = "Fired inside human reaction time {count} times in {window}s"
	rule.steps = [DotSecurityStep.of(DotSecurityAction.Kind.WARN)]
	return rule


# --- Access ----------------------------------------------------------------

func find(id: StringName) -> DotSecurityRule:
	for rule in rules:
		if rule != null and rule.id == id:
			return rule
	return null


func add(rule: DotSecurityRule) -> DotResult:
	if rule == null:
		return DotResult.fail(DotError.CODE_INVALID, "A rule cannot be null.")

	var valid := rule.validate()
	if not valid.ok:
		return valid

	var existing := find(rule.id)
	if existing != null:
		# Replaced rather than refused: a rules file naming a shipped id is an
		# operator overriding that rule, which is the whole point of the file.
		rules[rules.find(existing)] = rule
		return DotResult.success(rule)

	rules.append(rule)
	return DotResult.success(rule)


func remove(id: StringName) -> bool:
	var existing := find(id)
	if existing == null:
		return false
	rules.erase(existing)
	return true


func enabled_rules() -> Array[DotSecurityRule]:
	var out: Array[DotSecurityRule] = []
	for rule in rules:
		if rule != null and rule.enabled:
			out.append(rule)
	return out


## Rules watching one event. Built per call; the manager indexes them itself.
func for_event(event: StringName) -> Array[DotSecurityRule]:
	var out: Array[DotSecurityRule] = []
	for rule in rules:
		if rule != null and rule.enabled and rule.event == event:
			out.append(rule)
	return out


func validate() -> DotResult:
	var seen: Dictionary = {}

	for rule in rules:
		if rule == null:
			return DotResult.fail(DotError.CODE_INVALID, "A rule is null.")

		var valid := rule.validate()
		if not valid.ok:
			return valid

		if seen.has(rule.id):
			# Two rules with one id makes `sec_disable <id>` ambiguous and the
			# ledger unreadable. A JSON file replacing a shipped rule goes
			# through add(), which is why this only catches a genuine mistake.
			return DotResult.fail(
				DotError.CODE_INVALID,
				"Two rules share the id '%s'." % rule.id
			)
		seen[rule.id] = true

	return DotResult.success(self)


# --- Serialisation ---------------------------------------------------------

## Layers a JSON file over this policy.
##
## ```json
## { "rules": [ { "id": "chat_flood", "threshold": 4, "window_sec": 8 } ] }
## ```
##
## [b]A named rule is replaced whole, not merged field by field.[/b] Merging
## reads better in an example and is worse in practice: an operator who removes
## a step from their copy of a rule expects it gone, and a merge would keep the
## shipped ladder underneath and apply it. The dumped file is a complete rule
## set for exactly this reason — copy it, edit it, and what you see is what runs.
func apply_json_file(path: String) -> DotResult:
	if path.strip_edges() == "":
		return DotResult.success(self)

	if not FileAccess.file_exists(path):
		# Not an error. The common case is an operator who has not written one,
		# and the shipped defaults are a complete, working rule set.
		return DotResult.success(self)

	var file := FileAccess.open(path, FileAccess.READ)
	if file == null:
		return DotResult.failure(DotError.from_engine(
			FileAccess.get_open_error(), "opening %s" % path
		))

	var text := file.get_as_text()
	file.close()

	var parsed: Variant = JSON.parse_string(text)
	if parsed == null or typeof(parsed) != TYPE_DICTIONARY:
		return DotResult.fail(
			DotError.CODE_PARSE, "%s is not a JSON object." % path
		)

	return apply_dictionary(parsed as Dictionary).wrap(path)


func apply_dictionary(tree: Dictionary) -> DotResult:
	if tree.has("replace_defaults") and bool(tree["replace_defaults"]):
		rules.clear()

	if tree.has("disable"):
		var disable: Variant = tree["disable"]
		if disable is Array:
			for id in (disable as Array):
				var rule := find(StringName(str(id)))
				if rule != null:
					rule.enabled = false

	if not tree.has("rules"):
		return validate()

	var raw: Variant = tree["rules"]
	if not (raw is Array):
		return DotResult.fail(DotError.CODE_INVALID, "'rules' must be a list.")

	for entry in (raw as Array):
		if not (entry is Dictionary):
			return DotResult.fail(
				DotError.CODE_INVALID, "Every rule must be an object."
			)

		var built := DotSecurityRule.from_dictionary(entry as Dictionary)
		if not built.ok:
			return built

		var added := add(built.value as DotSecurityRule)
		if not added.ok:
			return added

	return validate()


func to_dictionary() -> Dictionary:
	var out: Array = []
	for rule in rules:
		if rule != null:
			out.append(rule.to_dictionary())
	return {"replace_defaults": true, "rules": out}


## Writes the effective rule set, for an operator to read and copy.
func save_json_file(path: String) -> DotResult:
	var dir := path.get_base_dir()
	if dir != "" and not DirAccess.dir_exists_absolute(dir):
		DirAccess.make_dir_recursive_absolute(dir)

	var file := FileAccess.open(path, FileAccess.WRITE)
	if file == null:
		return DotResult.failure(DotError.from_engine(
			FileAccess.get_open_error(), "writing %s" % path
		))

	file.store_string(JSON.stringify(to_dictionary(), "  "))
	file.close()
	return DotResult.success(path)


func describe_lines() -> PackedStringArray:
	var out := PackedStringArray()
	for rule in rules:
		if rule == null:
			continue
		out.append("%s %s" % ["[on] " if rule.enabled else "[off]", rule.describe()])
	return out
