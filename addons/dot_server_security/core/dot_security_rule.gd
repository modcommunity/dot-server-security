@tool
class_name DotSecurityRule
extends Resource

## One thing the guard watches for: "this many of that event, from one subject, within this window", then take the next step on the ladder.
## Everything else on it is about not catching the wrong person. Build one with [method of] and set [member steps]; the shipped set is in [DotSecurityPolicy].

## Identifier, used in `sec_status`, in the ledger and to disable one rule.
@export var id: StringName = &""

## Off entirely. A disabled rule counts nothing and costs nothing.
@export var enabled: bool = true

@export_group("What to watch")

## The event this counts. See [DotSecurityEvent] for the shipped vocabulary.
## Any name works, including a game's own.
@export var event: StringName = &""

## How many (by summed weight) before the rule trips.
@export_range(1, 10000, 1) var threshold: int = 5

## The window the count is taken over, in seconds.
## A sliding window, not a bucket: five messages at 0.9s and five at 1.1s are ten in two seconds, which a bucket resetting on the boundary sees as two fives and trips on neither.
@export_range(0.1, 86400.0, 0.1) var window_sec: float = 10.0

@export_group("Who it is against")

## Whether the count follows the account, the address, or both separately.
@export var scope: DotSecuritySubject.Scope = DotSecuritySubject.Scope.UID

@export_group("What to do")

## The escalation ladder. Empty falls back to [member action] every time.
@export var steps: Array[DotSecurityStep] = []

## The action taken when there are no [member steps]. Flat, every time.
@export var action: DotSecurityAction.Kind = DotSecurityAction.Kind.WARN

## Duration for [member action]. Ignored when [member steps] is set.
@export var duration_sec: int = 0

## How long an offence is remembered for escalation, in seconds.
## Separate from [member window_sec]: the window is how fast the behaviour must be to count at all, this is how long the server holds it against them. Spamming this morning and tonight should not restart at "warn".
@export_range(0.0, 2592000.0, 1.0) var offence_memory_sec: float = 3600.0

## Seconds after tripping during which this rule will not trip again for the same subject.
## Without it a rule whose action does not stop the behaviour (a warn) trips on every event, walking the whole ladder in a second. The setting an operator is least likely to think of.
@export_range(0.0, 3600.0, 0.5) var cooldown_sec: float = 5.0

@export_group("Who is exempt")

## Admin flags that make a subject immune to this rule.
## Checked against the session's own permissions, so an admin tidying a flood is not gagged for it.
@export var exempt_flags: PackedStringArray = PackedStringArray(["generic"])

## Immunity at or above which this rule does not act. 0 disables the check.
@export_range(0, 100, 1) var exempt_immunity: int = 0

## Never act on a player who has been connected less than this long, in seconds.
## Off by default. For behaviour a new player cannot have earned; leave off for connection and authentication rules, where the attacker is new.
@export_range(0.0, 3600.0, 1.0) var grace_sec: float = 0.0

@export_group("Reporting")

## Why, in the punishment record and in what the player is told.
## [code]{count}[/code], [code]{threshold}[/code], [code]{window}[/code], [code]{event}[/code] and [code]{offence}[/code] are substituted.
@export var reason: String = "Automatic: {count} {event} in {window}s"

## Log every trip at info rather than debug.
@export var loud: bool = true


static func of(
	p_id: StringName,
	p_event: StringName,
	p_threshold: int,
	p_window_sec: float
) -> DotSecurityRule:
	var rule := DotSecurityRule.new()
	rule.id = p_id
	rule.event = p_event
	rule.threshold = p_threshold
	rule.window_sec = p_window_sec
	return rule



## The step for the nth offence, counting from 1.
## Past the end of the ladder the last step repeats; reverting to nothing would reward persistence.
func step_for(offence: int) -> DotSecurityStep:
	if steps.is_empty():
		return DotSecurityStep.of(action, duration_sec)

	var index := clampi(offence - 1, 0, steps.size() - 1)
	var step := steps[index]

	if step == null:
		return DotSecurityStep.of(action, duration_sec)

	return step


## Whether this rule declines to act on a session, and why. Empty means it acts.
func exemption_for(session: DotClientSession) -> String:
	if session == null:
		# No session is not an exemption. Most of what a connect or RCON rule
		# catches has no session by definition, and treating that as exempt
		# would make those rules unable to fire at all.
		return ""

	if exempt_immunity > 0 and session.immunity >= exempt_immunity:
		return "immunity %d" % session.immunity

	for flag in exempt_flags:
		var name := String(flag).strip_edges()
		if name == "":
			continue
		if session.permissions.has(name):
			return "holds '%s'" % name

	if grace_sec > 0.0 and float(session.connected_seconds()) < grace_sec:
		return "connected %ds, grace is %ds" % [
			session.connected_seconds(), int(grace_sec)
		]

	return ""


func render_reason(count: float, offence: int) -> String:
	return reason \
		.replace("{count}", "%.0f" % count) \
		.replace("{threshold}", str(threshold)) \
		.replace("{window}", "%.0f" % window_sec) \
		.replace("{event}", String(event)) \
		.replace("{offence}", str(offence))



func validate() -> DotResult:
	if String(id).strip_edges() == "":
		return DotResult.fail(DotError.CODE_INVALID, "A rule needs an id.")

	if String(event).strip_edges() == "":
		return DotResult.fail(
			DotError.CODE_INVALID, "Rule '%s' watches no event." % id
		)

	if threshold < 1:
		return DotResult.fail(
			DotError.CODE_INVALID, "Rule '%s' has a threshold below 1." % id
		)

	if window_sec <= 0.0:
		return DotResult.fail(
			DotError.CODE_INVALID, "Rule '%s' has no window." % id
		)

	for step in steps:
		if step == null:
			return DotResult.fail(
				DotError.CODE_INVALID, "Rule '%s' has an empty step." % id
			)

	# Named rather than refused: a rule whose cooldown is shorter than its window
	# can walk its whole ladder inside one burst, which is legitimate for a rule
	# whose first step already removes the player and a mistake for any other.
	if cooldown_sec < window_sec and steps.size() > 1 \
			and not DotSecurityAction.is_removal(step_for(1).action):
		DotLog.warn(
			"security",
			"rule '%s' can escalate more than once inside its own window"
				% id,
			{"cooldown_sec": cooldown_sec, "window_sec": window_sec}
		)

	return DotResult.success(self)



## Reads a rule from a dictionary, which is how an operator writes one.
## The configuration surface that matters: a rule only expressible in GDScript is one most operators will not tune.
static func from_dictionary(raw: Dictionary) -> DotResult:
	var rule := DotSecurityRule.new()

	rule.id = StringName(str(raw.get("id", "")))
	rule.event = StringName(str(raw.get("event", "")))
	rule.enabled = bool(raw.get("enabled", true))
	rule.threshold = int(raw.get("threshold", 5))
	rule.window_sec = float(raw.get("window_sec", raw.get("window", 10.0)))
	rule.offence_memory_sec = float(raw.get("offence_memory_sec", 3600.0))
	rule.cooldown_sec = float(raw.get("cooldown_sec", 5.0))
	rule.exempt_immunity = int(raw.get("exempt_immunity", 0))
	rule.grace_sec = float(raw.get("grace_sec", 0.0))
	rule.loud = bool(raw.get("loud", true))

	if raw.has("reason"):
		rule.reason = str(raw["reason"])

	if raw.has("scope"):
		var scope := DotSecuritySubject.parse_scope(str(raw["scope"]))
		if scope < 0:
			return DotResult.fail(
				DotError.CODE_INVALID,
				"'%s' is not a scope." % str(raw["scope"]),
				"try uid, address or both"
			)
		rule.scope = scope as DotSecuritySubject.Scope

	if raw.has("exempt_flags"):
		var flags: Variant = raw["exempt_flags"]
		if flags is Array:
			var out := PackedStringArray()
			for flag in (flags as Array):
				out.append(str(flag))
			rule.exempt_flags = out

	if raw.has("action"):
		var parsed := DotSecurityAction.parse_kind(str(raw["action"]))
		if parsed < 0:
			return DotResult.fail(
				DotError.CODE_INVALID, "'%s' is not an action." % str(raw["action"])
			)
		rule.action = parsed as DotSecurityAction.Kind

	rule.duration_sec = int(raw.get("duration_sec", 0))

	if raw.has("steps"):
		var steps_raw: Variant = raw["steps"]
		if not (steps_raw is Array):
			return DotResult.fail(
				DotError.CODE_INVALID, "Rule '%s': steps must be a list." % rule.id
			)

		var built: Array[DotSecurityStep] = []
		for entry in (steps_raw as Array):
			if not (entry is Dictionary):
				return DotResult.fail(
					DotError.CODE_INVALID,
					"Rule '%s': every step must be an object." % rule.id
				)
			var step := DotSecurityStep.from_dictionary(entry as Dictionary)
			if not step.ok:
				return step.wrap("rule '%s'" % rule.id)
			built.append(step.value as DotSecurityStep)
		rule.steps = built

	return rule.validate()


func to_dictionary() -> Dictionary:
	var out := {
		"id": String(id),
		"enabled": enabled,
		"event": String(event),
		"threshold": threshold,
		"window_sec": window_sec,
		"scope": DotSecuritySubject.scope_name(scope),
		"cooldown_sec": cooldown_sec,
		"offence_memory_sec": offence_memory_sec,
		"reason": reason,
	}

	if exempt_immunity > 0:
		out["exempt_immunity"] = exempt_immunity
	if grace_sec > 0.0:
		out["grace_sec"] = grace_sec
	if not exempt_flags.is_empty():
		out["exempt_flags"] = Array(exempt_flags)

	if steps.is_empty():
		out["action"] = DotSecurityAction.kind_name(action)
		if duration_sec > 0:
			out["duration_sec"] = duration_sec
	else:
		var rungs: Array = []
		for step in steps:
			rungs.append(step.to_dictionary())
		out["steps"] = rungs

	return out


func describe() -> String:
	var ladder := PackedStringArray()
	if steps.is_empty():
		ladder.append(DotSecurityStep.of(action, duration_sec).describe())
	else:
		for step in steps:
			ladder.append(step.describe())

	return "%s: %d x %s in %.0fs per %s -> %s" % [
		id, threshold, event, window_sec,
		DotSecuritySubject.scope_name(scope),
		" then ".join(Array(ladder)),
	]
