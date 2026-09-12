@tool
class_name DotSecurityStep
extends Resource

## One rung of a rule's escalation ladder.
##
## [b]The ladder is the whole reason this addon is more than a rate limiter.[/b]
## A flat rule has one answer for a first offence and a fiftieth, so an operator
## picks between punishing a new player for typing too fast and letting a spammer
## run. Neither is the answer anybody wants. Steps let the rule say what it
## actually means: warn, then gag briefly, then gag properly, then remove.
##
## [codeblock]
## rule.steps = [
##     DotSecurityStep.of(DotSecurityAction.Kind.WARN),
##     DotSecurityStep.of(DotSecurityAction.Kind.GAG, 300),      # 5 minutes
##     DotSecurityStep.of(DotSecurityAction.Kind.GAG, 1800),     # 30 minutes
##     DotSecurityStep.of(DotSecurityAction.Kind.KICK),
##     DotSecurityStep.of(DotSecurityAction.Kind.BAN, 86400),    # a day
## ]
## [/codeblock]
##
## Offences past the last step repeat the last step, which is deliberate: a ladder
## that ran out and fell back to doing nothing would reward persistence.

@export var action: DotSecurityAction.Kind = DotSecurityAction.Kind.WARN

## Seconds the action lasts. 0 is permanent for a ban and meaningless for a kick.
@export var duration_sec: int = 0

## Told to the player when this step is applied. Empty uses the rule's reason.
@export var message: String = ""


static func of(
	p_action: DotSecurityAction.Kind,
	p_duration_sec: int = 0,
	p_message: String = ""
) -> DotSecurityStep:
	var step := DotSecurityStep.new()
	step.action = p_action
	step.duration_sec = p_duration_sec
	step.message = p_message
	return step


static func from_dictionary(raw: Dictionary) -> DotResult:
	var step := DotSecurityStep.new()

	var action_name := str(raw.get("action", "warn"))
	var parsed := DotSecurityAction.parse_kind(action_name)

	if parsed < 0:
		return DotResult.fail(
			DotError.CODE_INVALID,
			"'%s' is not an action." % action_name,
			"try none, warn, gag, voice_mute, silence, kick or ban"
		)

	step.action = parsed as DotSecurityAction.Kind
	step.duration_sec = int(raw.get("duration_sec", raw.get("duration", 0)))
	step.message = str(raw.get("message", ""))

	if step.duration_sec < 0:
		return DotResult.fail(
			DotError.CODE_INVALID, "A duration cannot be negative."
		)

	return DotResult.success(step)


func to_dictionary() -> Dictionary:
	var out := {"action": DotSecurityAction.kind_name(action)}
	if duration_sec > 0:
		out["duration_sec"] = duration_sec
	if message != "":
		out["message"] = message
	return out


func describe() -> String:
	var name := DotSecurityAction.kind_name(action)
	if DotSecurityAction.takes_duration(action) and duration_sec > 0:
		return "%s %s" % [name, DotSecurityAction.format_duration(duration_sec)]
	return name
