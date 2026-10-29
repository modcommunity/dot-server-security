class_name DotAntiCheatEvent
extends RefCounted

## What the anti-cheat detectors report: impossible (the server re-simulated and the claim does not fit; a rule may act at once) versus suspicious (also a very good player's day; count and show a human).
## Separate event names let an operator ban on one and report on the other (docs/anticheat.md).


## Moved further than the movement code could produce for that command.
const SPEED := &"cheat.speed"

## Position changed by more than any single tick could account for.
const TELEPORT := &"cheat.teleport"

## Stayed off the ground longer than gravity allows, or rose without cause.
const FLY := &"cheat.fly"

## Ended a tick inside world geometry.
const NOCLIP := &"cheat.noclip"

## Commands arriving faster than the client's own tick rate can generate them.
## A timer cheat and a speed hack both show here: both claim more simulation than wall-clock allows.
const TIMING := &"cheat.timing"

## Fired faster than the weapon's own cycle time.
const FIRE_RATE := &"cheat.fire_rate"

## Acted on something further away than the weapon can reach.
const REACH := &"cheat.reach"

## The client is not running what it says it is.
const INTEGRITY := &"cheat.integrity"

## A command number repeated, skipped or reordered beyond what loss explains.
const COMMAND_SEQUENCE := &"cheat.command_sequence"


## View angle changed faster than a hand moves, and landed on a target.
const AIM_SNAP := &"cheat.aim_snap"

## Aim is too smooth: a mouse has tremor and a script does not.
const AIM_SMOOTH := &"cheat.aim_smooth"

## Fired within a few milliseconds of the crosshair reaching a target.
const TRIGGERBOT := &"cheat.triggerbot"

## Recoil compensated too exactly over a burst.
const NO_RECOIL := &"cheat.no_recoil"

## Aim tracked a target through geometry it could not be seen through.
const TRACKING_THROUGH_WALL := &"cheat.tracking_through_wall"

## Headshot proportion far above what this server's population produces.
const HEADSHOT_RATIO := &"cheat.headshot_ratio"

## Everything the server proved.
const IMPOSSIBLE: Array[StringName] = [
	SPEED, TELEPORT, FLY, NOCLIP, TIMING, FIRE_RATE, REACH, INTEGRITY,
	COMMAND_SEQUENCE,
]

## Everything that is a judgement.
const SUSPICIOUS: Array[StringName] = [
	AIM_SNAP, AIM_SMOOTH, TRIGGERBOT, NO_RECOIL, TRACKING_THROUGH_WALL,
	HEADSHOT_RATIO,
]

const ALL: Array[StringName] = [
	SPEED, TELEPORT, FLY, NOCLIP, TIMING, FIRE_RATE, REACH, INTEGRITY,
	COMMAND_SEQUENCE,
	AIM_SNAP, AIM_SMOOTH, TRIGGERBOT, NO_RECOIL, TRACKING_THROUGH_WALL,
	HEADSHOT_RATIO,
]


static func is_impossible(name: StringName) -> bool:
	return IMPOSSIBLE.has(name)


static func is_suspicious(name: StringName) -> bool:
	return SUSPICIOUS.has(name)


## Whether a rule acting on one instance of this event can be defended.
## [DotAntiCheatConfig] uses it to refuse a configuration that would ban on a single behavioural signal.
static func may_act_on_one(name: StringName) -> bool:
	return is_impossible(name)
