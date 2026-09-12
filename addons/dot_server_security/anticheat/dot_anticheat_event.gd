class_name DotAntiCheatEvent
extends RefCounted

## What the anti-cheat detectors report, and the honest line through the middle
## of it.
##
## [b]Two kinds of signal, and conflating them is the mistake every home-grown
## anti-cheat makes.[/b]
##
## [b]Impossible[/b] — the server re-simulated what the client claimed and the
## claim does not fit. Moving further in a tick than the movement code can
## produce, firing faster than the weapon allows, a tick rate that does not match
## the clock. These are facts about arithmetic, not opinions about a player, and
## a rule may act on one of them immediately. The predictive anti-cheats that
## work are built on nothing else: they flag only what is physically impossible,
## so they cannot be argued with and they do not flag a player for being good or
## for having a bad connection.
##
## [b]Suspicious[/b] — the behaviour is unusual. Aim that snaps, aim that is too
## smooth, a headshot rate three standard deviations out, firing the instant a
## target crosses the crosshair. Every one of these is also a description of a
## very good player on a very good day, so a rule acting on a single instance
## will eventually ban somebody who did nothing. They are worth counting, worth
## accumulating, and worth showing to a human.
##
## The two are separate event names so an operator can put a ban on one and a
## report on the other, which is the configuration they actually want.

# --- Impossible: the server did the arithmetic -----------------------------

## Moved further than the movement code could produce for that command.
const SPEED := &"cheat.speed"

## Position changed by more than any single tick could account for.
const TELEPORT := &"cheat.teleport"

## Stayed off the ground longer than gravity allows, or rose without cause.
const FLY := &"cheat.fly"

## Ended a tick inside world geometry.
const NOCLIP := &"cheat.noclip"

## Commands arriving faster than the client's own tick rate can generate them.
##
## A timer cheat and a speed hack both show here, because both come down to
## claiming more simulation than wall-clock time allows.
const TIMING := &"cheat.timing"

## Fired faster than the weapon's own cycle time.
const FIRE_RATE := &"cheat.fire_rate"

## Acted on something further away than the weapon can reach.
const REACH := &"cheat.reach"

## The client is not running what it says it is.
const INTEGRITY := &"cheat.integrity"

## A command number repeated, skipped or reordered beyond what loss explains.
const COMMAND_SEQUENCE := &"cheat.command_sequence"

# --- Suspicious: a human should look ---------------------------------------

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
##
## Used by [DotAntiCheatConfig] to refuse a configuration that would ban on a
## single behavioural signal — which is how an anti-cheat bans a good player and
## loses a community.
static func may_act_on_one(name: StringName) -> bool:
	return is_impossible(name)
