@tool
class_name DotAntiCheatConfig
extends DotConfig

## Every threshold the detectors use, and the two that are not thresholds.
##
## [b]Almost all of this is per-game and none of the defaults are right for
## yours.[/b] A surf server's legitimate speed is a speed hack on a lobby; a
## game with a grapple teleports players on purpose. The defaults are wide
## enough to catch only the obvious, and an operator is expected to narrow them
## against `sec_ac_status`, which reports the largest value each detector has
## actually seen.

@export_group("Master")

## The detectors. Off costs nothing.
@export var enabled: bool = true

## Report only, never act — the same promise [member DotSecurityConfig.dry_run]
## makes, held separately because an operator commonly trusts chat rules long
## before they trust a movement threshold they have not tuned.
@export var dry_run: bool = true

## Refuse a rule that would act on a single behavioural signal.
##
## [b]On, and worth leaving on.[/b] Aim analysis describes a very good player as
## readily as a cheat, so a rule that bans on one instance will eventually ban
## somebody who did nothing — and the community remembers that far longer than
## it remembers the cheat. A behavioural rule needs a threshold above one, or
## this refuses it at boot and says why.
@export var refuse_single_shot_behavioural: bool = true

@export_group("Movement")

@export var watch_movement: bool = true

## Metres per second above which horizontal movement is impossible.
##
## [b]0 disables the check, and 0 is the right value until you have measured
## yours.[/b] It must be above anything the movement code can produce — a
## surf ramp, a boost pad, a grapple, a vehicle, knockback — and the honest way
## to set it is to run with it at 0 for a week and read the peak off
## `sec_ac_status`.
@export_range(0.0, 10000.0, 1.0) var max_horizontal_speed: float = 0.0

## Metres per second of rise above which upward movement is impossible.
@export_range(0.0, 10000.0, 1.0) var max_vertical_speed: float = 0.0

## Metres in one tick above which a position change is a teleport.
@export_range(0.0, 100000.0, 1.0) var max_tick_distance: float = 0.0

## Seconds off the ground above which a player is flying.
##
## Every game with a jump pad, a ladder, a glider or low gravity needs this
## raised or off.
@export_range(0.0, 600.0, 0.5) var max_airborne_sec: float = 0.0

## Fraction of the predicted position a re-simulation may differ by.
##
## Only used when a reference simulator is supplied — see
## [member DotAntiCheatDetectors.movement_reference]. This is the check that is
## actually unbypassable, and everything above is the envelope fallback for a
## game that cannot supply one.
@export_range(0.0, 100.0, 0.01) var reference_tolerance_m: float = 0.25

@export_group("Timing")

@export var watch_timing: bool = true

## How much faster than wall-clock a client's commands may arrive, as a ratio.
##
## 1.05 allows five per cent, which covers scheduling jitter and a burst after a
## stall. A timer cheat is usually 1.2 or more, so this is not a fine judgement.
@export_range(1.0, 3.0, 0.01) var max_time_ratio: float = 1.05

## Seconds of history the ratio is measured over. Short windows are all jitter.
@export_range(1.0, 300.0, 1.0) var timing_window_sec: float = 10.0

@export_group("Weapons")

@export var watch_fire_rate: bool = true

## Fraction of a weapon's stated cycle time that counts as too fast.
##
## 0.9 allows ten per cent for rounding and for a tick landing early. Below
## that, the client claimed to fire faster than its own weapon allows.
@export_range(0.1, 1.0, 0.01) var fire_interval_tolerance: float = 0.9

## Metres of slack added to a weapon's range before a hit counts as out of reach.
##
## Must cover lag compensation: the target was somewhere else when they fired.
@export_range(0.0, 100.0, 0.05) var reach_tolerance_m: float = 0.5

@export_group("Aim (behavioural)")

@export var watch_aim: bool = true

## Degrees in one tick above which a view change is called a snap.
@export_range(0.0, 360.0, 1.0) var snap_degrees: float = 60.0

## A snap only counts when it ends within this many degrees of a target.
##
## [b]The half that makes the check mean anything.[/b] Players spin constantly —
## to check behind them, to reposition, out of boredom. A fast turn that lands
## on nothing is a player; one that lands on a head is worth counting.
@export_range(0.0, 90.0, 0.5) var snap_on_target_degrees: float = 3.0

## Milliseconds between crosshair-on-target and firing, below which it is called
## a triggerbot.
##
## Human reaction to a visual cue does not go below about 100ms, and 80 leaves
## room for somebody already pulling the trigger.
@export_range(0.0, 1000.0, 5.0) var trigger_reaction_ms: float = 80.0

## Shots before the headshot ratio is judged at all.
##
## Small samples produce nonsense: three headshots out of three is a coincidence
## that happens on every server every hour.
@export_range(10, 10000, 10) var headshot_min_shots: int = 100

## Headshot fraction above which the ratio is reported.
@export_range(0.0, 1.0, 0.01) var headshot_ratio: float = 0.8

@export_group("Integrity")

@export var watch_integrity: bool = true

## Hashes a client may report. Empty accepts anything.
##
## [b]Worth having and worth not over-trusting.[/b] A client that lies about its
## build is caught; a client patched to report the right hash is not. It raises
## the cost of the laziest cheat and nothing more, which is still worth the
## fifteen lines.
@export var accepted_build_hashes: PackedStringArray = PackedStringArray()


func env_prefix() -> String:
	return "DOT_ANTICHEAT_"


func cli_prefix() -> String:
	return "--ac-"


func validate() -> DotResult:
	if max_time_ratio < 1.0:
		return DotResult.fail(
			DotError.CODE_INVALID,
			"max_time_ratio below 1 would flag every client.",
			"1.0 is exactly wall-clock; 1.05 is the usual allowance"
		)

	if fire_interval_tolerance <= 0.0 or fire_interval_tolerance > 1.0:
		return DotResult.fail(
			DotError.CODE_INVALID,
			"fire_interval_tolerance must be between 0 and 1."
		)

	return DotResult.success(self)
