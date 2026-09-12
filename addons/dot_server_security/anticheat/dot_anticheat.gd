@tool
class_name DotAntiCheat
extends Node

## Server-side detectors, reporting into the same rule engine everything else does.
##
## A detection is a [DotSecurityEvent] like any other, so the whole of the rule
## machinery — sliding windows, thresholds, escalation ladders, exemptions, the
## ledger, dry run, `sec_why` — applies to cheating without a second copy of any
## of it. "Three impossible speeds in a minute, then ban" is a rule, not code.
##
## [codeblock]
## var ac := DotAntiCheat.new()
## ac.config.max_horizontal_speed = 420.0     # measured, not guessed
## server.add_child(ac)
##
## # From the game, once per simulated tick:
## ac.observe_move(session, position, velocity, on_ground, delta)
## ac.observe_shot(session, weapon_id, cycle_time_sec)
## [/codeblock]
##
## [b]What this cannot do, stated plainly, because the alternative is an operator
## believing otherwise.[/b]
##
## There is no client-side component here and there will not be one: a Godot
## game ships its own script code to the player, and anything this addon ran on
## their machine could be read, patched or replayed by anyone who cared. Memory
## scanning, driver-level attestation and screenshot capture are the province of
## a signed native anti-cheat and are not honestly buildable here.
##
## So this catches what a server can prove and reports what a server can notice.
## It will not detect a well-written wallhack — nothing server-side reliably
## does. [b]The mitigation for that is not detection, it is not sending the
## data[/b]: interest management, which belongs in the netcode, is the only thing
## that actually stops it. A player whose client was never told where the enemy
## is cannot draw a box around them.

const CHANNEL := "anticheat"
const SERVICE := &"dot_anticheat"

## A detector fired. [param impossible] separates proof from suspicion.
signal detected(
	session: DotClientSession, kind: StringName, impossible: bool, detail: Dictionary
)

@export_group("Wiring")

@export var guard_ref: DotNodeRef = null

@export_group("Configuration")

@export var config: DotAntiCheatConfig = null

@export var config_file: String = "user://cfg/anticheat.json"

@export_group("Reference simulation")

## A callable that re-simulates one tick, for the check that cannot be bypassed.
##
## [b]This is the difference between an anti-cheat and a threshold.[/b] Given the
## command a client sent and the state it started from, a deterministic movement
## system can say exactly where that client should have ended up; anything else
## is a claim the server can reject. The envelope settings
## ([member DotAntiCheatConfig.max_horizontal_speed] and the rest) exist only
## for a game whose movement cannot be re-run, and they are guesses by
## comparison — wide enough to miss a careful cheat, narrow enough to catch a
## legitimate boost pad nobody thought about.
##
## Signature: [code]func(session, from_position, from_velocity, command, delta)
## -> Vector3[/code], returning the position the server believes in.
##
## This family's first-person controller is already command-driven and
## deterministic precisely so a server can reconcile it, so a game using it has
## the hard half done.
@export var movement_reference: Callable = Callable()

var guard: DotSecurityManager = null

## peer -> tracking state
var _tracks: Dictionary = {}

## Largest values actually seen, for an operator setting thresholds.
var _peak_speed: float = 0.0
var _peak_vertical: float = 0.0
var _peak_tick_distance: float = 0.0
var _peak_time_ratio: float = 1.0
var _detections: Dictionary = {}


func _ready() -> void:
	if Engine.is_editor_hint():
		return

	if config == null:
		config = DotAntiCheatConfig.new()

	if config_file != "":
		config.apply_json_file(config_file)

	config.apply_env()
	config.apply_cli()

	var valid := config.validate()
	if not valid.ok:
		DotLog.error(
			CHANNEL, "the anti-cheat config is wrong", {"detail": valid.error.message}
		)
		return

	if guard_ref == null:
		guard_ref = DotNodeRef.of_service(DotSecurityManager.SERVICE)

	if guard_ref.mode == DotNodeRef.Mode.REGISTRY \
			and DotRegistry.get_service(guard_ref.service) == null:
		var waited := await DotRegistry.await_service(guard_ref.service, 10.0)
		if not waited.ok:
			DotLog.warn(CHANNEL, "no security manager: detections go nowhere")
			return

	guard = guard_ref.resolve_or_null(self, CHANNEL) as DotSecurityManager
	DotRegistry.register(SERVICE, self)

	if guard != null:
		_audit_rules()

	DotLog.info(
		CHANNEL,
		"detectors up",
		{
			"dry_run": config.dry_run,
			"reference": movement_reference.is_valid(),
			"envelope": config.max_horizontal_speed > 0.0,
		}
	)

	if not movement_reference.is_valid() and config.max_horizontal_speed <= 0.0:
		# Both halves off is a legitimate first-week configuration and an easy
		# thing to leave that way by accident, so it is named rather than silent.
		DotLog.info(
			CHANNEL,
			"movement is not being checked: set a reference simulator, or "
			+ "measure max_horizontal_speed from sec_ac_status"
		)


func _exit_tree() -> void:
	DotRegistry.unregister_instance(SERVICE, self)


## Refuses a rule that would act on one behavioural signal.
##
## An operator who writes `cheat.aim_snap, threshold 1, ban` has written a rule
## that will eventually ban a good player, and they will not find out until it
## does. Named at boot, when it can still be changed.
func _audit_rules() -> void:
	if not config.refuse_single_shot_behavioural or guard.policy == null:
		return

	for rule in guard.policy.enabled_rules():
		if not DotAntiCheatEvent.is_suspicious(rule.event):
			continue
		if rule.threshold > 1:
			continue
		if rule.step_for(1).action == DotSecurityAction.Kind.NONE \
				or rule.step_for(1).action == DotSecurityAction.Kind.WARN:
			continue

		rule.enabled = false
		DotLog.error(
			CHANNEL,
			"rule '%s' would punish a single behavioural detection and has been "
				% rule.id + "disabled",
			{
				"event": String(rule.event),
				"why": "aim analysis describes a very good player as readily as "
					+ "a cheat; raise the threshold or make the first step a warn",
			}
		)


# --- What a game reports ---------------------------------------------------

## One simulated tick of a player's movement.
##
## [param command] is whatever the game's controller took as input; it is passed
## straight back to [member movement_reference] and is otherwise unread.
func observe_move(
	session: DotClientSession,
	position: Vector3,
	velocity: Vector3,
	on_ground: bool,
	delta: float,
	command: Variant = null
) -> void:
	if not _running() or not config.watch_movement or session == null:
		return
	if delta <= 0.0:
		return

	var track := _track(session)
	var previous: Vector3 = track["position"]
	var had_previous: bool = track["seen"]

	track["position"] = position
	track["velocity"] = velocity
	track["seen"] = true

	# The unbypassable check, when the game can supply it: re-run the movement
	# and compare. Everything below is the envelope fallback.
	if movement_reference.is_valid() and had_previous:
		var expected: Variant = movement_reference.call(
			session, previous, track["last_velocity"], command, delta
		)
		if expected is Vector3:
			var drift := (position - (expected as Vector3)).length()
			if drift > config.reference_tolerance_m:
				_report(
					session, DotAntiCheatEvent.SPEED, drift, {
						"drift_m": drift,
						"tolerance_m": config.reference_tolerance_m,
					}
				)

	track["last_velocity"] = velocity

	var horizontal := Vector2(velocity.x, velocity.z).length()
	_peak_speed = maxf(_peak_speed, horizontal)
	_peak_vertical = maxf(_peak_vertical, velocity.y)

	if config.max_horizontal_speed > 0.0 \
			and horizontal > config.max_horizontal_speed:
		_report(session, DotAntiCheatEvent.SPEED, horizontal, {
			"speed": horizontal, "limit": config.max_horizontal_speed
		})

	if config.max_vertical_speed > 0.0 and velocity.y > config.max_vertical_speed:
		_report(session, DotAntiCheatEvent.FLY, velocity.y, {
			"rise": velocity.y, "limit": config.max_vertical_speed
		})

	if had_previous:
		var moved := (position - previous).length()
		_peak_tick_distance = maxf(_peak_tick_distance, moved)

		if config.max_tick_distance > 0.0 and moved > config.max_tick_distance:
			_report(session, DotAntiCheatEvent.TELEPORT, moved, {
				"metres": moved, "limit": config.max_tick_distance
			})

	if on_ground:
		track["airborne_sec"] = 0.0
	else:
		track["airborne_sec"] = float(track["airborne_sec"]) + delta
		if config.max_airborne_sec > 0.0 \
				and float(track["airborne_sec"]) > config.max_airborne_sec:
			_report(
				session, DotAntiCheatEvent.FLY, float(track["airborne_sec"]),
				{"airborne_sec": track["airborne_sec"]}
			)
			# Reset, or every subsequent tick of one long jump reports again and
			# walks an escalation ladder over a single event.
			track["airborne_sec"] = 0.0


## One command from a client, for the timing check.
##
## [param client_delta] is how much simulated time the client claims this command
## covers. A client claiming more simulated time than has actually elapsed is
## the shape both a speed hack and a timer cheat take.
func observe_command(
	session: DotClientSession, client_delta: float, sequence: int = -1
) -> void:
	if not _running() or not config.watch_timing or session == null:
		return

	var track := _track(session)
	var now := Time.get_ticks_msec()

	if sequence >= 0:
		var last_seq := int(track["sequence"])
		if last_seq >= 0 and sequence <= last_seq:
			# Repeated or reordered. Some of this is ordinary packet loss, which
			# is why it is an event to be counted rather than acted on directly.
			_report(session, DotAntiCheatEvent.COMMAND_SEQUENCE, 1.0, {
				"got": sequence, "last": last_seq
			})
		track["sequence"] = sequence

	track["claimed_sec"] = float(track["claimed_sec"]) + client_delta

	var began := int(track["timing_began_ms"])
	if began <= 0:
		track["timing_began_ms"] = now
		return

	var elapsed := float(now - began) / 1000.0
	if elapsed < config.timing_window_sec:
		return

	var ratio := float(track["claimed_sec"]) / maxf(elapsed, 0.001)
	_peak_time_ratio = maxf(_peak_time_ratio, ratio)

	if ratio > config.max_time_ratio:
		_report(session, DotAntiCheatEvent.TIMING, ratio, {
			"ratio": ratio, "limit": config.max_time_ratio
		})

	track["claimed_sec"] = 0.0
	track["timing_began_ms"] = now


## One shot. [param cycle_time_sec] is what the weapon says it allows.
func observe_shot(
	session: DotClientSession,
	weapon_id: StringName = &"",
	cycle_time_sec: float = 0.0
) -> void:
	if not _running() or not config.watch_fire_rate or session == null:
		return

	var track := _track(session)
	var now := Time.get_ticks_msec()
	var key := "fired_%s" % weapon_id
	var last := int(track.get(key, 0))
	track[key] = now

	track["shots"] = int(track["shots"]) + 1

	if last <= 0 or cycle_time_sec <= 0.0:
		return

	var interval := float(now - last) / 1000.0
	var allowed := cycle_time_sec * config.fire_interval_tolerance

	if interval < allowed:
		_report(session, DotAntiCheatEvent.FIRE_RATE, 1.0, {
			"interval_sec": interval,
			"weapon": String(weapon_id),
			"allowed_sec": allowed,
		})


## One hit, for the reach check. Distances in metres.
func observe_hit(
	session: DotClientSession,
	distance_m: float,
	weapon_range_m: float,
	headshot: bool = false
) -> void:
	if not _running() or session == null:
		return

	var track := _track(session)

	if headshot:
		track["headshots"] = int(track["headshots"]) + 1

	if weapon_range_m > 0.0 \
			and distance_m > weapon_range_m + config.reach_tolerance_m:
		_report(session, DotAntiCheatEvent.REACH, distance_m, {
			"distance_m": distance_m, "range_m": weapon_range_m
		})

	_check_headshot_ratio(session, track)


## A view-angle change, for the aim detectors. Degrees.
##
## [param to_target_degrees] is how far the new aim is from the nearest enemy;
## pass a large number when there is none. A fast turn onto nothing is a player
## looking around, and counting it would flag everybody.
func observe_aim(
	session: DotClientSession,
	delta_degrees: float,
	to_target_degrees: float,
	_delta: float
) -> void:
	if not _running() or not config.watch_aim or session == null:
		return

	if delta_degrees >= config.snap_degrees \
			and to_target_degrees <= config.snap_on_target_degrees:
		_report(session, DotAntiCheatEvent.AIM_SNAP, 1.0, {
			"degrees": delta_degrees, "off_target": to_target_degrees
		})

	var track := _track(session)

	if to_target_degrees <= config.snap_on_target_degrees:
		if int(track["on_target_since_ms"]) <= 0:
			track["on_target_since_ms"] = Time.get_ticks_msec()
	else:
		track["on_target_since_ms"] = 0


## Called when a shot is fired, to judge how long the crosshair had been on target.
func observe_trigger(session: DotClientSession) -> void:
	if not _running() or not config.watch_aim or session == null:
		return

	var track := _track(session)
	var since := int(track["on_target_since_ms"])

	if since <= 0:
		return

	var reaction := float(Time.get_ticks_msec() - since)
	if reaction <= config.trigger_reaction_ms:
		_report(session, DotAntiCheatEvent.TRIGGERBOT, 1.0, {
			"reaction_ms": reaction, "limit_ms": config.trigger_reaction_ms
		})


## What the client says it is running.
func observe_build(session: DotClientSession, build_hash: String) -> void:
	if not _running() or not config.watch_integrity or session == null:
		return
	if config.accepted_build_hashes.is_empty():
		return

	if not config.accepted_build_hashes.has(build_hash):
		_report(session, DotAntiCheatEvent.INTEGRITY, 1.0, {
			"reported": build_hash
		})


func _check_headshot_ratio(session: DotClientSession, track: Dictionary) -> void:
	var shots := int(track["shots"])
	if shots < config.headshot_min_shots:
		return

	var ratio := float(track["headshots"]) / float(shots)
	if ratio < config.headshot_ratio:
		return

	_report(session, DotAntiCheatEvent.HEADSHOT_RATIO, 1.0, {
		"ratio": ratio, "shots": shots
	})

	# Counted from zero again, or every subsequent shot reports once the ratio
	# is over — which would walk an escalation ladder in a magazine.
	track["shots"] = 0
	track["headshots"] = 0


# --- Plumbing --------------------------------------------------------------

func _running() -> bool:
	if config == null or not config.enabled:
		return false
	if guard == null or not is_instance_valid(guard):
		return false
	return true


func _report(
	session: DotClientSession,
	kind: StringName,
	magnitude: float,
	detail: Dictionary
) -> void:
	_detections[kind] = int(_detections.get(kind, 0)) + 1

	var impossible := DotAntiCheatEvent.is_impossible(kind)
	detected.emit(session, kind, impossible, detail)

	if config.dry_run:
		# Logged and counted, never reported into the rule engine — so no rule
		# can act on it however it is written. A separate switch from the
		# guard's own dry run, because an operator commonly trusts chat rules
		# long before a movement threshold they have not measured.
		DotLog.info(CHANNEL, "would report %s" % kind, detail)
		return

	guard.report_session(kind, session, magnitude, detail)


func _track(session: DotClientSession) -> Dictionary:
	var key := session.peer_id

	if not _tracks.has(key):
		_tracks[key] = {
			"position": Vector3.ZERO,
			"velocity": Vector3.ZERO,
			"last_velocity": Vector3.ZERO,
			"seen": false,
			"airborne_sec": 0.0,
			"claimed_sec": 0.0,
			"timing_began_ms": 0,
			"sequence": -1,
			"shots": 0,
			"headshots": 0,
			"on_target_since_ms": 0,
		}

	return _tracks[key]


## Drops a player's tracking state. Call on disconnect, or peers leak.
func forget(session: DotClientSession) -> void:
	if session != null:
		_tracks.erase(session.peer_id)


# --- Reporting -------------------------------------------------------------

func describe() -> Dictionary:
	return {
		"enabled": _running(),
		"dry_run": config.dry_run if config != null else true,
		"reference": movement_reference.is_valid(),
		"tracking": _tracks.size(),
		"detections": _detections.duplicate(),
		"peak_speed": _peak_speed,
		"peak_tick_distance": _peak_tick_distance,
		"peak_time_ratio": _peak_time_ratio,
	}


func describe_lines() -> PackedStringArray:
	var out := PackedStringArray()

	if config == null:
		out.append("not configured")
		return out

	out.append("state       %s%s" % [
		"on" if config.enabled else "OFF",
		"  [dry run: reporting nothing to the rules]" if config.dry_run else "",
	])
	out.append("movement    %s" % (
		"re-simulated (unbypassable)" if movement_reference.is_valid()
		else ("envelope only" if config.max_horizontal_speed > 0.0
			else "NOT CHECKED")
	))
	out.append("tracking    %d players" % _tracks.size())

	# The peaks are the point of this listing: they are how an operator sets a
	# threshold from what their game actually does rather than from a guess.
	out.append("")
	out.append("peaks seen (set your limits above these)")
	out.append("  horizontal speed   %.2f  (limit %s)" % [
		_peak_speed,
		"off" if config.max_horizontal_speed <= 0.0
			else "%.2f" % config.max_horizontal_speed
	])
	out.append("  rise               %.2f  (limit %s)" % [
		_peak_vertical,
		"off" if config.max_vertical_speed <= 0.0
			else "%.2f" % config.max_vertical_speed
	])
	out.append("  distance per tick  %.2f  (limit %s)" % [
		_peak_tick_distance,
		"off" if config.max_tick_distance <= 0.0
			else "%.2f" % config.max_tick_distance
	])
	out.append("  time ratio         %.3f  (limit %.3f)" % [
		_peak_time_ratio, config.max_time_ratio
	])

	if _detections.is_empty():
		out.append("")
		out.append("nothing detected yet")
		return out

	out.append("")
	out.append("detections")
	for kind in _detections:
		out.append("  %-32s %d%s" % [
			String(kind), int(_detections[kind]),
			"" if DotAntiCheatEvent.is_impossible(kind) else "   (behavioural)"
		])

	return out
