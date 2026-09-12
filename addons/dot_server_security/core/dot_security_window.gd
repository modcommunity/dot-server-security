class_name DotSecurityWindow
extends RefCounted

## Sliding-window counters, one per subject, with a hard bound on memory.
##
## [b]Sliding, not bucketed.[/b] A fixed bucket that resets on a boundary is
## walked straight through: five messages at 0.9s and five more at 1.1s is ten
## messages in two seconds, and a bucket sees two counts of five and trips on
## neither. Every rate limit written that way has been defeated by somebody
## noticing the boundary, usually by accident.
##
## [b]The bounds are a security control, not tidiness.[/b] A structure that grows
## one entry per event and one bucket per address is a memory-exhaustion target
## reachable by exactly the traffic this addon exists to watch: send a million
## messages from a million forged-looking connections and the guard is the thing
## that falls over. So the entries per subject are capped, the subjects are
## capped, and the oldest go first. The same reasoning as dot-server-query's
## refusal to keep a challenge table.
##
## Losing the oldest entries under attack is the right failure: a subject at the
## entry cap is one already well past any sane threshold, so the rule has fired
## long before anything was dropped.

## Most timestamps held for one subject.
##
## Comfortably above any sane threshold. A rule needing more than this many
## events in its window has already tripped several hundred events ago.
const MAX_ENTRIES_PER_SUBJECT := 256

## Most subjects tracked at once, per window.
##
## Reached only under attack or on a very large server; the oldest-seen subject
## is evicted, which on a busy server is somebody who has not done the watched
## thing in a long time.
const MAX_SUBJECTS := 4096

## Subjects idle longer than this are swept, in seconds.
const IDLE_EVICTION_SEC := 900.0

## How often the sweep runs, in milliseconds. Sweeping per event costs more than
## the memory it saves.
const SWEEP_INTERVAL_MS := 30_000

## How long the window is, in seconds.
var window_sec: float = 10.0

## subject -> Array of [timestamp_ms, weight]
var _entries: Dictionary = {}

## subject -> last touched, in ticks
var _last_seen: Dictionary = {}

var _last_sweep_ms: int = 0
var _evicted: int = 0
var _dropped: int = 0


func _init(p_window_sec: float = 10.0) -> void:
	window_sec = maxf(0.1, p_window_sec)


## Records an event and returns the subject's weight within the window, this one
## included.
func add(subject: String, weight: float = 1.0) -> float:
	var now := Time.get_ticks_msec()
	_maybe_sweep(now)

	var list: Array = _entries.get(subject, [])

	if list.is_empty() and _entries.size() >= MAX_SUBJECTS:
		_evict_oldest()

	list.append([now, weight])

	if list.size() > MAX_ENTRIES_PER_SUBJECT:
		# Oldest first. They are the ones about to fall out of the window anyway.
		list = list.slice(list.size() - MAX_ENTRIES_PER_SUBJECT)
		_dropped += 1

	_entries[subject] = list
	_last_seen[subject] = now

	return _sum(list, now)


## The subject's current weight in the window, without recording anything.
func peek(subject: String) -> float:
	if not _entries.has(subject):
		return 0.0
	return _sum(_entries[subject] as Array, Time.get_ticks_msec())


## Forgets a subject entirely. What `sec_reset` calls, and what an action calls
## once it has been taken — leaving the count standing would trip the rule again
## on the very next event.
func clear_subject(subject: String) -> void:
	_entries.erase(subject)
	_last_seen.erase(subject)


func clear() -> void:
	_entries.clear()
	_last_seen.clear()


func subject_count() -> int:
	return _entries.size()


## Sums the entries still inside the window, discarding those that are not.
##
## Eviction happens here rather than on a timer because this is the only place
## that has to walk the list anyway.
func _sum(list: Array, now: int) -> float:
	var cutoff := now - int(window_sec * 1000.0)
	var total := 0.0
	var live: Array = []

	for entry in list:
		var pair: Array = entry
		if int(pair[0]) >= cutoff:
			live.append(pair)
			total += float(pair[1])

	# The trimmed list is written back by the caller through _entries, which add()
	# does; peek() deliberately does not, so that reading a counter for a status
	# line never changes it.
	list.clear()
	list.append_array(live)

	return total


func _maybe_sweep(now: int) -> void:
	if now - _last_sweep_ms < SWEEP_INTERVAL_MS:
		return
	_last_sweep_ms = now

	var cutoff := now - int(IDLE_EVICTION_SEC * 1000.0)
	var stale: Array = []

	for subject in _last_seen:
		if int(_last_seen[subject]) < cutoff:
			stale.append(subject)

	for subject in stale:
		_entries.erase(subject)
		_last_seen.erase(subject)
		_evicted += 1


func _evict_oldest() -> void:
	var oldest := ""
	var oldest_at := 0x7FFFFFFFFFFFFFF

	for subject in _last_seen:
		var seen := int(_last_seen[subject])
		if seen < oldest_at:
			oldest_at = seen
			oldest = subject

	if oldest != "":
		_entries.erase(oldest)
		_last_seen.erase(oldest)
		_evicted += 1


func describe() -> Dictionary:
	return {
		"window_sec": window_sec,
		"subjects": _entries.size(),
		"evicted": _evicted,
		"overflowed": _dropped,
	}
