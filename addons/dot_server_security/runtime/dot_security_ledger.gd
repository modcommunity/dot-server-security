class_name DotSecurityLedger
extends RefCounted

## What the guard did, and why.
##
## [b]An automatic punishment nobody can explain is worse than none.[/b] A player
## appeals, an operator looks, and the only thing to look at is that they are
## gagged — so either the operator lifts it blindly or refuses blindly, and after
## the second time they turn the guard off. `sec_why <player>` answers out of
## this: which rule, which event, how many in how long, which rung of the ladder,
## and whether it was actually applied or only would have been.
##
## Bounded, oldest-first. It is a debugging aid, not an audit trail — dot-server's
## audit log and dot-moderation's records are where a punishment durably lives.

## One decision.
class Entry extends RefCounted:
	var at: int = 0
	var rule_id: StringName = &""
	var event: StringName = &""
	var subject: String = ""
	var count: float = 0.0
	var threshold: int = 0
	var window_sec: float = 0.0
	var offence: int = 0
	var action: int = DotSecurityAction.Kind.NONE
	var duration_sec: int = 0
	## False when dry_run or an exemption meant nothing was actually done.
	var applied: bool = false
	## Why nothing was done, when nothing was.
	var withheld: String = ""
	var detail: String = ""

	func describe() -> String:
		var when := Time.get_datetime_string_from_unix_time(at, true)
		var what := DotSecurityAction.kind_name(action)

		if DotSecurityAction.takes_duration(action) and duration_sec > 0:
			what += " " + DotSecurityAction.format_duration(duration_sec)

		var verb := what if applied else "WOULD %s" % what
		var why := "" if withheld == "" else "  (%s)" % withheld

		return "%s  %-18s %-16s offence %d: %.0f x %s in %.0fs -> %s%s" % [
			when, rule_id, DotSecuritySubject.describe(subject),
			offence, count, event, window_sec, verb, why
		]

	func to_dictionary() -> Dictionary:
		return {
			"at": at,
			"rule": String(rule_id),
			"event": String(event),
			"subject": subject,
			"count": count,
			"threshold": threshold,
			"window_sec": window_sec,
			"offence": offence,
			"action": DotSecurityAction.kind_name(action),
			"duration_sec": duration_sec,
			"applied": applied,
			"withheld": withheld,
			"detail": detail,
		}


var limit: int = 512

var _entries: Array[Entry] = []
var _total: int = 0
var _applied: int = 0


func _init(p_limit: int = 512) -> void:
	limit = maxi(16, p_limit)


func record(entry: Entry) -> void:
	_entries.append(entry)
	_total += 1
	if entry.applied:
		_applied += 1

	if _entries.size() > limit:
		_entries = _entries.slice(_entries.size() - limit)


## Every decision against one subject, oldest first.
func for_subject(subject: String) -> Array[Entry]:
	var out: Array[Entry] = []
	for entry in _entries:
		if entry.subject == subject:
			out.append(entry)
	return out


## Every decision whose subject contains the given text. What `sec_why` uses,
## because an operator types a name or an address, not a prefixed subject.
func search(text: String) -> Array[Entry]:
	var needle := text.strip_edges().to_lower()
	var out: Array[Entry] = []

	if needle == "":
		return out

	for entry in _entries:
		if entry.subject.to_lower().contains(needle) \
				or entry.detail.to_lower().contains(needle):
			out.append(entry)

	return out


func recent(count: int = 20) -> Array[Entry]:
	if _entries.size() <= count:
		return _entries.duplicate()
	return _entries.slice(_entries.size() - count)


func size() -> int:
	return _entries.size()


func total() -> int:
	return _total


func applied_count() -> int:
	return _applied


func clear() -> void:
	_entries.clear()


func describe() -> Dictionary:
	return {
		"held": _entries.size(),
		"limit": limit,
		"total": _total,
		"applied": _applied,
	}
