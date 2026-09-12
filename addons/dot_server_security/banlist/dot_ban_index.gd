class_name DotBanIndex
extends RefCounted

## The merged contents of every ban feed, and the thing a join is checked against.
##
## [b]A join is on the hot path and must not be a walk.[/b] Account ids and exact
## addresses are dictionary lookups; only CIDR ranges are walked, which is why
## ranges are kept in their own small list rather than expanded into addresses.
## Expanding a /16 is sixty-five thousand entries for one line of somebody's
## blocklist.

## uid -> reason
var uids: Dictionary = {}

## exact normalised address -> reason
var addresses: Dictionary = {}

## Array of [base_int, mask_int, bits, reason] for IPv4 ranges.
var _ranges: Array = []

## Raw IPv6 prefixes as [prefix_text, reason]; matched by string prefix.
##
## Honest about being cruder than the IPv4 path: full IPv6 arithmetic in
## GDScript is a lot of code for something almost no blocklist publishes. A
## prefix match on the normalised text catches the case that does occur, which
## is a whole /64 or /48 written out.
var _v6_prefixes: Array = []

var feed_count: int = 0


func clear() -> void:
	uids.clear()
	addresses.clear()
	_ranges.clear()
	_v6_prefixes.clear()
	feed_count = 0


func size() -> int:
	return uids.size() + addresses.size() + _ranges.size() + _v6_prefixes.size()


func add_uid(uid: String, reason: String) -> void:
	var key := uid.strip_edges()
	if key != "":
		uids[key] = reason


## Adds an address, a CIDR range, or an IPv6 prefix, whichever it is.
func add_address(address: String, reason: String) -> void:
	var text := DotSecuritySubject.normalise_address(address)
	if text == "":
		return

	if text.contains("/"):
		_add_range(text, reason)
		return

	addresses[text] = reason


func _add_range(cidr: String, reason: String) -> void:
	var parts := cidr.split("/")
	if parts.size() != 2:
		return

	var base := parts[0].strip_edges()
	var bits := int(parts[1])

	if base.contains(":"):
		# IPv6. Kept as the literal prefix up to the last group boundary the
		# mask covers, and matched as text.
		_v6_prefixes.append([base.trim_suffix("::"), reason])
		return

	var packed := _ipv4_to_int(base)
	if packed < 0 or bits < 0 or bits > 32:
		return

	var mask := 0 if bits == 0 else (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
	_ranges.append([packed & mask, mask, bits, reason])


# --- Lookups ---------------------------------------------------------------

## Why this account is refused, or an empty string.
func reason_for_uid(uid: String) -> String:
	return str(uids.get(uid.strip_edges(), ""))


## Why this address is refused, or an empty string.
func reason_for_address(address: String) -> String:
	var text := DotSecuritySubject.normalise_address(address)
	if text == "":
		return ""

	if addresses.has(text):
		return str(addresses[text])

	if text.contains(":"):
		for entry in _v6_prefixes:
			var pair: Array = entry
			if text.begins_with(str(pair[0])):
				return str(pair[1])
		return ""

	var packed := _ipv4_to_int(text)
	if packed < 0:
		return ""

	for entry in _ranges:
		var row: Array = entry
		if (packed & int(row[1])) == int(row[0]):
			return str(row[3])

	return ""


func has_uid(uid: String) -> bool:
	return uids.has(uid.strip_edges())


static func _ipv4_to_int(text: String) -> int:
	var parts := text.split(".")
	if parts.size() != 4:
		return -1

	var out := 0
	for part in parts:
		if not part.is_valid_int():
			return -1
		var octet := int(part)
		if octet < 0 or octet > 255:
			return -1
		out = (out << 8) | octet

	return out


## Whether a bare string looks like an address or a range rather than an account.
static func looks_like_address(text: String) -> bool:
	var trimmed := text.strip_edges()
	if trimmed == "":
		return false

	var base := trimmed.split("/")[0]

	if base.contains(":"):
		# Crude on purpose: anything with a colon and only hex digits is an
		# IPv6 address, and an account id containing a colon is not one this
		# guesses about. A feed that mixes the two sets explicit fields.
		for i in range(base.length()):
			var c := base[i].to_lower()
			if not (c == ":" or (c >= "0" and c <= "9") or (c >= "a" and c <= "f")):
				return false
		return true

	return _ipv4_to_int(base) >= 0


func describe() -> Dictionary:
	return {
		"feeds": feed_count,
		"uids": uids.size(),
		"addresses": addresses.size(),
		"ranges": _ranges.size() + _v6_prefixes.size(),
	}
