class_name DotSecuritySubject
extends RefCounted

## Who a counter counts against. A peer id dies with the socket, so counting per connection is dodged by reconnecting; the scope is what survives (docs/rationale.md).
## UID follows an account across addresses (chat, commands, votes); ADDRESS covers what happens before an identity exists (connection floods, wrong RCON passwords); BOTH counts each event in both scopes, at double the counters.
## The prefixes mirror dot-moderation's, which this addon must not name; the self-test asserts they agree with the real addon, since a comment does not fail.

enum Scope {
	## The account behind the event. Survives a reconnect.
	UID = 0,
	## The address behind the event. Survives a new account.
	ADDRESS = 1,
	## Both, counted separately. Two counters, two chances to trip.
	BOTH = 2,
}

const PREFIX_UID := "uid:"
const PREFIX_ADDRESS := "ip:"

## Addresses no rule may act against, however it is configured.
## Loopback is the operator's own console and every headless test; "unknown" is every client the transport could not ask, in one bucket, so banning it refuses everybody while looking idle.
const NEVER_ACT: Array[String] = ["127.0.0.1", "::1", "localhost", "unknown", ""]


static func for_uid(uid: String) -> String:
	return PREFIX_UID + uid.strip_edges()


static func for_address(address: String) -> String:
	return PREFIX_ADDRESS + normalise_address(address)


static func is_uid(subject: String) -> bool:
	return subject.begins_with(PREFIX_UID)


static func is_address(subject: String) -> bool:
	return subject.begins_with(PREFIX_ADDRESS)


static func value_of(subject: String) -> String:
	if is_uid(subject):
		return subject.substr(PREFIX_UID.length())
	if is_address(subject):
		return subject.substr(PREFIX_ADDRESS.length())
	return subject


## Strips the IPv6 mapping an IPv4 client gets from a dual-stack listener.
## `::ffff:192.168.1.5` and `192.168.1.5` are one address; counting them as two lets a limit be dodged by which socket was opened.
static func normalise_address(address: String) -> String:
	var out := address.strip_edges().to_lower()
	if out.begins_with("::ffff:"):
		out = out.substr(7)
	return out


## The subject for a session in one scope. [constant Scope.BOTH] resolves to UID.
## BOTH is two subjects, so a caller needing one string gets the more specific account; use [method all_of_session] to mean both.
static func of_session(session: DotClientSession, scope: int) -> String:
	if session == null:
		return ""

	if scope == Scope.ADDRESS:
		return for_address(session.address)

	var uid := session.uid()
	if uid == "":
		# A session with no identity yet — still connecting, or a guest whose id
		# has not been assigned. The address is all there is, and dropping the
		# event instead would make the connect path unguardable.
		return for_address(session.address)

	return for_uid(uid)


## Every subject a session counts under in one scope. One entry, or two for BOTH.
static func all_of_session(session: DotClientSession, scope: int) -> PackedStringArray:
	var out := PackedStringArray()
	if session == null:
		return out

	if scope == Scope.UID or scope == Scope.BOTH:
		var uid := session.uid()
		if uid != "":
			out.append(for_uid(uid))

	if scope == Scope.ADDRESS or scope == Scope.BOTH:
		out.append(for_address(session.address))

	if out.is_empty():
		# BOTH or UID on a session with no identity and no address is nothing to
		# count against. Falling back to the address keeps the connect path
		# guardable; an empty address is refused by may_act_on anyway.
		out.append(for_address(session.address))

	return out


## Whether the guard is allowed to act against this subject at all.
## Checked at the action, not the count: counters may run for loopback (`sec_status` shows what it would have tripped), but nothing is done.
static func may_act_on(subject: String) -> bool:
	if subject.strip_edges() == "":
		return false

	if is_address(subject):
		return not NEVER_ACT.has(value_of(subject))

	return value_of(subject).strip_edges() != ""


static func scope_name(scope: int) -> String:
	match scope:
		Scope.UID: return "uid"
		Scope.ADDRESS: return "address"
		Scope.BOTH: return "both"
	return "unknown(%d)" % scope


static func parse_scope(text: String) -> int:
	match text.strip_edges().to_lower():
		"uid", "account", "player": return Scope.UID
		"address", "ip": return Scope.ADDRESS
		"both": return Scope.BOTH
	return -1


static func describe(subject: String) -> String:
	if is_uid(subject):
		return "account %s" % value_of(subject)
	if is_address(subject):
		return "address %s" % value_of(subject)
	return subject
