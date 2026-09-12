class_name DotSecuritySubject
extends RefCounted

## Who a counter counts against, and the reason that is a decision rather than a
## detail.
##
## [b]Count against a connection and you have counted nothing.[/b] A peer id dies
## with the socket, so "five messages in ten seconds" is dodged by reconnecting,
## and every spammer works that out within a minute. The scope is what survives:
## an account across reconnects, an address across accounts.
##
## Which one to use is per rule, and the two answer different questions:
##
## [b]UID[/b] is right for behaviour that is a person's — chat, commands, votes.
## It follows them onto a new address and it does not punish the sibling on the
## same connection.
##
## [b]ADDRESS[/b] is right for anything that happens [i]before[/i] there is an
## identity, which is most of what an attack is: connection floods, wrong RCON
## passwords, authentication that never completed. There is nobody to attribute
## those to yet.
##
## [b]BOTH[/b] counts the same event twice, once in each scope, so one rule can
## catch "this account is spamming" and another "this address is spamming from a
## different account each time". It is the right answer more often than it looks,
## and it is not the default because it doubles the counters.
##
## [b]The prefixes mirror dot-moderation's, and this addon must not name it.[/b]
## dot-moderation is optional, and a script mentioning a [code]class_name[/code]
## the project does not have fails to parse and takes every script referencing it
## down with it — so the two spellings of a subject live in two repositories and
## have to agree. They are asserted equal against the real addon in the self-test
## rather than trusted to a comment here, because a comment does not fail.

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
##
## Loopback is the operator's own console and every headless test; acting on it
## means the first thing the guard does is lock the operator out of their own
## server. "unknown" is what the transport reports when a peer cannot be asked,
## which is every such client in one bucket — a guard that bans it refuses
## everybody while looking idle.
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
##
## [code]::ffff:192.168.1.5[/code] and [code]192.168.1.5[/code] are one address,
## and counting them as two is how a limit is dodged by nothing more than which
## socket the server happened to open.
static func normalise_address(address: String) -> String:
	var out := address.strip_edges().to_lower()
	if out.begins_with("::ffff:"):
		out = out.substr(7)
	return out


## The subject for a session in one scope. [constant Scope.BOTH] resolves to UID.
##
## BOTH is not a subject — it is two — so anything needing one string gets the
## account, which is the more specific of the two. [method all_of_session] is what
## a caller that means both should use.
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
##
## Checked at the action, not at the count. The counters may run for loopback —
## `sec_status` showing what the operator's own traffic would have tripped is
## useful — but nothing is ever done about it.
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
