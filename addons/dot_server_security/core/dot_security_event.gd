class_name DotSecurityEvent
extends RefCounted

## One thing that happened, and who it is attributed to.
## The vocabulary is open on purpose: [method DotSecurityManager.report] takes any [StringName], so a game counting its own abuse gets the whole rule engine without forking the addon.
## Events are attributed to a subject, not a connection, so reconnecting dodges no counter. See [DotSecuritySubject].


## Any accepted chat message.
const CHAT_MESSAGE := &"chat.message"

## A message the chat system itself refused — too long, too fast, filtered.
const CHAT_REFUSED := &"chat.refused"

## A message with the same text as a recent one from the same subject.
const CHAT_DUPLICATE := &"chat.duplicate"

## A message that is mostly capital letters.
const CHAT_CAPS := &"chat.caps"

## A message containing something shaped like a link.
const CHAT_LINK := &"chat.link"

## A chat line beginning with a command prefix.
const CHAT_COMMAND := &"chat.command"


## A client reached the server, whatever happened next.
const CONNECT_ATTEMPT := &"connect.attempt"

## A client was refused: banned, full, wrong content, failed a check.
const CONNECT_REJECTED := &"connect.rejected"

## A client that connected and left again without ever playing.
## Catches a reconnect loop: every connection is legitimate and the server is still being hammered.
const CONNECT_CHURN := &"connect.churn"


## An identity could not be established.
const AUTH_FAILED := &"auth.failed"

## An identity was established and then refused admission.
const AUTH_REJECTED := &"auth.rejected"


## A wrong RCON password.
## The highest-value signal here: dot-server's per-address lockout is forgotten on restart; a rule over this turns a password spray into a ban.
const RCON_AUTH_FAILED := &"rcon.auth_failed"

## A command run over RCON.
const RCON_COMMAND := &"rcon.command"


## A command refused for want of permission.
## The innocent version happens once; the other happens fifty times.
const COMMAND_DENIED := &"command.denied"

## Every name this addon ships a meaning for. A rule may name anything else too.
const KNOWN: Array[StringName] = [
	CHAT_MESSAGE, CHAT_REFUSED, CHAT_DUPLICATE, CHAT_CAPS, CHAT_LINK, CHAT_COMMAND,
	CONNECT_ATTEMPT, CONNECT_REJECTED, CONNECT_CHURN,
	AUTH_FAILED, AUTH_REJECTED,
	RCON_AUTH_FAILED, RCON_COMMAND,
	COMMAND_DENIED,
]


## What happened.
var name: StringName = &""

## Who it is against, already scoped. See [DotSecuritySubject].
var subject: String = ""

## The account id behind it, when there is one. May be empty.
var uid: String = ""

## The address behind it, when there is one. May be empty.
var address: String = ""

## The live session, when the event came from one. May be null.
var session: DotClientSession = null

## How much this event counts for.
## A rule's threshold is compared against the summed weight in its window, so a watcher can say "four times as bad" without a second event name. Ordinary events weigh 1.
var weight: float = 1.0

## Whatever the watcher knew. Goes into the ledger, never onto the wire.
var detail: Dictionary = {}


static func make(
	p_name: StringName,
	p_subject: String,
	p_weight: float = 1.0,
	p_detail: Dictionary = {}
) -> DotSecurityEvent:
	var event := DotSecurityEvent.new()
	event.name = p_name
	event.subject = p_subject
	event.weight = p_weight
	event.detail = p_detail
	return event


## Builds an event already attributed to a session, in the given scope.
static func from_session(
	p_name: StringName,
	p_session: DotClientSession,
	scope: int,
	p_weight: float = 1.0,
	p_detail: Dictionary = {}
) -> DotSecurityEvent:
	var event := DotSecurityEvent.new()
	event.name = p_name
	event.session = p_session
	event.weight = p_weight
	event.detail = p_detail

	if p_session != null:
		event.uid = p_session.uid()
		event.address = p_session.address

	event.subject = DotSecuritySubject.of_session(p_session, scope)
	return event


static func is_known(p_name: StringName) -> bool:
	return KNOWN.has(p_name)


func describe() -> String:
	return "%s against %s (x%.1f)" % [name, subject, weight]
