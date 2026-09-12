class_name DotSecurityEvent
extends RefCounted

## One thing that happened, and who it is attributed to.
##
## [b]The vocabulary is open on purpose.[/b] The names below are what the shipped
## watchers report and what the shipped rules match on, but [method
## DotSecurityManager.report] takes any [StringName] — so a game counting its own
## abuse (a player who fired two hundred rounds in a second, somebody opening the
## buy menu forty times, a vote called every round) writes one line and gets the
## whole rule engine: windows, thresholds, escalation, exemptions and the ledger.
## A closed enum here would have meant every such game forking the addon.
##
## An event is attributed to a [b]subject[/b], not to a connection: a player who
## reconnects to dodge a counter has dodged nothing, because the counter is against
## their account or their address. See [DotSecuritySubject].

# --- Chat ------------------------------------------------------------------

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

# --- Connections -----------------------------------------------------------

## A client reached the server, whatever happened next.
const CONNECT_ATTEMPT := &"connect.attempt"

## A client was refused: banned, full, wrong content, failed a check.
const CONNECT_REJECTED := &"connect.rejected"

## A client that connected and left again without ever playing.
##
## The one that catches a reconnect loop, which looks like nothing else: every
## individual connection is legitimate and the server is still being hammered.
const CONNECT_CHURN := &"connect.churn"

# --- Authentication --------------------------------------------------------

## An identity could not be established.
const AUTH_FAILED := &"auth.failed"

## An identity was established and then refused admission.
const AUTH_REJECTED := &"auth.rejected"

# --- The remote console ----------------------------------------------------

## A wrong RCON password.
##
## [b]The highest-value signal in here.[/b] dot-server already locks an address out
## after `rcon_max_failures`, but that lockout is per-address and forgotten on
## restart; a rule over this is what turns a password spray into a ban.
const RCON_AUTH_FAILED := &"rcon.auth_failed"

## A command run over RCON.
const RCON_COMMAND := &"rcon.command"

# --- Commands --------------------------------------------------------------

## A command refused for want of permission.
##
## Worth counting because the innocent version happens once — somebody types a
## command they do not have — and the other version happens fifty times.
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
##
## A rule's threshold is compared against the summed weight in its window, not
## against a number of events, so a watcher can say "this one was four times as
## bad" without inventing a second event name. Ordinary events weigh 1.
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
