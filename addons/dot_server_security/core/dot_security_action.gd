class_name DotSecurityAction
extends RefCounted

## What a rule does when it trips, and the two backends that can do it.
##
## [b]Every action has a durable form and a fallback, and the difference matters
## to an operator.[/b] With dot-moderation installed, a gag is a record: stored,
## expiring, revocable, surviving a reconnect and a restart, visible in that
## addon's own listing beside the ones a human issued. Without it, a gag is two
## booleans on a session object — which is dot-server's own mute, and a session
## dies with its connection, so the player reconnects and talks.
##
## Both are supported because refusing to act without dot-moderation would make
## the whole addon conditional on another optional one, and a five-minute gag that
## a determined spammer can reconnect out of is still worth having against the
## ninety-nine per cent who will not think to.
##
## [b]dot-moderation is named nowhere here.[/b] It is reached duck-typed through
## whatever registered as [code]dot_moderation[/code], for the usual reason: a
## script mentioning a [code]class_name[/code] the project does not have fails to
## parse and takes every script referencing it down with it.

enum Kind {
	## Count and remember, do nothing. What a rule is set to while it is being
	## tuned, and the only honest setting for one an operator is not yet sure of.
	NONE = 0,
	## On record against the subject, enforcing nothing.
	WARN = 1,
	## May not use text chat.
	GAG = 2,
	## May not use voice.
	VOICE_MUTE = 3,
	## Both at once, which is what "mute" means to most operators.
	SILENCE = 4,
	## Removed from the server once.
	KICK = 5,
	## Cannot connect at all.
	BAN = 6,
}

## dot-moderation's own Kind values, which this addon must not name.
##
## The other half of the coupling described on [DotSecuritySubject], and asserted
## against the real addon in the self-test for the same reason.
const MOD_KIND_BAN := 0
const MOD_KIND_KICK := 1
const MOD_KIND_VOICE_MUTE := 2
const MOD_KIND_GAG := 3
const MOD_KIND_WARN := 4


static func kind_name(kind: int) -> String:
	match kind:
		Kind.NONE: return "none"
		Kind.WARN: return "warn"
		Kind.GAG: return "gag"
		Kind.VOICE_MUTE: return "voice_mute"
		Kind.SILENCE: return "silence"
		Kind.KICK: return "kick"
		Kind.BAN: return "ban"
	return "unknown(%d)" % kind


static func parse_kind(text: String) -> int:
	match text.strip_edges().to_lower():
		"none", "count", "off": return Kind.NONE
		"warn": return Kind.WARN
		"gag", "chat_mute": return Kind.GAG
		"voice_mute", "voice": return Kind.VOICE_MUTE
		"silence", "mute": return Kind.SILENCE
		"kick": return Kind.KICK
		"ban": return Kind.BAN
	return -1


## Whether this action removes the player from the server.
static func is_removal(kind: int) -> bool:
	return kind == Kind.KICK or kind == Kind.BAN


## Whether a duration means anything for this action.
##
## A kick has no duration — it happens once and is over, which is why
## dot-moderation calls it history rather than a state — and a warn records one
## only so a listing can say how long the note stands.
static func takes_duration(kind: int) -> bool:
	return kind == Kind.GAG or kind == Kind.VOICE_MUTE \
		or kind == Kind.SILENCE or kind == Kind.BAN


static func format_duration(seconds: int) -> String:
	if seconds <= 0:
		return "permanent"
	if seconds < 60:
		return "%ds" % seconds
	if seconds < 3600:
		return "%dm" % int(seconds / 60.0)
	if seconds < 86400:
		return "%.1fh" % (seconds / 3600.0)
	return "%.1fd" % (seconds / 86400.0)


# --- Applying --------------------------------------------------------------

## Carries out an action. Returns what was done, for the ledger.
##
## [param moderation] is whatever registered as [code]dot_moderation[/code], or
## null. [param session] is the live session when there is one — a subject may
## have no session at all (an address that never finished connecting), in which
## case only the durable backend can do anything and the fallback does nothing.
static func apply(
	kind: int,
	subject: String,
	duration_sec: int,
	reason: String,
	issuer: String,
	moderation: Object,
	server: DotServer,
	session: DotClientSession
) -> DotResult:
	if kind == Kind.NONE:
		return DotResult.success("counted")

	if not DotSecuritySubject.may_act_on(subject):
		# Not an error. A rule that keeps tripping against loopback in a headless
		# test is working correctly and must not fill the log with failures.
		return DotResult.success("exempt subject")

	var durable := _apply_durable(
		kind, subject, duration_sec, reason, issuer, moderation
	)

	# The durable backend records; the session backend is what the player
	# actually feels this second. Both run when both can: dot-moderation's gag is
	# consulted on the chat path through `dot_mute_source`, but a session already
	# mid-message should not get one more line out because a store was slow.
	var immediate := _apply_to_session(kind, duration_sec, reason, server, session)

	if durable.ok:
		return DotResult.success(
			"%s (recorded%s)" % [kind_name(kind), "" if immediate.ok else ", session miss"]
		)

	if immediate.ok:
		return DotResult.success("%s (session only)" % kind_name(kind))

	return durable.wrap("could not apply %s to %s" % [kind_name(kind), subject])


## The dot-moderation path: a stored, expiring, revocable record.
static func _apply_durable(
	kind: int,
	subject: String,
	duration_sec: int,
	reason: String,
	issuer: String,
	moderation: Object
) -> DotResult:
	if moderation == null or not is_instance_valid(moderation):
		return DotResult.fail(
			DotError.CODE_UNSUPPORTED, "No moderation store is installed."
		)

	if not moderation.has_method("issue"):
		return DotResult.fail(
			DotError.CODE_INVALID,
			"What is registered as the moderation store cannot issue punishments.",
			"got a %s" % moderation.get_class()
		)

	var mod_kind := _to_mod_kind(kind)
	if mod_kind < 0:
		return DotResult.fail(
			DotError.CODE_UNSUPPORTED,
			"%s has no durable form." % kind_name(kind)
		)

	# SILENCE is two records, because it is two states there and either may be
	# revoked without the other. Issued gag-first so that a store failing halfway
	# leaves the text mute — the one a spam rule was actually about — in place.
	if kind == Kind.SILENCE:
		var gag := _issue(
			moderation, MOD_KIND_GAG, subject, duration_sec, reason, issuer
		)
		var voice := _issue(
			moderation, MOD_KIND_VOICE_MUTE, subject, duration_sec, reason, issuer
		)
		return gag if gag.ok else voice

	# A kick has no duration in that addon: it is history, not a state.
	var seconds := duration_sec if takes_duration(kind) else 0
	return _issue(moderation, mod_kind, subject, seconds, reason, issuer)


static func _issue(
	moderation: Object,
	mod_kind: int,
	subject: String,
	duration_sec: int,
	reason: String,
	issuer: String
) -> DotResult:
	# issuer_immunity is deliberately the maximum. The guard is not a moderator
	# with a rank: a rule that declined to act because the target out-ranked a
	# number nobody chose would be a rule that silently protects exactly the
	# people most able to abuse the server. Who is exempt is decided by the rule's
	# own exemptions, in one place, on purpose.
	var issued: Variant = moderation.call(
		"issue", mod_kind, subject, reason, issuer, duration_sec, 0x7FFFFFFF
	)

	if issued is DotResult:
		return issued as DotResult

	return DotResult.fail(
		DotError.CODE_INVALID, "The moderation store answered with something else."
	)


## The fallback: dot-server's own session state, which dies with the connection.
static func _apply_to_session(
	kind: int,
	duration_sec: int,
	reason: String,
	server: DotServer,
	session: DotClientSession
) -> DotResult:
	if session == null or not is_instance_valid(session):
		return DotResult.fail(DotError.CODE_STATE, "No live session.")

	match kind:
		Kind.WARN:
			return DotResult.success("warned")

		Kind.GAG:
			session.silence(session.muted, true, duration_sec)
			return DotResult.success("gagged")

		Kind.VOICE_MUTE:
			session.silence(true, session.gagged, duration_sec)
			return DotResult.success("voice muted")

		Kind.SILENCE:
			session.silence(true, true, duration_sec)
			return DotResult.success("silenced")

		Kind.KICK, Kind.BAN:
			if server == null:
				return DotResult.fail(DotError.CODE_STATE, "No server to kick from.")
			return server.kick(session, reason)

	return DotResult.fail(DotError.CODE_INVALID, "Unknown action.")


static func _to_mod_kind(kind: int) -> int:
	match kind:
		Kind.WARN: return MOD_KIND_WARN
		Kind.GAG: return MOD_KIND_GAG
		Kind.VOICE_MUTE: return MOD_KIND_VOICE_MUTE
		Kind.SILENCE: return MOD_KIND_GAG
		Kind.KICK: return MOD_KIND_KICK
		Kind.BAN: return MOD_KIND_BAN
	return -1
