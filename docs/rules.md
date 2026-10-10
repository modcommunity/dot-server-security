# The rule engine

One engine for chat, connections, authentication, the remote console and anti-cheat; how it counts, when it acts, and what it acts through. Anti-cheat's own rules are [anticheat.md](anticheat.md); external ban lists are [ban-feeds.md](ban-feeds.md).

## One engine, and everything is an event

There is no separate chat-spam system, connection-flood system and anti-cheat system. There is one rule engine, and everything reports into it:

```
watchers ──┐
detectors ─┼──> DotSecurityEvent ──> sliding window per (rule, subject)
a game ────┘                              │
                                   threshold reached?
                                          │
                          cooldown, offence memory, exemptions
                                          │
                                   step N of the ladder
                                          │
                        ┌─────────────────┴─────────────────┐
                   dot-moderation                    the session itself
                   (durable record)                  (dies with the socket)
```

**Anti-cheat is not a special case.** A detection is a `DotSecurityEvent` like any other, so "three impossible speeds in a minute, then ban" is a rule rather than code, and it gets windows, escalation, exemptions, dry run, the ledger and `sec_why` for free. A second copy of any of that machinery would have drifted from the first within a month.

The event vocabulary is open on purpose: a game reports its own events. `warn_unknown_events` warns at boot about a rule whose event nothing reports, and it must know the anti-cheat events as well as `DotSecurityEvent.KNOWN`.

## It ships in dry run, and that is a decision

`DotSecurityConfig.dry_run` defaults to **true**. Every rule evaluates, every trip is logged and ledgered marked `WOULD`, and nobody is punished.

An addon that starts punishing an existing community the moment it is installed, on thresholds nobody chose, against a chat culture it has never seen, is one that gets uninstalled after the first false positive, and then the server has no guard at all. The shipped thresholds are timid for the same reason, and every ladder still goes somewhere.

The anti-cheat has **its own** dry run, separate, because an operator commonly trusts the chat rules long before a movement threshold they have not measured.

## The five settings that are not obvious

**`cooldown_sec`** is the most important and the one nobody thinks of. Without it, a rule whose action does not stop the behaviour (a warning) trips on the very next event, walks its whole ladder inside one second and bans somebody over four messages.

**`offence_memory_sec` is not `window_sec`.** The window is how *fast* the behaviour must be to count as an offence at all; the memory is how long the server holds it against them. Ten seconds and a day are both reasonable and they are not the same number.

**`scope`** decides whether a counter survives a reconnect. Count against a peer and you have counted nothing.

**The ladder repeats its last rung** rather than running out. Reverting to nothing would reward persistence.

**Exemption is checked at the action, not at the count.** An admin's traffic still counts, so `sec_status` can show what it would have tripped; nothing is ever done about it.

## Why the sliding window is sliding

A fixed bucket that resets on a boundary is walked straight through: five messages at 0.9 s and five more at 1.1 s is ten in two seconds, and a bucket sees two counts of five and trips on neither. Every rate limit written that way has eventually been defeated by somebody noticing the boundary, usually by accident.

**The bounds on it are a security control, not tidiness.** A structure growing one entry per event and one bucket per address is a memory-exhaustion target reachable by exactly the traffic this addon exists to watch. Entries per subject, subjects per window and offence records are all capped, oldest first, and idle subjects are swept. Losing the oldest entries under attack is the right failure: a subject at the entry cap is hundreds of events past any sane threshold, so the rule fired long before anything was dropped. Same reasoning as dot-server-query's refusal to keep a challenge table.

## The couplings, and why they are tested rather than commented

dot-moderation, dot-chat and dot-auth are optional, and a script mentioning a `class_name` the project does not have fails to parse *and takes every script referencing it down with it*, which for a security addon means the guard stops existing rather than stops watching one source. So three values defined in other repositories are reproduced here:

| Here | There | If they drift |
| --- | --- | --- |
| `DotSecuritySubject.PREFIX_UID` / `PREFIX_ADDRESS` | dot-moderation's `DotPunishmentSubject` | every punishment is filed against a subject nothing else can find |
| `DotSecurityAction.MOD_KIND_*` | dot-moderation's `DotPunishment.Kind` | a gag is issued as a ban |
| `DotSecurityWatch.REFUSAL_PERMISSION` | dot-server's `command_refused` wording | `command.denied` silently stops counting |

**All three are asserted against the real addons in the suite**, which is why they are linked into this project. A comment does not fail when the other side changes.

The last one deserves naming: `command_executed` fires *only after the permission check has passed*, so it never sees a denial. `command_refused` sees every refusal and distinguishes a permission refusal from a mistyped command by a string prefix alone. Matching that prefix is the only way to tell somebody probing from somebody typing.

## Acting with and without dot-moderation

Both, always, when both can:

- **The durable half** is a record: stored, expiring, revocable, surviving a reconnect and a restart.
- **The session half** is what the player feels this second. A session already mid-message should not get one more line out because a store was slow.

`SILENCE` issues **two** records, gag first, because it is two states there and either may be revoked without the other, and a store failing halfway should leave the text mute, which is the one a spam rule was about.

`issue()` is called with maximum issuer immunity, deliberately. The guard is not a moderator with a rank: a rule declining to act because the target out-ranked a number nobody chose would silently protect exactly the people most able to abuse the server. Who is exempt is decided by the rule's own exemptions, in one place.

## Finding the moderation store

**The store is found late, never latched at attach.** dot-moderation's manager is built by the game, inside a module dot-server loads *after* the listener is open, while a `DotSecurityManager` attaches as the server boots. So `moderation_store()` returns the cached answer when there is one and looks the registry up again when there is not; `is_instance_valid` covers the game change that frees the old store and builds a new one. `describe()` and `sec_status` ask the same way, and the boot line says "not yet" rather than "no moderation store". Why this matters: [history](history.md#the-guard-latched-the-moderation-store-at-boot).

The console surface (`sec_status`, `sec_why`, `sv_security`) is registered after the server's `state_changed`, because a guard placed beside a server is ready before the console exists.

## Deliberately not here

- **A client-side component** or **wallhack detection**: see [anticheat.md](anticheat.md#what-this-cannot-do).
- **Machine learning over aim traces.** The published work on it is real and needs a labelled dataset from your own game to be worth anything; the hooks here (`observe_aim`, `observe_trigger`) are where such a model would plug in, and a model shipped without your data would be a random number generator with a confusion matrix.
- **Its own ban storage.** dot-moderation is the durable store and `DotBanFeeds` is the read-only external half. Two write targets is the two-lists problem.
- **Rate limiting the game's own traffic.** dot-server's `DotAddressGuard` caps connections per address and dot-server-query rate-limits queries; both are in the right places already.
