# dot-server-security

Hardening a dedicated server, as configuration: sliding-window rules over chat, connections, authentication, the remote console and the anti-cheat detectors, escalating through warn, gag, mute, kick and ban.

**The distributable is `addons/dot_server_security/`.** It requires [dot-core](../dot-core) and [dot-server](../dot-server), and optionally integrates with [dot-moderation](../dot-moderation), [dot-chat](../dot-chat) and [dot-auth](../dot-auth) — all three discovered at runtime, none imported, none named.

```bash
ln -s ../../dot-core/addons/dot_core addons/dot_core
ln -s ../../dot-server/addons/dot_server addons/dot_server

# Optional, and the self-test wants all three: every bridge is duck-typed, and
# linking the real addons is what checks the couplings against the thing they
# describe rather than against a mock of it.
ln -s ../../dot-moderation/addons/dot_moderation addons/dot_moderation
ln -s ../../dot-chat/addons/dot_chat addons/dot_chat
ln -s ../../dot-auth/addons/dot_auth addons/dot_auth
```

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

## It ships in dry run, and that is a decision

`DotSecurityConfig.dry_run` defaults to **true**. Every rule evaluates, every trip is logged and ledgered marked `WOULD`, and nobody is punished.

An addon that starts punishing an existing community the moment it is installed — on thresholds nobody chose, against a chat culture it has never seen — is one that gets uninstalled after the first false positive, and then the server has no guard at all. The shipped thresholds are timid for the same reason, and every ladder still goes somewhere.

The anti-cheat has **its own** dry run, separate, because an operator commonly trusts the chat rules long before a movement threshold they have not measured.

## The five settings that are not obvious

**`cooldown_sec`** is the most important and the one nobody thinks of. Without it, a rule whose action does not stop the behaviour — a warning — trips on the very next event, walks its whole ladder inside one second and bans somebody over four messages.

**`offence_memory_sec` is not `window_sec`.** The window is how *fast* the behaviour must be to count as an offence at all; the memory is how long the server holds it against them. Ten seconds and a day are both reasonable and they are not the same number.

**`scope`** decides whether a counter survives a reconnect. Count against a peer and you have counted nothing.

**The ladder repeats its last rung** rather than running out. Reverting to nothing would reward persistence.

**Exemption is checked at the action, not at the count.** An admin's traffic still counts, so `sec_status` can show what it would have tripped; nothing is ever done about it.

## Why the sliding window is sliding

A fixed bucket that resets on a boundary is walked straight through: five messages at 0.9s and five more at 1.1s is ten in two seconds, and a bucket sees two counts of five and trips on neither. Every rate limit written that way has eventually been defeated by somebody noticing the boundary, usually by accident.

**The bounds on it are a security control, not tidiness.** A structure growing one entry per event and one bucket per address is a memory-exhaustion target reachable by exactly the traffic this addon exists to watch. Entries per subject, subjects per window and offence records are all capped, oldest first, and idle subjects are swept. Losing the oldest entries under attack is the right failure: a subject at the entry cap is hundreds of events past any sane threshold, so the rule fired long before anything was dropped. Same reasoning as dot-server-query's refusal to keep a challenge table.

## The couplings, and why they are tested rather than commented

dot-moderation, dot-chat and dot-auth are optional, and a script mentioning a `class_name` the project does not have fails to parse *and takes every script referencing it down with it* — which for a security addon means the guard stops existing rather than stops watching one source. So three values defined in other repositories are reproduced here:

| Here | There | If they drift |
| --- | --- | --- |
| `DotSecuritySubject.PREFIX_UID` / `PREFIX_ADDRESS` | dot-moderation's `DotPunishmentSubject` | every punishment is filed against a subject nothing else can find |
| `DotSecurityAction.MOD_KIND_*` | dot-moderation's `DotPunishment.Kind` | a gag is issued as a ban |
| `DotSecurityWatch.REFUSAL_PERMISSION` | dot-server's `command_refused` wording | `command.denied` silently stops counting |

**All three are asserted against the real addons in the self-test**, which is why they are linked into this project. A comment does not fail when the other side changes.

The last one deserves naming: `command_executed` fires *only after the permission check has passed*, so it never sees a denial. `command_refused` sees every refusal and distinguishes a permission refusal from a mistyped command by a string prefix alone. Matching that prefix is the only way to tell somebody probing from somebody typing.

## Acting with and without dot-moderation

Both, always, when both can:

- **The durable half** is a record — stored, expiring, revocable, surviving a reconnect and a restart.
- **The session half** is what the player feels this second. A session already mid-message should not get one more line out because a store was slow.

`SILENCE` issues **two** records, gag first, because it is two states there and either may be revoked without the other — and a store failing halfway should leave the text mute, which is the one a spam rule was about.

`issue()` is called with maximum issuer immunity, deliberately. The guard is not a moderator with a rank: a rule declining to act because the target out-ranked a number nobody chose would silently protect exactly the people most able to abuse the server. Who is exempt is decided by the rule's own exemptions, in one place.

## Anti-cheat: the line down the middle

`DotAntiCheatEvent` splits its vocabulary in two and **nothing else in this addon matters as much**:

**Impossible** (`cheat.speed`, `teleport`, `fly`, `timing`, `fire_rate`, `reach`, `integrity`, `command_sequence`) — the server did the arithmetic and the client's claim does not fit. Facts, not opinions. A rule may act on one.

**Suspicious** (`cheat.aim_snap`, `aim_smooth`, `triggerbot`, `no_recoil`, `tracking_through_wall`, `headshot_ratio`) — every one also describes a very good player on a very good day.

`DotAntiCheat._audit_rules()` **disables at boot** any enabled rule that would punish on a single behavioural detection, and says why. That is not paternalism: aim analysis cannot distinguish a cheat from a good day, so such a rule will eventually ban somebody who did nothing, and a community remembers that far longer than it remembers a cheat. Every shipped behavioural rule warns and stops — the ladder does not continue, because a ladder is exactly how a behavioural signal turns into a wrongful ban. The suite asserts that of the whole shipped set.

**`movement_reference` is the only check that cannot be bypassed.** Give it the command and the state, and deterministic movement says exactly where the client should have ended up. The predictive open-source anti-cheats that actually work are built on nothing else, and they flag only the physically impossible, so they cannot be argued with and do not flag a player for being good or for having a bad connection. This family's first-person controller is already command-driven and deterministic precisely so a server can reconcile it, so a game using it has the hard half done.

The envelope thresholds are the fallback for a game that cannot re-simulate, and **they ship at 0, meaning off**. A surf server's legitimate speed is a speed hack on a lobby; a game with a grapple teleports on purpose. `sec_ac_status` prints the largest value each detector has actually seen, which is how an operator sets a threshold from their game rather than from a guess.

### What this cannot do

There is no client-side component and there will not be one: a Godot game ships its script code to the player, so anything running on their machine can be read, patched or replayed. Memory scanning, driver attestation and screenshot capture need a signed native anti-cheat and are not honestly buildable here. The build-hash check catches a client that lies and not one patched to report the right hash; it raises the cost of the laziest cheat and nothing more, which is still worth fifteen lines.

**It will not detect a well-written wallhack, and nothing server-side reliably does.** The mitigation is not detection, it is not sending the data — interest management, which belongs in the netcode. A client never told where the enemy is cannot draw a box around them. Anyone planning around this addon should know that before they plan.

## External ban lists

`DotBanFeeds` registers as `dot_ban_source`, the seam dot-server already asks on every admission, so nothing in dot-server changes.

**It chains rather than replaces, and that is the bug it exists to avoid.** dot-moderation registers under the same name; whichever readied second would silently win, leaving a deployment with both installed enforcing exactly one. Whatever held the name is captured **before** registering — capture after and the node finds itself and recurses until the stack gives out — and both must say yes.

Other decisions worth not undoing:

- **Plain HTTP is refused** unless `allow_insecure`. A ban list over HTTP is one anybody on the path can rewrite, and the interesting rewrite is the empty one, which fails open and silently.
- **A missing credential is refused at boot**, not on the first fetch. On a five-minute refresh that is five minutes of an unguarded server.
- **One bad feed is named and skipped**, never fatal. A server that refuses to boot over a blocklist is a server that is not running.
- **The disk cache is loaded but still marked stale.** A cache is what was true last time this process could reach the feed, and a `refuse_all` feed must not be satisfied by it.
- **Expired entries are dropped at parse time.** Enforcing until the next fetch is how somebody stays banned for a week after their day was up.
- **CIDR ranges are matched, not expanded.** A `/16` is sixty-five thousand entries for one line of somebody's list. IPv6 is a text-prefix match and says so — full v6 arithmetic in GDScript is a lot of code for something almost no blocklist publishes.
- **Credentials come from `token_file`**, because `DotConfig` refuses secrets from the environment and argv for reasons that apply here exactly.

## The guard latched the moderation store at boot, and therefore never found one

`attach()` read `DotRegistry.get_service(&"dot_moderation")` once and kept the answer. On every server in this family that has a store at all, that answer is **null**.

The ordering is not unusual, it is the only ordering there is. A `DotSecurityManager` is placed beside a `DotServer` and attaches as the server boots. dot-moderation's manager is built by the **game** — `ArenaServices`, `HungryServices`, `RoomServices`, each inside a module dot-server loads *after* the listener is open. So the registry lookup at attach time ran before the store existed, every time, and the guard spent the rest of the process believing there was none.

What that costs is the whole durable half of this addon. `DotSecurityAction.apply` falls back to the session when it is handed no store — deliberately, so a deployment without dot-moderation still gets a gag the player feels — so every automatic punishment the guard issued died with the connection and the person it was issued against reconnected and carried on. **Nothing errors and nothing looks wrong**: a server with no store is a supported configuration, `sec_status` said "session only (lost on reconnect)", and that line is indistinguishable from the truth on a server that genuinely has no store.

`moderation_store()` is the fix: the cached answer when there is one, another registry lookup when there is not. Looked up *again* rather than *every time* — the lookup is a dictionary read, but it happens on the path where somebody is being punished, and once found the answer does not change for the life of the server. `is_instance_valid` covers the game change that frees the old store and builds a new one.

Two smaller things went with it:

- **`describe()` and `sec_status` ask again too.** They were reading the latched field, so the operator's own view of what was in force agreed with the bug rather than with the server.
- **The boot line says "not yet".** It used to say "no moderation store", which on the ordinary server is wrong about a second later. It now names `sec_status` as the thing that answers what is in force now.

The suite asserts it by taking the cached answer away rather than by re-attaching, because what broke was the latch and not the lookup.

## `cfg/security.yml` exists in dot-server-deploy now

This addon was in that project's `ADDONS` list, linked into its `addons/`, compiled against by every game it vendors — and **never constructed**. A guard nobody builds watches nothing, and there is no symptom: the addon is present, the class resolves, and an operator reading the dependency list concludes their server is guarded.

`TmcHost._build_security()` builds the manager, one `DotSecurityWatch` and the detectors for every server that tool runs, and `./server check` now fails if `sec_status` or `sec_why` is missing from the console of a server that actually booted — because an absent command is invisible until an admin types it during an incident.

## Validating changes

```bash
godot --headless --path . --import
find . -name '*.gd' -not -path './.godot/*' | while read f; do
    godot --headless --path . --check-only --script "res://${f#./}"
done

# 188 checks. Exits non-zero on any failure.
godot --headless --path . res://examples/security_selftest.tscn   # 191 checks
```

The suite runs against the **real** dot-moderation rather than a mock — the durable half of every action goes through it, and a suite that stubbed it would be asserting against its own idea of that addon.

## Bugs the first run found, none of which errored

- **The console surface never registered.** A guard placed in a scene beside a server is ready *before* that server boots, and the console does not exist until it does — so `_register_console` found null and returned. The result was a server with a working guard, no `sec_status`, no `sec_why`, and no `sv_security` to turn it off with. Nothing errored because there was nothing to error. It now waits for `state_changed`. Exactly the same ordering trap as dot-server-query's host, in a different place.
- **A lambda captured a local by value.** GDScript lambdas capture locals by value, so a test assigning to a captured `String` inside a signal handler changed nothing outside it, and the assertion read as dot-server having changed its refusal wording.
- **Anti-cheat events were reported as unknown.** `warn_unknown_events` checked only `DotSecurityEvent.KNOWN`, so every shipped anti-cheat rule logged a warning at boot saying no watcher reports its event — while the detector shipped in the same addon reported exactly that.

## File map

```
addons/dot_server_security/
  core/
    dot_security_event.gd     What happened. An OPEN vocabulary, on purpose.
    dot_security_subject.gd   Who it counts against. uid / address / both.
    dot_security_action.gd    What to do, and the two backends that can do it.
    dot_security_step.gd      One rung of an escalation ladder.
    dot_security_rule.gd      A rule, and its JSON form — the surface that matters.
    dot_security_policy.gd    The shipped rule set, and layering a file over it.
    dot_security_window.gd    Sliding counters with a hard bound on memory.
    dot_security_config.gd    Everything that is not a rule.
  runtime/
    dot_security_manager.gd   Counts, decides, acts. Registered as dot_security.
    dot_security_ledger.gd    What it did and why. What sec_why answers from.
  watch/
    dot_security_watch.gd     Wires chat, connections, RCON, commands and auth.
  anticheat/
    dot_anticheat_event.gd    The impossible/suspicious split. Read this first.
    dot_anticheat_config.gd   Every threshold, and why yours are not these.
    dot_anticheat.gd          The detectors, and what they cannot do.
  banlist/
    dot_ban_feed.gd           One endpoint: where, how to authenticate, how to parse.
    dot_ban_index.gd          The merged list. CIDR matched, never expanded.
    dot_ban_feeds.gd          Fetch, merge, cache, and chain into dot_ban_source.
  console/
    dot_security_commands.gd  The operator's whole view. sec_why is the one.
  cfg/
    security_rules.example.json
    ban_feeds.example.json
```

## Things deliberately not here

- **A client-side component.** See the anti-cheat section. It would be theatre.
- **Machine learning over aim traces.** The published work on it is real and needs a labelled dataset from your own game to be worth anything; the hooks here (`observe_aim`, `observe_trigger`) are where such a model would plug in, and a model shipped without your data would be a random number generator with a confusion matrix.
- **Wallhack detection.** Interest management in the netcode is the answer, and it is not this addon's to give.
- **Its own ban storage.** dot-moderation is the durable store and `DotBanFeeds` is the read-only external half. Two write targets is the two-lists problem dot-moderation's own README warns about.
- **Rate limiting the game's own traffic.** dot-server's `DotAddressGuard` caps connections per address and dot-server-query rate-limits queries; both are in the right places already.
