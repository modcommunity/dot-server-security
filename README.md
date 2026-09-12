This is the **server security** asset for TMC's **Dot** collection. It watches what happens on a dedicated server, counts it against rules an operator writes, and escalates — warn, gag, mute, kick, ban — without anybody having to be awake.

This collection of assets provides modular building blocks for creating games and applications within the TMC ecosystem, ensuring consistency and interoperability across all `dot-*` assets. This includes core functionality, networking, authentication, cloud integration, and more.

**These assets are COMPLETELY OPEN SOURCE**. You are free to use, modify, and distribute them under the terms of the MIT license. The only thing not open source is the back-end web infrastructure. So if you opt into using your own authentication backend instead of integrating with TMC, you will need to build and integrate your own back-end infrastructure.

## From Maintainer & WARNING
This asset, along with all the others, was built initially with **Claude Code** and will continue to be maintained and extended using it. This is because I (`gamemann`) cannot build the entire TMC platform alone (I wish I could lol).

**Please treat this as partially tested.** Every asset has its own headless test suite and those suites pass, but very little of this has been in front of real players yet. Expect rough edges, and please report anything you run into.

I intend on reviewing code, testing, and editing documentation regularly. If you're interested in helping out, please let me know!

## It ships doing nothing, and that is the point

Every rule is in dry run on install. It counts, it logs, it fills in `sec_status` — and it punishes nobody until you say so.

An addon that starts punishing an existing community the moment it is installed, on thresholds nobody chose, against a chat culture it has never seen, is one that gets uninstalled after the first false positive. Then the server has no guard at all. Run it for a week, read `sec_status`, then `sv_security_dryrun 0`.

## The shape of a rule

**This many of that event, from one subject, within this window — then take the next step on the ladder.**

```json
{
  "id": "chat_flood",
  "event": "chat.message",
  "threshold": 6,
  "window_sec": 10,
  "scope": "uid",
  "cooldown_sec": 15,
  "steps": [
    {"action": "warn", "message": "Slow down, please."},
    {"action": "gag",  "duration_sec": 300},
    {"action": "gag",  "duration_sec": 1800},
    {"action": "kick"}
  ]
}
```

Six messages in ten seconds. First time, a warning; then five minutes; then half an hour; then out. Offences are remembered for `offence_memory_sec`, so somebody who spammed this morning does not start again at "warn" tonight — and somebody who spammed a fortnight ago does.

**The ladder is why this is more than a rate limiter.** A flat rule has one answer for a first offence and a fiftieth, so you end up choosing between punishing a new player for typing fast and letting a spammer run.

**`cooldown_sec` is the setting you would not have thought of.** Without it, a rule whose action does not stop the behaviour — a warning — trips again on the very next message and walks its whole ladder in one second, banning somebody over four lines.

## What it watches

| | |
| --- | --- |
| `chat.message` `chat.duplicate` `chat.caps` `chat.link` `chat.refused` `chat.command` | text chat, from the server's own path and from dot-chat's router |
| `connect.attempt` `connect.rejected` `connect.churn` | connections, including the reconnect loop no single connection looks wrong in |
| `auth.failed` `auth.rejected` | authentication, when dot-auth is installed |
| `rcon.auth_failed` `rcon.command` | the remote console |
| `command.denied` | somebody probing for commands they do not hold |
| `cheat.*` | the anti-cheat detectors, below |

**The vocabulary is open.** `guard.report_session(&"arena.buy_menu_spam", session)` is one line, and that event gets the whole engine: windows, thresholds, ladders, exemptions, the ledger, dry run and `sec_why`. A closed enum would have meant every game forking this.

## Scope: count against a person, or against a connection

Count against a connection and you have counted nothing — a peer id dies with the socket, so "five messages in ten seconds" is dodged by reconnecting.

- **`uid`** for behaviour that is a person's: chat, commands, votes. Follows them to a new address; does not punish the sibling on the same connection.
- **`address`** for anything that happens *before* there is an identity, which is most of what an attack is: connection floods, wrong RCON passwords, authentication that never completed.
- **`both`** counts twice, separately, so one rule catches "this account is spamming" and another "this address is spamming from a new account each time".

## Anti-cheat

Detections are ordinary events, so all the rule machinery applies to them. **There are two kinds and conflating them is the mistake every home-grown anti-cheat makes.**

**Impossible** — the server re-simulated what the client claimed and the claim does not fit. Moving further in a tick than the movement code can produce, firing faster than the weapon allows, claiming more simulated time than has elapsed. These are facts about arithmetic. A rule may act on one.

**Suspicious** — aim that snaps, aim too smooth to be a hand, firing inside human reaction time, a headshot rate three deviations out. Every one of these also describes a very good player on a very good day. They accumulate, they warn, they tell the admins. **The shipped behavioural rules never punish, and the detector refuses at boot to let you configure one that punishes on a single detection** — because a community remembers a wrongly banned good player far longer than it remembers a cheat.

The strongest check is a re-simulation:

```gdscript
ac.movement_reference = func(session, from, velocity, command, delta) -> Vector3:
    return my_controller.simulate(from, velocity, command, delta)
```

Given the command a client sent and the state it started from, deterministic movement says exactly where it should have ended up; anything else is a claim the server can reject. This family's first-person controller is already command-driven and deterministic precisely so a server can reconcile it. Without one, the envelope thresholds (`max_horizontal_speed` and friends) are the fallback — and they ship at `0`, meaning off, because the honest way to set them is to read the peaks off `sec_ac_status` after a week of your own game.

**What it cannot do, stated plainly.** There is no client-side component and there will not be one: a Godot game ships its script code to the player, so anything running on their machine can be read, patched or replayed. Memory scanning and driver-level attestation need a signed native anti-cheat and are not honestly buildable here. It will not detect a well-written wallhack — nothing server-side reliably does. **The mitigation for that is not detection, it is not sending the data**: interest management, in the netcode. A client never told where the enemy is cannot draw a box around them.

## External ban lists

Any number of endpoints, merged, cached, and consulted on every join.

```json
{
  "id": "network",
  "url": "https://bans.example.net/api/v1/active",
  "auth": "bearer",
  "token_file": "user://cfg/network.token",
  "list_path": "data.bans",
  "on_failure": "keep_last"
}
```

- **Auth**: public, bearer (a static key or a JWT alike), basic, a custom header, a query parameter, or a timestamp-nonce-HMAC that sends nothing replayable.
- **Formats**: a bare array of strings, an array of objects with any of several field names, a wrapper object, or `{"uids": [...], "ips": [...]}`. A blocklist you cannot point this at is one you will copy into a file by hand, and then it is stale.
- **IDs, addresses and CIDR ranges.** A `/24` is matched, not expanded — expanding a `/16` is sixty-five thousand entries for one line of somebody's list.
- **Expiries are honoured.** A list that publishes them and a consumer that ignores them is how somebody stays banned for a week after their day was up.
- **It caches to disk**, so a restart during an outage still enforces.
- **`on_failure`** is `keep_last` (default), `ignore`, or `refuse_all` — fail open or fail closed, your call.

**It chains rather than replaces.** dot-moderation registers under the same `dot_ban_source` name, and whichever readied second would otherwise silently win — leaving a deployment with both enforcing exactly one. Both are asked, and both must say yes.

**Credentials come from a file.** `token_file`, not the environment and not the command line: both are readable by other processes and both end up in `ps` output and in pasted bug reports.

## With and without dot-moderation

With it, a gag is a record: stored, expiring, revocable, surviving a reconnect and a restart, sitting in that addon's listing beside the ones a human issued.

Without it, a gag is two booleans on a session object — real, felt, and lost when they reconnect. Both are supported, because refusing to act without dot-moderation would make this addon conditional on another optional one, and a five-minute gag is still worth having against the ninety-nine per cent who will not think to reconnect out of it.

Nothing here names dot-moderation, dot-chat or dot-auth. All three are reached at runtime.

## Explaining yourself

```
] sec_why Someone
2 record(s) matching 'Someone':
  2026-09-12T14:02:11  chat_flood  account u-8813  offence 2: 7 x chat.message in 10s -> gag 5m
  2026-09-12T14:39:40  chat_repeat account u-8813  offence 1: 3 x chat.duplicate in 30s -> warn
```

An automatic punishment nobody can explain gets lifted blindly or refused blindly, and after the second time the operator turns the guard off. `sec_forget` is the other half: clear somebody's counters after lifting a punishment by hand, or the next event escalates from where the ladder left off and the person you just forgave is gagged again for one message.

Also: `sec_status`, `sec_rules`, `sec_rule <id>`, `sec_log`, `sec_enable` / `sec_disable`, `sec_reload`, `sec_dump`, `sec_test` (feed it synthetic events to prove a rule fires), `sec_bans`, `sec_bans_refresh`, `sec_bans_check`, `sec_ac_status`, `sec_ac_dryrun`. Plus `sv_security` and `sv_security_dryrun`, both live.

## Installing

Copy `addons/dot_server_security/`, [`dot-core`](https://github.com/modcommunity/dot-core)'s `addons/dot_core/` and [`dot-server`](https://github.com/modcommunity/dot-server)'s `addons/dot_server/` into your project and enable dot-server-security in *Project → Project Settings → Plugins*.

```gdscript
var guard := DotSecurityManager.new()
server.add_child(guard)

var watch := DotSecurityWatch.new()      # wires it to everything worth watching
server.add_child(watch)
```

[dot-moderation](https://github.com/modcommunity/dot-moderation), [dot-chat](https://github.com/modcommunity/dot-chat) and [dot-auth](https://github.com/modcommunity/dot-auth) are optional and are named nowhere in the source.

## Testing

```bash
godot --headless --path . res://examples/security_selftest.tscn
```

188 checks: the sliding window and its memory bound, escalation and cooldowns, exemptions, dry run, rules from JSON, the chat detectors, CIDR matching, every feed format and every auth mode, ban-source chaining, the anti-cheat split, and the fallback with no moderation store. The couplings to addons this one must not name — dot-moderation's subject prefixes and punishment kinds, dot-server's refusal wording — are asserted against the real addons rather than trusted to a comment, because a comment does not fail when the other side changes.
