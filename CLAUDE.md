# dot-server-security

Hardening a dedicated server, as configuration: sliding-window rules over chat, connections, authentication, the remote console and the anti-cheat detectors, escalating through warn, gag, mute, kick and ban; anti-cheat that splits "the server proved it" from "a human should look"; and external ban-list feeds chained into dot-server's `dot_ban_source`. Ships in dry run.

Read the family [CLAUDE.md](../../CLAUDE.md) first; this file is only what is specific to this addon. The reasoning is in [docs/](docs/README.md).

**The distributable is `addons/dot_server_security/`.** It requires dot-core and dot-server. dot-moderation, dot-chat and dot-auth are optional, discovered at runtime and named nowhere; the suite wants all three linked (`.gitignore`), because linking the real addons is what checks the couplings against the thing they describe rather than a mock.

## Read before

| Read | Before |
| --- | --- |
| [docs/README.md](docs/README.md) | the index |
| [docs/rules.md](docs/rules.md) | the manager, rules, windows, actions, the watch, the console, anything touching dot-moderation |
| [docs/anticheat.md](docs/anticheat.md) | `DotAntiCheat`, `DotAntiCheatEvent`, `DotAntiCheatConfig` |
| [docs/ban-feeds.md](docs/ban-feeds.md) | `DotBanFeed`, `DotBanIndex`, `DotBanFeeds` |
| [docs/history.md](docs/history.md) | the bugs, and how each looked |

## Layout

| Path | What |
| --- | --- |
| `addons/dot_server_security/core/` | `DotSecurityEvent` (an open vocabulary), `DotSecuritySubject` (uid / address / both), `DotSecurityAction` (and its two backends), `DotSecurityStep`, `DotSecurityRule` and its JSON form, `DotSecurityPolicy` (the shipped set, and layering a file over it), `DotSecurityWindow`, `DotSecurityConfig` |
| `addons/dot_server_security/runtime/` | `DotSecurityManager` (counts, decides, acts; registered as `dot_security`), `DotSecurityLedger` (what `sec_why` answers from) |
| `addons/dot_server_security/watch/` | `DotSecurityWatch`: wires chat, connections, RCON, commands and auth |
| `addons/dot_server_security/anticheat/` | `DotAntiCheatEvent` (the impossible/suspicious split), `DotAntiCheatConfig`, `DotAntiCheat` |
| `addons/dot_server_security/banlist/` | `DotBanFeed` (one endpoint), `DotBanIndex` (the merged list), `DotBanFeeds` (fetch, merge, cache, chain) |
| `addons/dot_server_security/console/` | `DotSecurityCommands`: the operator's whole view; `sec_why` is the one |
| `addons/dot_server_security/cfg/` | `security_rules.example.json`, `ban_feeds.example.json` |
| `examples/security_selftest.tscn` | the suite, against the real dot-moderation |
| `examples/cfg_selftest.tscn` | `security.yml` through `DotSecurityConfig.load_cfg` and `DotAntiCheatConfig.load_cfg`: `cfg/addons/dot_server_security/`, `cfg/server/addons/dot_server_security/` over it, the flat `cfg/security.yml` shim (WARN once, removed 2026-12-31) |

## Running and testing

- The family's two steps ([game-dev/CLAUDE.md](../../CLAUDE.md#validating-anything)), then `godot --headless --path . res://examples/security_selftest.tscn` (non-zero on failure).
- The suite runs against the real dot-moderation, dot-chat and dot-auth; never replace them with mocks. [rules](docs/rules.md#the-couplings-and-why-they-are-tested-rather-than-commented)
- dot-server-deploy builds this for every server it runs (`TmcHost._build_security()`, `cfg/security.yml`); a change to the console surface should still pass its `./server check`. [history](docs/history.md#the-guard-was-linked-and-never-built)

## Rules that bite

**The engine**

- One engine: anti-cheat detections and game events are `DotSecurityEvent`s like any other; never build a second counter. [rules](docs/rules.md#one-engine-and-everything-is-an-event)
- `dry_run` defaults to true, anti-cheat has its own, and shipped thresholds stay timid. [rules](docs/rules.md#it-ships-in-dry-run-and-that-is-a-decision)
- `cooldown_sec` is what stops a warning walking its ladder in a second; `offence_memory_sec` is not `window_sec`; `scope` decides if a count survives a reconnect; the ladder repeats its last rung; exemption is checked at the action, not the count. [rules](docs/rules.md#the-five-settings-that-are-not-obvious)
- Windows slide, never reset on a boundary, and every structure in them is capped oldest-first. [rules](docs/rules.md#why-the-sliding-window-is-sliding)
- `warn_unknown_events` must know the anti-cheat events too. [history](docs/history.md#the-first-run)

**Couplings**

- `PREFIX_UID`/`PREFIX_ADDRESS`, `MOD_KIND_*` and `REFUSAL_PERMISSION` reproduce values from dot-moderation and dot-server, and the suite asserts each against the real addon. [rules](docs/rules.md#the-couplings-and-why-they-are-tested-rather-than-commented)
- Act on both halves: the durable record and the session. `SILENCE` is two records, gag first; `issue()` uses maximum issuer immunity. [rules](docs/rules.md#acting-with-and-without-dot-moderation)
- Never latch the moderation store at attach: `moderation_store()` looks again until it finds one, and so do `describe()` and `sec_status`. [rules](docs/rules.md#finding-the-moderation-store)
- The console registers after the server's `state_changed`. [rules](docs/rules.md#finding-the-moderation-store)

**Anti-cheat**

- Impossible detections may act; suspicious ones only warn. `_audit_rules()` disables at boot any rule that would punish on one behavioural detection. [anticheat](docs/anticheat.md#behavioural-rules-cannot-punish-on-one-detection)
- `movement_reference` (re-simulation) is the real check; envelope thresholds ship at 0 (off), and `sec_ac_status` shows what to set them from. [anticheat](docs/anticheat.md#envelope-thresholds-ship-off)
- No client-side component and no wallhack detection; that is interest management in the netcode. [anticheat](docs/anticheat.md#what-this-cannot-do)

**Ban feeds**

- `DotBanFeeds` chains into `dot_ban_source` (capture before registering), re-chains on every registry change, and stops when the newcomer's `previous_source` chain already reaches it. [ban-feeds](docs/ban-feeds.md#it-chains-and-stays-on-top)
- Plain HTTP refused without `allow_insecure`; missing credentials refused at boot; one bad feed skipped; disk cache loaded stale; expired entries dropped at parse; CIDR matched, not expanded; credentials from `token_file`. [ban-feeds](docs/ban-feeds.md#decisions-worth-not-undoing)

Deliberately not here: a client-side component, machine learning over aim traces (`observe_aim`/`observe_trigger` are the hooks), wallhack detection, its own ban storage, rate limiting game traffic. [rules](docs/rules.md#deliberately-not-here)
