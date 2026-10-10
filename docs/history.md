# History

Bugs worth recognising if they come back. None errored.

## The guard latched the moderation store at boot

`attach()` read `DotRegistry.get_service(&"dot_moderation")` once and kept the answer. On every server in this family that has a store at all, that answer was **null**: dot-moderation's manager is built by the game's services layer, inside a module dot-server loads *after* the listener is open, and the guard attaches as the server boots. The ordering is not unusual, it is the only ordering there is.

What that cost was the whole durable half of this addon. `DotSecurityAction.apply` falls back to the session when it is handed no store (deliberately, so a deployment without dot-moderation still gets a gag the player feels), so every automatic punishment the guard issued died with the connection and the person it was issued against reconnected and carried on. **Nothing looked wrong**: a server with no store is a supported configuration, and `sec_status` said "session only (lost on reconnect)", indistinguishable from the truth on a server that genuinely has none. `describe()` and `sec_status` read the latched field too, so the operator's own view agreed with the bug.

The fix is `moderation_store()` ([rules](rules.md#finding-the-moderation-store)). The suite asserts it by taking the cached answer away rather than by re-attaching, because what broke was the latch and not the lookup.

## The guard was linked and never built

dot-server-deploy had this addon in its `ADDONS` list, linked and compiled against by every game it vendors, and **never constructed** it. A guard nobody builds watches nothing, and there is no symptom: the addon is present, the class resolves, and an operator reading the dependency list concludes their server is guarded. dot-server-deploy's `TmcHost._build_security()` builds it now (configured by `cfg/security.yml`), and its `./server check` fails if `sec_status` or `sec_why` is missing from a server that booted.

## The first run

- **The console surface never registered.** A guard placed in a scene beside a server is ready *before* that server boots, and the console does not exist until it does, so `_register_console` found null and returned: a working guard, no `sec_status`, no `sec_why`, and no `sv_security` to turn it off with. It now waits for `state_changed`. The same ordering trap as dot-server-query's host.
- **A lambda captured a local by value.** A test assigning to a captured `String` inside a signal handler changed nothing outside it, and the assertion read as dot-server having changed its refusal wording. See [gdscript-hazards](../../../docs/gdscript-hazards.md#a-lambda-captures-by-value-and-that-means-something-different-per-type).
- **Anti-cheat events were reported as unknown.** `warn_unknown_events` checked only `DotSecurityEvent.KNOWN`, so every shipped anti-cheat rule logged a boot warning saying no watcher reports its event, while the detector shipped in the same addon reported exactly that.
