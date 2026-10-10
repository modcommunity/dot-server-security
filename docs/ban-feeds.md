# External ban lists

`DotBanFeeds` registers as `dot_ban_source`, the seam dot-server already asks on every admission, so nothing in dot-server changes.

## It chains, and stays on top

**It chains rather than replaces, and that is the bug it exists to avoid.** dot-moderation registers under the same name; whichever readied second would silently win, leaving a deployment with both installed enforcing exactly one.

- Whatever held the name is captured **before** registering. Capture after and the node finds itself and recurses until the stack gives out. Both must say yes.
- **It is kept on top, not put there once.** A game's module registers dot-moderation under the same name on every changelevel, and the registry is last-wins, so a chain captured only at `_ready` is displaced by the first level change and the feeds are never asked again. `DotBanFeeds` listens to `DotRegistry.signals()` and, deferred, chains onto whoever arrived and registers itself again.
- **Unless the newcomer's own `previous_source` chain already reaches the feeds** (dot-server-deploy's party bookings do the same dance), because going on top of that would make the chain a loop.

## Decisions worth not undoing

- **Plain HTTP is refused** unless `allow_insecure`. A ban list over HTTP is one anybody on the path can rewrite, and the interesting rewrite is the empty one, which fails open and silently.
- **A missing credential is refused at boot**, not on the first fetch. On a five-minute refresh that is five minutes of an unguarded server.
- **One bad feed is named and skipped**, never fatal. A server that refuses to boot over a blocklist is a server that is not running.
- **The disk cache is loaded but still marked stale.** A cache is what was true last time this process could reach the feed, and a `refuse_all` feed must not be satisfied by it.
- **Expired entries are dropped at parse time.** Enforcing until the next fetch is how somebody stays banned for a week after their day was up.
- **CIDR ranges are matched, not expanded.** A `/16` is sixty-five thousand entries for one line of somebody's list. IPv6 is a text-prefix match and says so: full v6 arithmetic in GDScript is a lot of code for something almost no blocklist publishes.
- **Credentials come from `token_file`**, because `DotConfig` refuses secrets from the environment and argv for reasons that apply here exactly.
