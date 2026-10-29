# Reasoning moved out of code comments

Short versions of what the source comments used to carry in full; each is a decision a later edit should not undo.

## Count against the account or address, never the connection

A peer id dies with the socket, so "five messages in ten seconds" is dodged by reconnecting. UID scope follows a person across addresses and does not punish a sibling on the same connection; ADDRESS scope covers what happens before any identity exists (connection floods, wrong RCON passwords, authentication that never completed); BOTH counts the event in each scope and is not the default because it doubles the counters. The `PREFIX_UID`/`PREFIX_ADDRESS` spellings mirror dot-moderation's, which this addon must not name, and the self-test asserts them against the real addon.

## Windows are bounded because the guard is an attack target

A structure that grows one entry per event and one bucket per address is a memory-exhaustion target reachable by exactly the traffic the addon watches: a million messages from a million connections must not make the guard the thing that falls over. Entries per subject and subjects are capped and the oldest go first. Losing the oldest entries under attack is the right failure, because a subject at the entry cap is already far past any sane threshold and its rule has fired.

## Client-supplied text is escaped before it is logged

An anti-cheat detail can contain what the client said (its build string, a weapon id). `DotLog.format_fields` quotes a value but does not escape a newline, so a build string of `x\ninf security ...` once wrote a second, forged record into the log an admin reads to decide who cheated, and a megabyte one wrote a megabyte per detection. Strings are escaped and cut on the one path that logs a detail; numbers the server measured pass through.

## The moderation store is looked up again, not latched

A `DotSecurityManager` placed beside a server attaches as the server boots, but dot-moderation's manager is built by the game in a module loaded afterwards, so the registry lookup at attach is null on every server that has a store. Latching that answer made every gag, mute and ban fall back to the session, which dies with the connection: nothing errored, because a server with no store is a supported configuration. The lookup is repeated until found and dropped when a game change frees the store.

## Console registration waits for the console

A guard in a scene beside a server is ready before the server boots, and the console does not exist until it does. Registering unconditionally silently produced a working guard with no `sec_status`, no `sec_why` and no `sv_security` to turn it off.

## Permission refusals are recognised by a string prefix

`command_executed` fires only after the permission check passed, so it never sees a denial; `command_refused` sees every refusal and distinguishes permission by a text prefix alone. That is the only way to tell probing from mistyping, and the self-test asserts the prefix against the real dot-server because a comment does not fail when the wording changes.

## An auth failure with no address is dropped

dot-auth reports why, not who. A failure that cannot be attributed to a session still mid-handshake is dropped rather than attributed to nobody: a rule counting "somebody, somewhere failed" would ban the next person to connect.
