# Anti-cheat: the line down the middle

`DotAntiCheatEvent` splits its vocabulary in two and **nothing else in this addon matters as much**:

**Impossible** (`cheat.speed`, `teleport`, `fly`, `timing`, `fire_rate`, `reach`, `integrity`, `command_sequence`): the server did the arithmetic and the client's claim does not fit. Facts, not opinions. A rule may act on one.

**Suspicious** (`cheat.aim_snap`, `aim_smooth`, `triggerbot`, `no_recoil`, `tracking_through_wall`, `headshot_ratio`): every one also describes a very good player on a very good day.

## Behavioural rules cannot punish on one detection

`DotAntiCheat._audit_rules()` **disables at boot** any enabled rule that would punish on a single behavioural detection, and says why. That is not paternalism: aim analysis cannot distinguish a cheat from a good day, so such a rule will eventually ban somebody who did nothing, and a community remembers that far longer than it remembers a cheat. Every shipped behavioural rule warns and stops; the ladder does not continue, because a ladder is exactly how a behavioural signal turns into a wrongful ban. The suite asserts that of the whole shipped set.

## Re-simulation is the check that cannot be bypassed

**`movement_reference` is the only check that cannot be bypassed.** Give it the command and the state, and deterministic movement says exactly where the client should have ended up. The predictive server-side anti-cheats that actually work are built on nothing else, and they flag only the physically impossible, so they cannot be argued with and do not flag a player for being good or for having a bad connection. This family's first-person controller is already command-driven and deterministic precisely so a server can reconcile it, so a game using it has the hard half done.

## Envelope thresholds ship off

The envelope thresholds are the fallback for a game that cannot re-simulate, and **they ship at 0, meaning off**. A surf server's legitimate speed is a speed hack on a lobby; a game with a grapple teleports on purpose. `sec_ac_status` prints the largest value each detector has actually seen, which is how an operator sets a threshold from their game rather than from a guess.

## What this cannot do

There is no client-side component and there will not be one: a Godot game ships its script code to the player, so anything running on their machine can be read, patched or replayed. Memory scanning, driver attestation and screenshot capture need a signed native anti-cheat and are not honestly buildable here. The build-hash check catches a client that lies and not one patched to report the right hash; it raises the cost of the laziest cheat and nothing more, which is still worth fifteen lines.

**It will not detect a well-written wallhack, and nothing server-side reliably does.** The mitigation is not detection, it is not sending the data: interest management, which belongs in the netcode. A client never told where the enemy is cannot draw a box around them. Anyone planning around this addon should know that before they plan.
