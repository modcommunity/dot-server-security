@tool
class_name DotSecurityConfig
extends DotConfig

## Everything about the guard that is not a rule.
##
## Layered like every other config in this family: exported defaults, then a JSON
## file, then the environment, then the command line. The rules themselves are a
## list rather than a scalar and live in their own file — see [member rules_file]
## and [DotSecurityPolicy].

@export_group("Master")

## The whole guard. Off counts nothing, acts on nothing and costs nothing.
@export var enabled: bool = true

## [b]Count and log, never act.[/b]
##
## The setting to run a new rule set under for a week before trusting it. Every
## rule evaluates, every trip is logged and enters the ledger marked
## [code]would[/code], and nobody is warned, gagged, kicked or banned.
##
## [b]On by default, deliberately.[/b] An addon that starts punishing an existing
## community the moment it is installed — on thresholds nobody chose, against a
## chat culture it has never seen — is one that gets uninstalled after the first
## false positive, and the server ends up with no guard at all. `sec_dryrun 0`,
## or this setting, is a decision an operator should make after reading
## `sec_status` rather than one made for them at install time.
@export var dry_run: bool = true

@export_group("Files")

## JSON file of rules, layered over whatever the policy was built with.
##
## Empty uses the shipped defaults alone. This is the file an operator edits.
@export var rules_file: String = "user://cfg/security_rules.json"

## Write the effective rule set here at boot, for an operator to read and copy.
##
## Not the same file as [member rules_file] and never overwrites it: a config
## file that the program rewrites is one an operator stops trusting their own
## edits to.
@export var dump_rules_file: String = ""

@export_group("Telling people")

## Tell the player what happened and why.
##
## [b]Worth it.[/b] A player silently unable to type concludes the server is
## broken and asks in a voice channel, or leaves. One line naming the rule turns
## an automated punishment into something they can argue with, which is also what
## makes a bad rule visible to the operator.
@export var notify_subject: bool = true

## Tell connected admins when a rule acts.
@export var notify_admins: bool = true

## Flag an admin needs to be told. Empty tells every admin.
@export var notify_flag: String = "generic"

## Also announce removals to everybody, the way a manual kick is announced.
@export var announce_removals: bool = false

@export_group("Chat detection")

## Shortest message the capitals check looks at.
##
## Below this, capitals mean nothing: "OK", "GG" and "WHAT" are not shouting, and
## a rule that counts them catches every player on the server.
@export_range(0, 200, 1) var caps_min_length: int = 12

## Fraction of letters that must be capitals to count as shouting.
@export_range(0.1, 1.0, 0.05) var caps_ratio: float = 0.7

## How long a message is remembered for the duplicate check, in seconds.
@export_range(0.0, 600.0, 1.0) var duplicate_memory_sec: float = 30.0

## How many recent messages per subject the duplicate check compares against.
@export_range(1, 64, 1) var duplicate_depth: int = 5

## Treat a near-identical message as a duplicate, not just an exact one.
##
## Compares with case, whitespace and punctuation removed, which is what catches
## the spammer who adds a full stop each time.
@export var duplicate_normalises: bool = true

## Substrings that make a message count as containing a link.
##
## Deliberately crude and deliberately configurable. A real URL parser here would
## be slower, would still be wrong, and would not know that this community
## tolerates one domain and not another.
@export var link_markers: PackedStringArray = PackedStringArray([
	"http://", "https://", "www.", ".com/", ".net/", ".gg/", "discord.gg"
])

## Links from these are never counted. Substring match on the whole message.
@export var link_allow: PackedStringArray = PackedStringArray()

@export_group("Connections")

## Seconds within which a connect-then-leave counts as churn.
##
## Longer than a slow join and much shorter than a short session. A player who
## joins, sees the map and leaves inside this is the pattern; one who plays a
## round is not.
@export_range(1.0, 600.0, 1.0) var churn_window_sec: float = 20.0

@export_group("Bookkeeping")

## How many decisions the ledger keeps, for `sec_why` and a bug report.
@export_range(16, 100000, 16) var ledger_size: int = 512

## Log a rule naming an event no watcher ever reports.
##
## On, because it is almost always a typo in a rule file, and the symptom
## otherwise is a rule that simply never fires — which looks exactly like a rule
## that is working and never needed.
@export var warn_unknown_events: bool = true


func env_prefix() -> String:
	return "DOT_SECURITY_"


func cli_prefix() -> String:
	return "--sec-"


func validate() -> DotResult:
	if caps_ratio <= 0.0 or caps_ratio > 1.0:
		return DotResult.fail(
			DotError.CODE_INVALID, "caps_ratio must be between 0 and 1."
		)

	if ledger_size < 16:
		return DotResult.fail(
			DotError.CODE_INVALID, "ledger_size must be at least 16."
		)

	return DotResult.success(self)
