@tool
class_name DotSecurityConfig
extends DotSecurityConfigBase

## Everything about the guard that is not a rule.
## Layered like every config in this family; the rules live in their own file ([member rules_file], [DotSecurityPolicy]).

@export_group("Master")

## The whole guard. Off counts nothing, acts on nothing and costs nothing.
@export var enabled: bool = true

## [b]Count and log, never act.[/b] Every rule evaluates and every trip is logged and enters the ledger as [code]would[/code], but nobody is punished.
## On by default, deliberately: a guard that punishes an existing community on thresholds nobody chose gets uninstalled after the first false positive. Turning it off is a decision made after reading `sec_status` (docs/rules.md).
@export var dry_run: bool = true

@export_group("Files")

## JSON file of rules, layered over whatever the policy was built with.
##
## Empty uses the shipped defaults alone. This is the file an operator edits.
@export var rules_file: String = "user://cfg/security_rules.json"

## Write the effective rule set here at boot, for an operator to read and copy.
## Never the same file as [member rules_file] and never overwrites it: a config the program rewrites is one an operator stops trusting their edits to.
@export var dump_rules_file: String = ""

@export_group("Telling people")

## Tell the player what happened and why.
## A player silently unable to type assumes the server is broken; one line naming the rule makes the punishment arguable and a bad rule visible to the operator.
@export var notify_subject: bool = true

## Tell connected admins when a rule acts.
@export var notify_admins: bool = true

## Flag an admin needs to be told. Empty tells every admin.
@export var notify_flag: String = "generic"

## Also announce removals to everybody, the way a manual kick is announced.
@export var announce_removals: bool = false

@export_group("Chat detection")

## Shortest message the capitals check looks at.
## Below this capitals mean nothing ("OK", "GG"), and counting them would catch every player.
@export_range(0, 200, 1) var caps_min_length: int = 12

## Fraction of letters that must be capitals to count as shouting.
@export_range(0.1, 1.0, 0.05) var caps_ratio: float = 0.7

## How long a message is remembered for the duplicate check, in seconds.
@export_range(0.0, 600.0, 1.0) var duplicate_memory_sec: float = 30.0

## How many recent messages per subject the duplicate check compares against.
@export_range(1, 64, 1) var duplicate_depth: int = 5

## Treat a near-identical message as a duplicate, not just an exact one.
## Compares with case, whitespace and punctuation removed, which catches the spammer who adds a full stop each time.
@export var duplicate_normalises: bool = true

## Substrings that make a message count as containing a link.
## Crude and configurable on purpose: a URL parser would be slower, still wrong, and unaware that a community tolerates one domain and not another.
@export var link_markers: PackedStringArray = PackedStringArray([
	"http://", "https://", "www.", ".com/", ".net/", ".gg/", "discord.gg"
])

## Links from these are never counted. Substring match on the whole message.
@export var link_allow: PackedStringArray = PackedStringArray()

@export_group("Connections")

## Seconds within which a connect-then-leave counts as churn.
## Longer than a slow join, much shorter than a short session: joining, seeing the map and leaving inside it is the pattern.
@export_range(1.0, 600.0, 1.0) var churn_window_sec: float = 20.0

@export_group("Bookkeeping")

## How many decisions the ledger keeps, for `sec_why` and a bug report.
@export_range(16, 100000, 16) var ledger_size: int = 512

## Log a rule naming an event no watcher ever reports.
## On, because it is almost always a typo, and the symptom otherwise is a rule that never fires, which looks like one that is working.
@export var warn_unknown_events: bool = true


func env_prefix() -> String:
	return "DOT_SECURITY_"


func cli_prefix() -> String:
	return "--sec-"

## `security.yml` key -> property, for the guard.
const CFG_KEYS := {
	"sec_enabled": "enabled",
	"sec_dryrun": "dry_run",
	"sec_rules_file": "rules_file",
	"sec_notify_subject": "notify_subject",
	"sec_notify_admins": "notify_admins",
	"sec_notify_flag": "notify_flag",
	"sec_announce_removals": "announce_removals",
	"sec_caps_min_length": "caps_min_length",
	"sec_caps_ratio": "caps_ratio",
	"sec_duplicate_memory_sec": "duplicate_memory_sec",
	"sec_duplicate_depth": "duplicate_depth",
	"sec_link_allow": "link_allow",
	"sec_churn_window_sec": "churn_window_sec",
	"sec_ledger_size": "ledger_size",
}



func cfg_keys() -> Dictionary:
	return CFG_KEYS


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
