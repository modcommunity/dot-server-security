@tool
class_name DotBanFeeds
extends Node

## Fetches external ban lists, merges them, and refuses the people on them.
##
## Registers as [code]dot_ban_source[/code], which is the seam dot-server already
## asks on every admission — so nothing in dot-server changes and no addon
## imports another.
##
## [b]It chains rather than replaces.[/b] dot-moderation registers under the same
## name, and whichever node readies second would otherwise silently win, leaving
## a deployment with both installed enforcing exactly one of them. Whatever was
## registered before is kept and asked as well, and both answers have to be
## "admit" for a player to get in. An operator with dot-moderation and two
## partner feeds gets all three, which is what they thought they were getting.
##
## [codeblock]
## var feeds := DotBanFeeds.new()
## feeds.feeds = [
##     DotBanFeed.of(&"network", "https://bans.example.org/v1/active"),
##     DotBanFeed.of(&"partner", "https://partner.example/blocklist.json"),
## ]
## server.add_child(feeds)
## [/codeblock]

const CHANNEL := "security"
const SERVICE := &"dot_security_bans"

## The seam dot-server asks. dot-moderation publishes the same name.
const BAN_SOURCE := &"dot_ban_source"

## A fetch finished, for good or ill.
signal fetched(feed_id: StringName, result: DotResult, entries: int)

## The merged list changed.
signal list_changed(total: int)

@export_group("Feeds")

## The endpoints. Any number; each has its own credential and refresh rate.
@export var feeds: Array[DotBanFeed] = []

## JSON file of feeds, layered over [member feeds]. The operator's surface.
@export var feeds_file: String = "user://cfg/ban_feeds.json"

@export_group("Behaviour")

## Fetch every feed as soon as this node is ready.
@export var fetch_on_ready: bool = true

## Also consult whatever was registered as `dot_ban_source` before this node.
##
## Off means this node replaces dot-moderation's enforcement rather than adding
## to it, which is almost never what anybody wants — see the class note.
@export var chain_previous: bool = true

## Tell an admitted-then-banned player why, using the feed's own reason text.
##
## The reason comes from somebody else's list and is shown to the person it is
## about. Off for a deployment whose upstream writes reasons it would not want
## quoted.
@export var show_upstream_reason: bool = true

var index := DotBanIndex.new()

## Whatever held `dot_ban_source` before this node did. Duck-typed; never named.
var previous_source: Object = null

## feed id -> Array of {uid, address, reason}, as last fetched or cached.
var _entries: Dictionary = {}

var _http: DotHttp = null
var _timers: Dictionary = {}
var _last_ok: Dictionary = {}
var _stale: Dictionary = {}
var _fetches: int = 0
var _failures: int = 0


func _ready() -> void:
	if Engine.is_editor_hint():
		return

	_load_feeds_file()

	_http = DotHttp.new()
	_http.name = "BanFeedHttp"
	add_child(_http)

	# Captured BEFORE registering, or this node finds itself and every admission
	# check recurses until the stack gives out.
	var existing := DotRegistry.get_service(BAN_SOURCE)
	if chain_previous and existing != null and existing != self \
			and is_instance_valid(existing) \
			and existing.has_method("check_admission"):
		previous_source = existing
		DotLog.info(
			CHANNEL,
			"chaining to the ban source that was already registered",
			{"was": existing.get_class()}
		)

	DotRegistry.register(SERVICE, self)
	DotRegistry.register(BAN_SOURCE, self)

	for feed in feeds:
		if feed == null or not feed.enabled:
			continue

		var valid := feed.validate()
		if not valid.ok:
			# Named and skipped rather than fatal. One misconfigured feed must
			# not take the other three down, and a server that refuses to boot
			# over a blocklist is a server that is not running at all.
			DotLog.error(
				CHANNEL,
				"ban feed refused",
				{"feed": String(feed.id), "detail": valid.error.message}
			)
			continue

		_load_cache(feed)
		_schedule(feed)

		if fetch_on_ready:
			fetch(feed)

	_rebuild()


func _exit_tree() -> void:
	DotRegistry.unregister_instance(SERVICE, self)
	DotRegistry.unregister_instance(BAN_SOURCE, self)


# --- The seam dot-server asks ----------------------------------------------

## Whether this person may join. The contract behind `dot_ban_source`.
##
## Asked twice per join: once with the address alone before anybody has said who
## they are, and again with both once they have. Both calls come through here.
func check_admission(uid: String, address: String) -> DotResult:
	# Anything still fetching for the first time with REFUSE_ALL set fails
	# closed, which is the whole point of that setting: a deployment that chose
	# it would rather turn people away than admit somebody its list would block.
	for feed in feeds:
		if feed == null or not feed.enabled:
			continue
		if feed.on_failure != DotBanFeed.OnFailure.REFUSE_ALL:
			continue
		if bool(_stale.get(feed.id, true)):
			return DotResult.fail(
				DotError.CODE_STATE,
				"The server cannot check its ban list right now.",
				"feed '%s' is stale and set to refuse" % feed.id
			)

	var reason := ""

	if uid.strip_edges() != "":
		reason = index.reason_for_uid(uid)

	if reason == "" and address.strip_edges() != "":
		reason = index.reason_for_address(address)

	if reason != "":
		return DotResult.fail(
			DotError.CODE_FORBIDDEN,
			"You are banned from this server." if not show_upstream_reason
				else reason,
			"external ban list"
		)

	if previous_source != null and is_instance_valid(previous_source):
		var chained: Variant = previous_source.call("check_admission", uid, address)
		if chained is DotResult:
			return chained as DotResult

	return DotResult.success(true)


# --- Fetching --------------------------------------------------------------

## Fetches one feed now. Safe to call at any time; `sec_bans_refresh` does.
func fetch(feed: DotBanFeed) -> void:
	if feed == null or not feed.enabled:
		return

	_http.timeout_sec = feed.timeout_sec
	_http.max_retries = feed.max_retries
	_http.max_response_bytes = feed.max_bytes

	var res: DotResult = await _http.get_json(
		feed.effective_url(), feed.headers()
	)

	_fetches += 1

	if not res.ok:
		_failures += 1
		_stale[feed.id] = true

		DotLog.warn(
			CHANNEL,
			"could not fetch a ban feed",
			{
				"feed": String(feed.id),
				"detail": res.error.message,
				"policy": ["keep_last", "ignore", "refuse_all"][feed.on_failure],
			}
		)

		if feed.on_failure == DotBanFeed.OnFailure.IGNORE:
			_entries_of(feed).clear()
			_rebuild()

		fetched.emit(feed.id, res, 0)
		return

	var parsed := parse_payload(feed, res.value)

	if not parsed.ok:
		_failures += 1
		_stale[feed.id] = true
		DotLog.warn(
			CHANNEL,
			"a ban feed answered something unreadable",
			{"feed": String(feed.id), "detail": parsed.error.message}
		)
		fetched.emit(feed.id, parsed, 0)
		return

	var entries: Array = parsed.value
	_entries[feed.id] = entries
	_stale[feed.id] = false
	_last_ok[feed.id] = int(Time.get_unix_time_from_system())

	_save_cache(feed, entries)
	_rebuild()

	DotLog.info(
		CHANNEL,
		"ban feed fetched",
		{"feed": String(feed.id), "entries": entries.size()}
	)

	fetched.emit(feed.id, parsed, entries.size())


## Fetches every enabled feed.
func fetch_all() -> void:
	for feed in feeds:
		if feed != null and feed.enabled:
			await fetch(feed)


func _entries_of(feed: DotBanFeed) -> Array:
	if not _entries.has(feed.id):
		_entries[feed.id] = []
	return _entries[feed.id]


# --- Parsing ---------------------------------------------------------------

## Turns whatever a service answered into entries. Static, so it is testable.
##
## [b]Written to accept the shapes services actually use[/b] rather than one this
## family would have chosen: a bare array of strings, an array of objects, an
## object wrapping either at some path, and objects whose id field is called any
## of five things. A blocklist an operator cannot point this at is a blocklist
## they will copy into a file by hand, and then it is stale.
static func parse_payload(feed: DotBanFeed, payload: Variant) -> DotResult:
	var list: Variant = payload

	if feed.list_path.strip_edges() != "":
		for key in feed.list_path.split("."):
			if not (list is Dictionary) or not (list as Dictionary).has(key):
				return DotResult.fail(
					DotError.CODE_PARSE,
					"Feed '%s': nothing at '%s'." % [feed.id, feed.list_path]
				)
			list = (list as Dictionary)[key]

	elif list is Dictionary:
		# No path given. The two conventional shapes are an object with a
		# well-known list key, and an object whose uids and ips are separate.
		var dict: Dictionary = list
		for key in ["bans", "data", "results", "entries", "list", "items"]:
			if dict.has(key):
				list = dict[key]
				break

		if list is Dictionary:
			var built := _from_split_object(list as Dictionary)
			if built != null:
				return DotResult.success(built)

	if not (list is Array):
		return DotResult.fail(
			DotError.CODE_PARSE,
			"Feed '%s' did not answer with a list." % feed.id,
			"set list_path to where the list lives"
		)

	var now := int(Time.get_unix_time_from_system())
	var out: Array = []

	for raw in (list as Array):
		var entry := _entry_from(feed, raw, now)
		if not entry.is_empty():
			out.append(entry)

	return DotResult.success(out)


## `{"uids": [...], "ips": [...]}` and its spellings.
static func _from_split_object(dict: Dictionary) -> Variant:
	var out: Array = []
	var matched := false

	for key in ["uids", "ids", "users", "accounts"]:
		if dict.has(key) and dict[key] is Array:
			matched = true
			for value in (dict[key] as Array):
				out.append({"uid": str(value), "reason": "listed"})

	for key in ["ips", "addresses", "ranges"]:
		if dict.has(key) and dict[key] is Array:
			matched = true
			for value in (dict[key] as Array):
				out.append({"address": str(value), "reason": "listed"})

	return out if matched else null


static func _entry_from(feed: DotBanFeed, raw: Variant, now: int) -> Dictionary:
	if raw is String:
		var text := (raw as String).strip_edges()
		if text == "":
			return {}

		if feed.guess_bare_strings and DotBanIndex.looks_like_address(text):
			return {"address": text, "reason": "listed"}

		return {"uid": text, "reason": "listed"}

	if not (raw is Dictionary):
		return {}

	var dict: Dictionary = raw
	var out := {}

	for field in feed.uid_fields:
		if dict.has(field) and str(dict[field]).strip_edges() != "":
			out["uid"] = str(dict[field]).strip_edges()
			break

	for field in feed.address_fields:
		if dict.has(field) and str(dict[field]).strip_edges() != "":
			out["address"] = str(dict[field]).strip_edges()
			break

	if out.is_empty():
		return {}

	out["reason"] = "listed"
	for field in feed.reason_fields:
		if dict.has(field) and str(dict[field]).strip_edges() != "":
			out["reason"] = str(dict[field]).strip_edges()
			break

	# An expired entry is dropped here rather than enforced until the next
	# fetch. A list that publishes expiries and a consumer that ignores them is
	# how somebody stays banned for a week after their day was up.
	for field in feed.expires_fields:
		if not dict.has(field):
			continue
		var expires := int(dict[field])
		if expires > 0 and expires <= now:
			return {}
		break

	return out


# --- Merging ---------------------------------------------------------------

func _rebuild() -> void:
	index.clear()
	index.feed_count = 0

	for feed in feeds:
		if feed == null or not feed.enabled:
			continue

		var entries: Array = _entries.get(feed.id, [])
		if entries.is_empty():
			continue

		index.feed_count += 1

		for raw in entries:
			var entry: Dictionary = raw
			var reason := "%s: %s" % [feed.id, str(entry.get("reason", "listed"))]

			if entry.has("uid"):
				index.add_uid(str(entry["uid"]), reason)
			if entry.has("address"):
				index.add_address(str(entry["address"]), reason)

	list_changed.emit(index.size())


# --- The disk cache --------------------------------------------------------

func _load_cache(feed: DotBanFeed) -> void:
	if feed.cache_path.strip_edges() == "":
		return
	if not FileAccess.file_exists(feed.cache_path):
		return

	var file := FileAccess.open(feed.cache_path, FileAccess.READ)
	if file == null:
		return

	var text := file.get_as_text()
	file.close()

	var parsed: Variant = JSON.parse_string(text)
	if parsed == null or not (parsed is Array):
		return

	# Loaded but still marked stale: a cache is what was true last time this
	# process could reach the feed, which is not the same as what is true now,
	# and a REFUSE_ALL feed must not be satisfied by it.
	_entries[feed.id] = parsed as Array
	_stale[feed.id] = true

	DotLog.info(
		CHANNEL,
		"ban feed loaded from cache",
		{"feed": String(feed.id), "entries": (parsed as Array).size()}
	)


func _save_cache(feed: DotBanFeed, entries: Array) -> void:
	if feed.cache_path.strip_edges() == "":
		return

	var dir := feed.cache_path.get_base_dir()
	if dir != "" and not DirAccess.dir_exists_absolute(dir):
		DirAccess.make_dir_recursive_absolute(dir)

	var file := FileAccess.open(feed.cache_path, FileAccess.WRITE)
	if file == null:
		return

	file.store_string(JSON.stringify(entries))
	file.close()
	DotWeb.sync_filesystem()


# --- Scheduling ------------------------------------------------------------

func _schedule(feed: DotBanFeed) -> void:
	if feed.refresh_sec <= 0.0:
		return

	var timer := Timer.new()
	timer.name = "Refresh_%s" % feed.id
	timer.wait_time = feed.refresh_sec
	timer.autostart = true
	timer.timeout.connect(func() -> void: fetch(feed))
	add_child(timer)

	_timers[feed.id] = timer


# --- Configuration ---------------------------------------------------------

func _load_feeds_file() -> void:
	if feeds_file.strip_edges() == "" or not FileAccess.file_exists(feeds_file):
		return

	var file := FileAccess.open(feeds_file, FileAccess.READ)
	if file == null:
		return

	var text := file.get_as_text()
	file.close()

	var parsed: Variant = JSON.parse_string(text)
	if parsed == null or not (parsed is Dictionary):
		DotLog.error(CHANNEL, "the ban feeds file is not a JSON object")
		return

	var tree: Dictionary = parsed
	if not tree.has("feeds") or not (tree["feeds"] is Array):
		return

	for raw in (tree["feeds"] as Array):
		if not (raw is Dictionary):
			continue

		var built := DotBanFeed.from_dictionary(raw as Dictionary)
		if not built.ok:
			DotLog.error(
				CHANNEL, "ban feed refused", {"detail": built.error.message}
			)
			continue

		var feed := built.value as DotBanFeed
		var existing := find(feed.id)

		if existing != null:
			feeds[feeds.find(existing)] = feed
		else:
			feeds.append(feed)


func find(id: StringName) -> DotBanFeed:
	for feed in feeds:
		if feed != null and feed.id == id:
			return feed
	return null


# --- Reporting -------------------------------------------------------------

func describe() -> Dictionary:
	var out := index.describe()
	out["fetches"] = _fetches
	out["failures"] = _failures
	out["chained"] = previous_source != null
	return out


func describe_lines() -> PackedStringArray:
	var out := PackedStringArray()
	var d := index.describe()

	out.append("listed      %d accounts, %d addresses, %d ranges" % [
		int(d["uids"]), int(d["addresses"]), int(d["ranges"])
	])
	out.append("fetches     %d (%d failed)" % [_fetches, _failures])
	out.append("chained     %s" % (
		"yes, to an existing ban source" if previous_source != null else "no"
	))

	if feeds.is_empty():
		out.append("feeds       none configured")
		return out

	out.append("")
	for feed in feeds:
		if feed == null:
			continue

		var state := "off"
		if feed.enabled:
			state = "stale" if bool(_stale.get(feed.id, true)) else "ok"

		var last := int(_last_ok.get(feed.id, 0))
		var ago := "never"
		if last > 0:
			ago = "%ds ago" % (int(Time.get_unix_time_from_system()) - last)

		out.append("  %-14s %-5s %-12s %d entries  %s" % [
			feed.id, state, ago,
			(_entries.get(feed.id, []) as Array).size(),
			feed.url,
		])

	return out
