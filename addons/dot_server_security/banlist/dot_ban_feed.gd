@tool
class_name DotBanFeed
extends Resource

## One external list of people who may not play here.
##
## A community with eight servers, a partner network, or a shared blocklist wants
## one list, fetched rather than copied. This is one endpoint of that: where it
## is, how to prove you may read it, how to find the identifiers in whatever it
## answers with, and what to do when it is down.
##
## [b]Several feeds are the normal case, not the advanced one.[/b] A network's own
## list, a partner's, and a public one have different owners, different trust and
## different refresh rates, and merging them by hand into one file is how they
## drift. [DotBanFeeds] holds any number.
##
## [codeblock]
## var feed := DotBanFeed.new()
## feed.id = &"network"
## feed.url = "https://bans.example.org/v1/active"
## feed.auth = DotBanFeed.Auth.BEARER
## feed.token_file = "user://cfg/bans.token"    # not the token itself
## [/codeblock]

enum Auth {
	## A public list. No credential is sent.
	NONE = 0,
	## `Authorization: Bearer <token>`. Covers a static API key and a JWT alike —
	## a JWT is a bearer token whose contents the server happens to be able to
	## read, and nothing on this side needs to.
	BEARER = 1,
	## `Authorization: Basic base64(user:password)`.
	BASIC = 2,
	## An arbitrary header, for an API that wants `X-Api-Key` or similar.
	HEADER = 3,
	## A query parameter appended to the URL.
	##
	## [b]Supported and discouraged.[/b] A credential in a URL is a credential in
	## every proxy log, every crash report and every browser history between here
	## and there. It is here because some services offer nothing else.
	QUERY = 4,
	## A timestamp, a nonce and an HMAC over both, in headers.
	##
	## The shape the backbone's integration requests already use, so a site
	## verifying both needs one implementation. Nothing replayable is sent, which
	## is what makes it the right choice over a bearer token on an endpoint whose
	## traffic somebody else can see.
	HMAC = 5,
}

enum OnFailure {
	## Keep whatever was last fetched, or the disk cache, and carry on.
	##
	## [b]The default, and it is a real choice rather than an easy one.[/b] A feed
	## that is down should not empty the ban list, and it should not close the
	## server either — an operator whose blocklist provider has an outage would
	## rather admit a few banned people than nobody at all. A deployment where
	## that trade goes the other way sets REFUSE_ALL.
	KEEP_LAST = 0,
	## Treat the list as empty. Admits everybody this feed would have refused.
	IGNORE = 1,
	## Refuse every admission while this feed is stale. Fails closed.
	REFUSE_ALL = 2,
}

## Identifier, used in logs, in `sec_bans` and to disable one feed.
@export var id: StringName = &""

## Off entirely.
@export var enabled: bool = true

@export_group("Endpoint")

## Where to fetch. Must be HTTPS unless [member allow_insecure] is set.
@export var url: String = ""

## Allow plain HTTP.
##
## A ban list over HTTP is a ban list anybody on the path can rewrite, and the
## interesting rewrite is the empty one — which fails open and silently. Off.
@export var allow_insecure: bool = false

## Seconds between fetches. 0 fetches once at boot and never again.
@export_range(0.0, 86400.0, 1.0) var refresh_sec: float = 300.0

@export_range(1.0, 120.0, 1.0) var timeout_sec: float = 20.0

@export_range(0, 10, 1) var max_retries: int = 2

@export_group("Authentication")

@export var auth: Auth = Auth.NONE

## The credential. [b]Refused from the environment and the command line.[/b]
##
## Both are readable by other processes on the box and both end up in `ps` output
## and in pasted bug reports. Use [member token_file], which is the layer this
## family already treats as safe for a secret.
@export var token: String = ""

## A file holding the credential, read at boot. Preferred over [member token].
@export var token_file: String = ""

## Username, for [constant Auth.BASIC].
@export var username: String = ""

## Header name, for [constant Auth.HEADER].
@export var header_name: String = "X-Api-Key"

## Query parameter name, for [constant Auth.QUERY].
@export var query_name: String = "key"

@export_group("Parsing")

## Where the list lives in the response, as dot-separated keys.
##
## Empty treats the whole document as the list. `data.bans` reaches
## `{"data": {"bans": [...]}}`, which is what most REST APIs actually answer.
@export var list_path: String = ""

## Field holding an account id, when entries are objects.
##
## Several are tried in order, because no two services agree: the first one
## present on an entry wins.
@export var uid_fields: PackedStringArray = PackedStringArray([
	"uid", "id", "user_id", "player_id", "account"
])

## Field holding an address, when entries are objects.
@export var address_fields: PackedStringArray = PackedStringArray([
	"ip", "address", "ip_address"
])

## Field holding a reason, when entries are objects.
@export var reason_fields: PackedStringArray = PackedStringArray([
	"reason", "note", "comment"
])

## Field holding a unix expiry, when entries are objects. Past entries are dropped.
@export var expires_fields: PackedStringArray = PackedStringArray([
	"expires", "expires_at", "until"
])

## Treat a bare string entry as an address when it looks like one.
##
## A list of bare strings is the commonest shape there is and it says nothing
## about what its entries are. Anything parsing as an address or a CIDR range is
## taken as one; everything else is an account id.
@export var guess_bare_strings: bool = true

@export_group("Behaviour")

@export var on_failure: OnFailure = OnFailure.KEEP_LAST

## Cache the last good fetch here, so a restart during an outage still enforces.
##
## [b]The setting that makes KEEP_LAST mean anything across a restart.[/b] Without
## it, a server rebooted while the feed is down comes up with an empty list.
@export var cache_path: String = ""

## Refuse a response larger than this, in bytes. 0 is no limit.
@export_range(0, 268435456, 1024) var max_bytes: int = 16777216


static func of(p_id: StringName, p_url: String) -> DotBanFeed:
	var feed := DotBanFeed.new()
	feed.id = p_id
	feed.url = p_url
	feed.cache_path = "user://cache/banfeed_%s.json" % p_id
	return feed


# --- Requests --------------------------------------------------------------

## The credential in force: the file if there is one, else the inline value.
func effective_token() -> String:
	if token_file.strip_edges() != "" and FileAccess.file_exists(token_file):
		var file := FileAccess.open(token_file, FileAccess.READ)
		if file != null:
			var text := file.get_as_text().strip_edges()
			file.close()
			return text
	return token


## The URL to fetch, with a query credential appended when that is the mode.
func effective_url() -> String:
	if auth != Auth.QUERY:
		return url

	var credential := effective_token()
	if credential == "":
		return url

	var joiner := "&" if url.contains("?") else "?"
	return "%s%s%s=%s" % [
		url, joiner, query_name.uri_encode(), credential.uri_encode()
	]


## Headers for one request, credential included.
func headers() -> Dictionary:
	var out := {"Accept": "application/json"}
	var credential := effective_token()

	match auth:
		Auth.BEARER:
			if credential != "":
				out["Authorization"] = "Bearer " + credential

		Auth.BASIC:
			if credential != "":
				out["Authorization"] = "Basic " + Marshalls.utf8_to_base64(
					"%s:%s" % [username, credential]
				)

		Auth.HEADER:
			if credential != "" and header_name.strip_edges() != "":
				out[header_name] = credential

		Auth.HMAC:
			if credential != "":
				var ts := int(Time.get_unix_time_from_system())
				var nonce := DotHash.random_hex(8)
				# Signed over timestamp, nonce and the path, so a signature
				# captured from one request cannot be replayed against another.
				var payload := "%d.%s.%s" % [ts, nonce, url]
				out["X-Dot-Timestamp"] = str(ts)
				out["X-Dot-Nonce"] = nonce
				out["X-Dot-Signature"] = DotHash.hmac_sha256_hex(
					credential, payload
				)

	return out


# --- Validation ------------------------------------------------------------

func validate() -> DotResult:
	if String(id).strip_edges() == "":
		return DotResult.fail(DotError.CODE_INVALID, "A ban feed needs an id.")

	if url.strip_edges() == "":
		return DotResult.fail(
			DotError.CODE_INVALID, "Feed '%s' has no url." % id
		)

	if url.begins_with("http://") and not allow_insecure:
		return DotResult.fail(
			DotError.CODE_INVALID,
			"Feed '%s' is plain HTTP." % id,
			"a ban list over HTTP is one anybody on the path can rewrite, and "
			+ "the interesting rewrite is the empty one; set allow_insecure "
			+ "only on a trusted network"
		)

	if not url.begins_with("http://") and not url.begins_with("https://"):
		return DotResult.fail(
			DotError.CODE_INVALID, "Feed '%s' has no scheme." % id
		)

	if auth != Auth.NONE and effective_token() == "":
		# Named at boot rather than left to fail on the first fetch, which on a
		# five-minute refresh is five minutes of an unguarded server.
		return DotResult.fail(
			DotError.CODE_AUTH,
			"Feed '%s' needs a credential and has none." % id,
			"set token_file"
		)

	return DotResult.success(self)


static func sensitive_keys() -> PackedStringArray:
	return PackedStringArray(["token"])


func describe() -> String:
	return "%s %s (%s, every %.0fs)" % [
		id, url, auth_name(auth), refresh_sec
	]


static func auth_name(mode: int) -> String:
	match mode:
		Auth.NONE: return "public"
		Auth.BEARER: return "bearer"
		Auth.BASIC: return "basic"
		Auth.HEADER: return "header"
		Auth.QUERY: return "query"
		Auth.HMAC: return "hmac"
	return "unknown"


static func parse_auth(text: String) -> int:
	match text.strip_edges().to_lower():
		"none", "public", "": return Auth.NONE
		"bearer", "token", "jwt": return Auth.BEARER
		"basic": return Auth.BASIC
		"header": return Auth.HEADER
		"query": return Auth.QUERY
		"hmac", "signed": return Auth.HMAC
	return -1


static func parse_failure(text: String) -> int:
	match text.strip_edges().to_lower():
		"keep_last", "keep", "last": return OnFailure.KEEP_LAST
		"ignore", "open", "fail_open": return OnFailure.IGNORE
		"refuse_all", "closed", "fail_closed": return OnFailure.REFUSE_ALL
	return -1


static func from_dictionary(raw: Dictionary) -> DotResult:
	var feed := DotBanFeed.new()

	feed.id = StringName(str(raw.get("id", "")))
	feed.url = str(raw.get("url", ""))
	feed.enabled = bool(raw.get("enabled", true))
	feed.allow_insecure = bool(raw.get("allow_insecure", false))
	feed.refresh_sec = float(raw.get("refresh_sec", 300.0))
	feed.timeout_sec = float(raw.get("timeout_sec", 20.0))
	feed.max_retries = int(raw.get("max_retries", 2))
	feed.token = str(raw.get("token", ""))
	feed.token_file = str(raw.get("token_file", ""))
	feed.username = str(raw.get("username", ""))
	feed.header_name = str(raw.get("header_name", "X-Api-Key"))
	feed.query_name = str(raw.get("query_name", "key"))
	feed.list_path = str(raw.get("list_path", ""))
	feed.guess_bare_strings = bool(raw.get("guess_bare_strings", true))
	feed.max_bytes = int(raw.get("max_bytes", 16777216))

	feed.cache_path = str(raw.get(
		"cache_path", "user://cache/banfeed_%s.json" % feed.id
	))

	if raw.has("auth"):
		var mode := parse_auth(str(raw["auth"]))
		if mode < 0:
			return DotResult.fail(
				DotError.CODE_INVALID,
				"'%s' is not an auth mode." % str(raw["auth"]),
				"try none, bearer, basic, header, query or hmac"
			)
		feed.auth = mode as Auth

	if raw.has("on_failure"):
		var mode2 := parse_failure(str(raw["on_failure"]))
		if mode2 < 0:
			return DotResult.fail(
				DotError.CODE_INVALID,
				"'%s' is not a failure policy." % str(raw["on_failure"]),
				"try keep_last, ignore or refuse_all"
			)
		feed.on_failure = mode2 as OnFailure

	for key in ["uid_fields", "address_fields", "reason_fields", "expires_fields"]:
		if not raw.has(key):
			continue
		var value: Variant = raw[key]
		if value is Array:
			var out := PackedStringArray()
			for entry in (value as Array):
				out.append(str(entry))
			feed.set(key, out)

	return feed.validate()


func to_dictionary(redact: bool = true) -> Dictionary:
	return {
		"id": String(id),
		"enabled": enabled,
		"url": url,
		"auth": auth_name(auth),
		"token": "***" if redact and token != "" else token,
		"token_file": token_file,
		"refresh_sec": refresh_sec,
		"on_failure": ["keep_last", "ignore", "refuse_all"][on_failure],
		"list_path": list_path,
		"cache_path": cache_path,
	}
