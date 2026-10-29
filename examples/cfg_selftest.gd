extends Node

## The yml layout of dot-server-security's settings: new path, flat shim, operator layer.
## Run: timeout 120 godot --headless --path . res://examples/cfg_selftest.tscn

const FOLDER := "dot_server_security"
const FILE := "security.yml"
const LEGACY := "user://dot_server_security_cfg_selftest_legacy"

var _passed := 0
var _failed := 0


func _ready() -> void:
	DotLog.set_level(DotLog.Level.ERROR)
	_run.call_deferred()


func _run() -> void:
	print("dot-server-security cfg self-test")
	var addon_dir := "user://cfg/addons/" + FOLDER
	var server_dir := "user://cfg/server/addons/" + FOLDER
	_clean(addon_dir, server_dir)
	DotCfgLegacy.reset()

	_write(LEGACY.path_join(FILE), "sec_ledger_size: 32\n")
	var config := DotSecurityConfig.new()
	var res := config.load_cfg(FILE, LEGACY)
	_check(res.ok and config.ledger_size == 32, "only the flat file: it is still read")
	_check(DotCfgLegacy.warned_count() == 1, "and warned once")
	DotSecurityConfig.new().load_cfg(FILE, LEGACY)
	_check(DotCfgLegacy.warned_count() == 1, "a second load does not warn again")

	_write(addon_dir.path_join(FILE), "sec_ledger_size: 128\nsome_deployment_key: 1\n")
	config = DotSecurityConfig.new()
	res = config.load_cfg(FILE, LEGACY)
	_check(res.ok and config.ledger_size == 128, "the new path wins over the flat file")
	_check(config.unknown_keys.is_empty(), "and a key of the deployment's is skipped, not reported")

	_write(server_dir.path_join(FILE), "sec_ledger_size: 256\n")
	config = DotSecurityConfig.new()
	res = config.load_cfg(FILE, LEGACY)
	_check(res.ok and config.ledger_size == 256, "the operator's server layer wins")

	_write(server_dir.path_join(FILE), "sec_ledger_size: [broken\n")
	_check(not DotSecurityConfig.new().load_cfg(FILE, LEGACY).ok, "a bad file fails")

	_write(server_dir.path_join(FILE), "ac_max_speed: 30\nsec_ledger_size: 64\n")
	var ac := DotAntiCheatConfig.new()
	res = ac.load_cfg(FILE, LEGACY)
	_check(res.ok and ac.max_horizontal_speed == 30.0, "the detectors read their ac_ keys from the same file")

	_clean(addon_dir, server_dir)
	DotCfgLegacy.reset()
	print("%d passed, %d failed" % [_passed, _failed])
	get_tree().quit(1 if _failed > 0 else 0)


func _clean(addon_dir: String, server_dir: String) -> void:
	DotPaths.remove_tree(addon_dir)
	DotPaths.remove_tree(server_dir)
	DotPaths.remove_tree(LEGACY)


func _write(path: String, text: String) -> void:
	DirAccess.make_dir_recursive_absolute(path.get_base_dir())
	var f := FileAccess.open(path, FileAccess.WRITE)
	f.store_string(text)
	f.close()


func _check(condition: bool, what: String) -> void:
	if condition:
		_passed += 1
		print("   ok   ", what)
	else:
		_failed += 1
		print("  FAIL  ", what)
