@tool
class_name DotSecurityConfigBase
extends DotConfig

## Shared `cfg/` file loading for the guard's and the detectors' configs; a subclass supplies [method cfg_keys].

## The addon name [DotAddonConfig] turns into the folder `dot_server_security`.
const CFG_ADDON := "dot-server-security"


## The `security.yml` key -> property map this config reads.
func cfg_keys() -> Dictionary:
	return {}


## Applies this config's keys of [param file_name] from `cfg/addons/dot_server_security/`, then the operator's `cfg/server/addons/dot_server_security/`.
## A flat [param legacy_dir]/[param file_name] is still read (one WARN) while no new copy exists. Other keys are skipped.
func apply_cfg_file(file_name: String = "security.yml", legacy_dir: String = "res://cfg") -> DotResult:
	return DotAddonConfig.apply_file(CFG_ADDON, file_name, legacy_dir, _apply_cfg_values)


func _apply_cfg_values(values: Dictionary, path: String) -> PackedStringArray:
	var keys := cfg_keys()
	var own := {}
	for raw in values:
		if keys.has(String(raw)):
			own[keys[String(raw)]] = values[raw]
	return apply_dictionary(own, path)


## [method apply_cfg_file], then the environment, the command line and validation.
func load_cfg(file_name: String = "security.yml", legacy_dir: String = "res://cfg") -> DotResult:
	unknown_keys = PackedStringArray()
	var file_res := apply_cfg_file(file_name, legacy_dir)
	if not file_res.ok:
		return file_res
	apply_env()
	apply_cli()
	var valid := validate()
	if not valid.ok:
		return valid.wrap("Configuration is invalid.")
	return DotResult.success(self)
