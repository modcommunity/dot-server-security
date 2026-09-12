@tool
extends EditorPlugin

## Editor entry point for dot-server-security. Registers inspector types only.
##
## No autoloads: a project may run a server and a client in one process, and two
## servers in one editor session, and a singleton would make both impossible. The
## host places the nodes and points them at a server with a [DotNodeRef].

const _ICON := "res://addons/dot_server_security/icon_placeholder.svg"

const _TYPES := [
	["DotSecurityManager", "Node",
		"res://addons/dot_server_security/runtime/dot_security_manager.gd"],
	["DotSecurityWatch", "Node",
		"res://addons/dot_server_security/watch/dot_security_watch.gd"],
	["DotBanFeeds", "Node",
		"res://addons/dot_server_security/banlist/dot_ban_feeds.gd"],
	["DotAntiCheat", "Node",
		"res://addons/dot_server_security/anticheat/dot_anticheat.gd"],
]


func _enter_tree() -> void:
	var icon: Texture2D = null
	if ResourceLoader.exists(_ICON):
		icon = load(_ICON) as Texture2D

	for entry in _TYPES:
		add_custom_type(entry[0], entry[1], load(entry[2]), icon)


func _exit_tree() -> void:
	# Reversed so a type is never removed before something that referenced it,
	# which matters when the editor reloads the plugin.
	for i in range(_TYPES.size() - 1, -1, -1):
		remove_custom_type(_TYPES[i][0])
