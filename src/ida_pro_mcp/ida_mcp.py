"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import sys
import idaapi
import ida_kernwin
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


CONFIG_ACTION_ID = "mcp:configure"
CONFIG_ACTION_LABEL = "MCP Configuration"


class MCPConfigForm(idaapi.Form):
    """Form to configure MCP server host and port."""

    def __init__(self, host: str, port: int):
        form_str = r"""STARTITEM 0
MCP Server Configuration

<Host:{host}>
<Port:{port}>
"""
        super().__init__(
            form_str,
            {
                "host": idaapi.Form.StringInput(value=host),
                "port": idaapi.Form.NumericInput(value=port, tp=idaapi.Form.FT_DEC),
            },
        )


class MCPConfigHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        form = MCPConfigForm(self.plugin.host, self.plugin.port)
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return 0

        host = form.host.value
        port = form.port.value
        form.Free()

        if port < 1 or port > 65535:
            print(f"[MCP] Invalid port: {port}")
            return 0

        self.plugin.host = host
        self.plugin.port = port
        print(f"[MCP] Configuration updated: {host}:{port}")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCPUIHooks(ida_kernwin.UI_Hooks):
    """Defers menu attachment until the UI is fully ready."""

    def ready_to_run(self):
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", CONFIG_ACTION_ID, idaapi.SETMENU_APP
        )
        self.unhook()


class MCPAutoStartHooks(ida_kernwin.UI_Hooks):
    """Starts the MCP server once IDA has finished loading a database."""

    def __init__(self, plugin: "MCP"):
        super().__init__()
        self.plugin = plugin

    def ready_to_run(self):
        # IDA finished initial UI + DB load; start the server once.
        if self.plugin.mcp is None:
            self.plugin.run(0)
        self.unhook()


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 13337

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self._instance = None
        self._bound_port = None
        self.host = self.DEFAULT_HOST
        self.port = self.DEFAULT_PORT
        self._autostart = MCPAutoStartHooks(self)
        self._autostart.hook()

        # Register a separate menu item for host/port configuration
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CONFIG_ACTION_ID,
                CONFIG_ACTION_LABEL,
                MCPConfigHandler(self),
            )
        )
        # Defer menu attachment until the UI is fully initialized
        self._ui_hooks = MCPUIHooks()
        self._ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self.mcp:
            self.mcp.stop()
            self.mcp = None
            self._unregister_instance()

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        port = self.port
        max_port = port + 100
        while port < max_port:
            try:
                bound = MCP_SERVER.serve(
                    self.host, port, request_handler=IdaMcpHttpRequestHandler
                )
                actual = int(bound) if bound else port
                print(f"  Config: http://{self.host}:{actual}/config.html")
                self.mcp = MCP_SERVER
                self._bound_port = actual
                self._register_instance(actual)
                return
            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    port += 1
                else:
                    raise
        print(f"[MCP] Error: No available port in range {self.port}-{max_port - 1}")

    def _register_instance(self, port: int) -> None:
        try:
            import os
            import ida_nalt
            import ida_loader
            from ida_mcp.registry import write_instance

            idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
            input_file = ida_nalt.get_root_filename() or ""
            self._instance = write_instance(
                pid=os.getpid(),
                host=self.host,
                port=port,
                idb_path=idb_path,
                input_file=input_file,
            )
            print(f"[MCP] Registered instance {self._instance['id']} ({input_file})")
        except Exception as e:
            print(f"[MCP] Instance registration failed: {e}")
            self._instance = None

    def _unregister_instance(self) -> None:
        inst = getattr(self, "_instance", None)
        if not inst:
            return
        try:
            from ida_mcp.registry import remove_instance

            remove_instance(inst["id"])
        except Exception as e:
            print(f"[MCP] Instance unregistration failed: {e}")
        self._instance = None

    def term(self):
        if hasattr(self, "_autostart"):
            self._autostart.unhook()
        if hasattr(self, "_ui_hooks"):
            self._ui_hooks.unhook()
        ida_kernwin.unregister_action(CONFIG_ACTION_ID)
        if self.mcp:
            self.mcp.stop()
        self._unregister_instance()


def PLUGIN_ENTRY():
    return MCP()


