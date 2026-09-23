import json
import os


def _gui_style(port, pid, input_file="a.exe", backend="gui"):
    return {
        "pid": pid,
        "host": "127.0.0.1",
        "port": port,
        "idb_path": f"C:/work/{input_file}.i64",
        "binary": input_file,
        "input_file": input_file,
        "started_at": "2026-08-02T12:00:00Z",
        "backend": backend,
    }


def test_sanitize_prefix_basic(discovery):
    assert discovery.sanitize_prefix("crackme.exe") == "crackme_exe"
    assert discovery.sanitize_prefix("My Library.DLL") == "my_library_dll"
    assert discovery.sanitize_prefix("weird@@file$$name") == "weird_file_name"


def test_from_discovery_maps_gui_shape(discovery):
    inst = discovery.from_discovery(_gui_style(55000, os.getpid()))
    assert inst.id == "port55000"
    assert inst.port == 55000
    assert inst.input_file == "a.exe"
    assert inst.backend == "gui"


def test_from_discovery_falls_back_to_binary(discovery):
    payload = _gui_style(55000, os.getpid(), input_file="a.exe")
    payload["input_file"] = ""
    assert discovery.from_discovery(payload).input_file == "a.exe"


def test_gui_register_bridge_read_roundtrip(tmp_path, monkeypatch, discovery):
    from conftest import _load_module, IDA_MCP_DIR
    gui = _load_module("ida_mcp_gui_discovery_test", IDA_MCP_DIR / "discovery.py")
    monkeypatch.setenv("IDA_MCP_INSTANCE_DIR", str(tmp_path))
    gui.register_instance("127.0.0.1", 55000, os.getpid(), "a.exe",
                          "C:/work/a.exe.i64", backend="gui", input_file="a.exe")
    live = discovery.read_registry_dir(str(tmp_path), probe=False)
    assert len(live) == 1
    assert live[0].id == "port55000"
    assert live[0].input_file == "a.exe"


def test_read_registry_dir_live(tmp_path, discovery):
    (tmp_path / "instance_55000.json").write_text(json.dumps(_gui_style(55000, os.getpid())))
    live = discovery.read_registry_dir(str(tmp_path), probe=False)
    assert len(live) == 1
    assert live[0].id == "port55000"
    assert live[0].input_file == "a.exe"
    assert live[0].port == 55000


def test_read_registry_dir_drops_dead_pid(tmp_path, discovery):
    (tmp_path / "instance_55001.json").write_text(json.dumps(_gui_style(55001, 99999999)))
    assert discovery.read_registry_dir(str(tmp_path), probe=False) == []
    assert not (tmp_path / "instance_55001.json").exists()


def test_read_registry_dir_drops_corrupt(tmp_path, discovery):
    (tmp_path / "instance_55002.json").write_text("{not json")
    assert discovery.read_registry_dir(str(tmp_path), probe=False) == []
    assert not (tmp_path / "instance_55002.json").exists()


def test_read_registry_dir_ignores_foreign_files(tmp_path, discovery):
    (tmp_path / "other.json").write_text(json.dumps(_gui_style(55000, os.getpid())))
    assert discovery.read_registry_dir(str(tmp_path), probe=False) == []
    assert (tmp_path / "other.json").exists()


def test_assign_prefixes_single_no_prefix(discovery):
    a = discovery.InstanceInfo("a", 1, "127.0.0.1", 13337, "i", "crackme.exe", "t")
    mapping = discovery.assign_prefixes([a])
    assert mapping["a"] == ""  # single instance: unprefixed


def test_assign_prefixes_two_prefixed(discovery):
    a = discovery.InstanceInfo("a", 1, "127.0.0.1", 13337, "i", "crackme.exe", "t")
    b = discovery.InstanceInfo("b", 2, "127.0.0.1", 13338, "i", "library.dll", "t")
    mapping = discovery.assign_prefixes([a, b])
    assert mapping["a"] == "crackme_exe__"
    assert mapping["b"] == "library_dll__"


def test_assign_prefixes_collision_disambiguates(discovery):
    a = discovery.InstanceInfo("abcdef-one", 1, "127.0.0.1", 13337, "i", "same.exe", "t")
    b = discovery.InstanceInfo("abcdef-two", 2, "127.0.0.1", 13338, "i", "same.exe", "t")
    mapping = discovery.assign_prefixes([a, b])
    assert mapping["abcdef-one"] != mapping["abcdef-two"]
    assert mapping["abcdef-one"].startswith("same_exe_")
