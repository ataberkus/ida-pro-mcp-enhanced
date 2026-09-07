import json
import os


def test_sanitize_prefix_basic(discovery):
    assert discovery.sanitize_prefix("crackme.exe") == "crackme_exe"
    assert discovery.sanitize_prefix("My Library.DLL") == "my_library_dll"
    assert discovery.sanitize_prefix("weird@@file$$name") == "weird_file_name"


def test_read_registry_dir_live(tmp_path, discovery):
    inst = {
        "id": "pid1234-a1b2c3",
        "pid": os.getpid(),  # current process is definitely alive
        "host": "127.0.0.1",
        "port": 13337,
        "session_id": "s",
        "idb_path": "C:/work/crackme.exe.i64",
        "input_file": "crackme.exe",
        "started_at": "2026-08-02T12:00:00Z",
    }
    (tmp_path / f"{inst['id']}.json").write_text(json.dumps(inst))
    live = discovery.read_registry_dir(str(tmp_path), probe=False)
    assert len(live) == 1
    assert live[0].input_file == "crackme.exe"
    assert live[0].port == 13337


def test_read_registry_dir_drops_dead_pid(tmp_path, discovery):
    inst = {
        "id": "dead", "pid": 99999999, "host": "127.0.0.1", "port": 13337,
        "session_id": "s", "idb_path": "x", "input_file": "x.exe",
        "started_at": "2026-08-02T12:00:00Z",
    }
    (tmp_path / "dead.json").write_text(json.dumps(inst))
    assert discovery.read_registry_dir(str(tmp_path), probe=False) == []


def test_assign_prefixes_single_no_prefix(discovery):
    a = discovery.InstanceInfo("a", 1, "127.0.0.1", 13337, "s", "i", "crackme.exe", "t")
    mapping = discovery.assign_prefixes([a])
    assert mapping["a"] == ""  # single instance: unprefixed


def test_assign_prefixes_two_prefixed(discovery):
    a = discovery.InstanceInfo("a", 1, "127.0.0.1", 13337, "s", "i", "crackme.exe", "t")
    b = discovery.InstanceInfo("b", 2, "127.0.0.1", 13338, "s", "i", "library.dll", "t")
    mapping = discovery.assign_prefixes([a, b])
    assert mapping["a"] == "crackme_exe__"
    assert mapping["b"] == "library_dll__"


def test_assign_prefixes_collision_disambiguates(discovery):
    a = discovery.InstanceInfo("abcdef-one", 1, "127.0.0.1", 13337, "s", "i", "same.exe", "t")
    b = discovery.InstanceInfo("abcdef-two", 2, "127.0.0.1", 13338, "s", "i", "same.exe", "t")
    mapping = discovery.assign_prefixes([a, b])
    assert mapping["abcdef-one"] != mapping["abcdef-two"]
    assert mapping["abcdef-one"].startswith("same_exe_")
