import json
import os


def test_registry_dir_uses_env_override(tmp_path, monkeypatch, registry):
    monkeypatch.setenv(registry.INSTANCE_ENV, str(tmp_path))
    assert registry.registry_dir() == str(tmp_path)


def test_write_and_remove_instance(tmp_path, monkeypatch, registry):
    monkeypatch.setenv(registry.INSTANCE_ENV, str(tmp_path))
    payload = registry.write_instance(
        pid=os.getpid(), host="127.0.0.1", port=13337,
        idb_path="C:/work/crackme.exe.i64", input_file="crackme.exe",
    )
    path = os.path.join(str(tmp_path), f"{payload['id']}.json")
    assert os.path.isfile(path)
    data = json.loads(open(path, encoding="utf-8").read())
    assert data["input_file"] == "crackme.exe"
    assert data["port"] == 13337
    assert data["pid"] == os.getpid()
    registry.remove_instance(payload["id"])
    assert not os.path.exists(path)
