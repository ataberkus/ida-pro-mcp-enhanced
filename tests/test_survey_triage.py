from __future__ import annotations

import pytest

from ida_pro_mcp.vnext.triage import (
    classify_import,
    is_junk_string,
    is_loader_string,
    is_runtime_function_name,
    tokenize_api_name,
)


@pytest.mark.parametrize(
    ("name", "module", "category"),
    [
        ("GetForegroundWindow", "", "other"),
        ("RegisterClassExW", "USER32", "other"),
        ("SendMessageW", "USER32", "other"),
        ("SendDlgItemMessageW", "USER32", "other"),
        ("SHAddToRecentDocs", "SHELL32", "other"),
        ("CoCreateFreeThreadedMarshaler", "ole32", "other"),
        ("RegOpenKeyExW", "ADVAPI32", "registry"),
        ("send", "", "network"),
        ("recv@@GLIBC_2.2.5", "", "network"),
        ("Ordinal_23", "WS2_32.dll", "network"),
        ("InternetOpenUrlA", "", "network"),
        ("CryptEncrypt", "", "crypto"),
        ("BCryptOpenAlgorithmProvider", "", "crypto"),
        ("MD5_Update", "", "crypto"),
        ("IsDebuggerPresent", "", "anti_debug"),
        ("LoadLibraryExW", "", "dynamic_loading"),
        ("CreateRemoteThread", "", "process"),
        ("CreateFileW", "", "file_io"),
        ("fopen", "", "file_io"),
        ("printf", "", "other"),
    ],
)
def test_classify_import_matches_whole_tokens(name, module, category):
    assert classify_import(name, module) == category


def test_tokenize_strips_decorations():
    assert tokenize_api_name("__imp_RegOpenKeyExW") == ["reg", "open", "key", "ex"]
    assert tokenize_api_name("SHA256_Init") == ["sha256", "init"]
    assert tokenize_api_name(".puts@@GLIBC_2.2.5") == ["puts"]


def test_string_filters():
    for junk in ("D9t$8", "fD9#t\nH", "abc", "@@@@@@a"):
        assert is_junk_string(junk), junk
    for good in ("Yes, %s is correct!\n", "%s:%d", "Notepad", "C:\\Windows\\x"):
        assert not is_junk_string(good), good
    for loader in ("GLIBC_2.4", "/lib64/ld-linux-x86-64.so.2", "libc.so.6", "__libc_start_main"):
        assert is_loader_string(loader), loader
    assert is_loader_string("KERNEL32.dll", {"kernel32.dll"})
    assert not is_loader_string("Yes, %s is correct!")


def test_runtime_function_names():
    for name in ("__security_check_cookie", "frame_dummy", "_start", "wil::details::foo", "memset"):
        assert is_runtime_function_name(name), name
    for name in ("main", "check_pw", "WinMain", "strange_parser"):
        assert not is_runtime_function_name(name), name
