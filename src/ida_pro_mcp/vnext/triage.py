"""Pure (IDA-free) heuristics used by binary triage: import categorization,
string noise filtering/scoring and runtime-stub name detection."""

from __future__ import annotations

import re

IMPORT_CATEGORIES = (
    "anti_debug",
    "dynamic_loading",
    "crypto",
    "network",
    "registry",
    "process",
    "file_io",
)

# Tokens: acronyms (with trailing digits), Capitalized words, lowercase runs, numbers.
_TOKEN_RE = re.compile(r"[A-Z]+[0-9]*(?=[A-Z][a-z]|[^A-Za-z0-9]|$)|[A-Z]?[a-z]+[0-9]*|[A-Z]+[0-9]*|[0-9]+")

_ANTI_DEBUG = {
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "zwqueryinformationprocess", "outputdebugstring", "ntsetinformationthread",
    "zwsetinformationthread", "ptrace", "debugactiveprocess",
}
_DYNAMIC_LOADING = {
    "loadlibrary", "loadlibraryex", "getprocaddress", "ldrloaddll",
    "ldrgetprocedureaddress", "dlopen", "dlsym", "dlmopen",
}
_CRYPTO_TOKENS = {
    "crypt", "encrypt", "decrypt", "cipher", "hash", "hmac", "md5", "sha", "sha1",
    "sha256", "sha512", "aes", "rsa", "ssl", "tls", "evp", "cert",
}
_NETWORK_MODULES = {"ws2_32", "wsock32", "wininet", "winhttp", "urlmon", "dnsapi", "iphlpapi", "libcurl"}
_NETWORK_NAMES = {
    "socket", "connect", "bind", "listen", "accept", "send", "recv", "sendto", "recvfrom",
    "sendmsg", "recvmsg", "select", "closesocket", "getaddrinfo", "freeaddrinfo",
    "gethostbyname", "gethostbyaddr", "inet_addr", "inet_ntoa", "inet_pton", "inet_ntop",
    "htons", "ntohs", "htonl", "ntohl", "ioctlsocket", "setsockopt", "getsockopt",
}
_NETWORK_PREFIXES = ("wsa", "internet", "winhttp", "urldownload", "httpopen", "httpsend", "httpquery", "curl_")
_PROCESS_NAMES = {
    "createprocess", "createprocessasuser", "createprocesswithlogon", "openprocess",
    "terminateprocess", "createremotethread", "createremotethreadex", "createthread",
    "openthread", "suspendthread", "resumethread", "getthreadcontext", "setthreadcontext",
    "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
    "writeprocessmemory", "readprocessmemory", "ntunmapviewofsection", "zwunmapviewofsection",
    "queueuserapc", "setwindowshookex", "createtoolhelp32snapshot", "process32first",
    "process32next", "shellexecute", "shellexecuteex", "winexec", "system", "fork", "vfork",
    "popen", "posix_spawn", "kill",
}
_FILE_TOKENS = {"file", "directory"}
_FILE_NAMES = {
    "fopen", "fdopen", "freopen", "fclose", "fread", "fwrite", "fgets", "fputs", "fseek",
    "ftell", "fflush", "open", "openat", "creat", "unlink", "remove", "rename", "mkdir",
    "rmdir", "opendir", "readdir", "closedir", "stat", "lstat", "fstat", "chmod", "truncate",
}


def api_base_name(name: str) -> str:
    """Strip import decorations: `__imp_`/`.`/`j_` prefixes, `@@GLIBC_x`/`@N` suffixes, A/W suffix."""
    base = name.strip()
    for prefix in ("__imp_", "__imp__", "_imp_", "j_", "."):
        if base.startswith(prefix):
            base = base[len(prefix):]
    base = base.split("@", 1)[0].lstrip("_") or base
    if len(base) > 2 and base[-1] in "AW" and base[-2].islower():
        base = base[:-1]
    return base


def tokenize_api_name(name: str) -> list[str]:
    """Lowercase tokens of an API name split on CamelCase, digits-with-acronyms and `_`."""
    return [t.lower() for t in _TOKEN_RE.findall(api_base_name(name))]


def classify_import(name: str, module: str = "") -> str:
    """Category of an imported API (see IMPORT_CATEGORIES) or 'other'.

    Whole-token / exact-name matching, so `RegisterClassExW` is not registry,
    `SendMessageW` is not network and `GetForegroundWindow` matches nothing.
    """
    base = api_base_name(name)
    lower = base.lower()
    tokens = tokenize_api_name(name)
    mod = module.lower().rsplit(".", 1)[0] if module.lower().endswith((".dll", ".so")) else module.lower()

    if lower in _ANTI_DEBUG:
        return "anti_debug"
    if lower in _DYNAMIC_LOADING:
        return "dynamic_loading"
    if any(t in _CRYPTO_TOKENS for t in tokens):
        return "crypto"
    if mod in _NETWORK_MODULES or lower in _NETWORK_NAMES or lower.startswith(_NETWORK_PREFIXES):
        return "network"
    if "reg" in tokens:  # RegOpenKeyEx, SHRegGetValue; Register* tokenizes as 'register'
        return "registry"
    if lower in _PROCESS_NAMES or lower.startswith(("exec", "posix_spawn")):
        return "process"
    if lower in _FILE_NAMES or any(t in _FILE_TOKENS for t in tokens):
        return "file_io"
    return "other"


# Loader / symbol-version / toolchain strings that are never interesting.
_LOADER_STRING_RE = re.compile(
    r"^(?:(?:GLIBC|GLIBCXX|CXXABI|GCC|LIBC)_[\d.A-Z_]+"
    r"|/lib(?:32|64)?/ld-.*|ld-linux.*\.so.*|lib[\w+\-.]*\.so(?:\.\d+)*"
    r"|__gmon_start__|_ITM_\w+|__cxa_\w+|__libc_\w+|_Jv_RegisterClasses"
    r"|GCC: \(.*|\.(?:interp|dynstr|dynsym|text|data|bss|rodata|rdata|idata|pdata|reloc|rsrc)\b.*)$"
)
_URL_RE = re.compile(r"\b(?:https?|ftp|wss?)://", re.IGNORECASE)
_PATH_RE = re.compile(r"^(?:[A-Za-z]:\\|\\\\|/(?:etc|tmp|proc|dev|home|usr|var|bin)/|%\w+%\\)")
_REGISTRY_RE = re.compile(r"^(?:HKEY_|HKLM\\|HKCU\\|SOFTWARE\\|Software\\|SYSTEM\\)")
_FORMAT_RE = re.compile(r"%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|z|I64)?[sdiuxXpcfn]")
_MESSAGE_RE = re.compile(
    r"\b(?:error|fail(?:ed|ure)?|invalid|denied|wrong|correct|success(?:ful)?|password|"
    r"usage|cannot|unable|key|license|debug)\b",
    re.IGNORECASE,
)


def is_loader_string(text: str, import_names: set[str] | frozenset[str] = frozenset()) -> bool:
    """Loader/import-table noise: GLIBC versions, ld.so paths, lib*.so, or a name in
    `import_names` (lowercased import/module names)."""
    s = text.strip()
    return bool(_LOADER_STRING_RE.match(s)) or s.lower() in import_names


def string_kind(text: str) -> str | None:
    """Informative-string tag: url, registry, path, format, message, or None."""
    if _URL_RE.search(text):
        return "url"
    if _REGISTRY_RE.match(text):
        return "registry"
    if _PATH_RE.match(text):
        return "path"
    if _FORMAT_RE.search(text):
        return "format"
    if _MESSAGE_RE.search(text):
        return "message"
    return None


def is_junk_string(text: str) -> bool:
    """Byte soup mis-detected as text (e.g. code bytes like 'D9t$8').

    Junk when: fewer than 4 non-space chars; or, unless it looks like a
    url/path/registry/format/message, under 60% alphanumeric/space or short
    (<10 chars), single-word and vowel-free.
    """
    s = text.strip()
    if len(s) < 4:
        return True
    if string_kind(s):
        return False
    good = sum(1 for c in s if c.isalnum() or c == " ")
    if good / len(s) < 0.6:
        return True
    return len(s) < 10 and " " not in s and not any(c in "aeiouyAEIOUY" for c in s)


def string_score(text: str, code_refs: int) -> int:
    """Rank: code references dominate (capped), informative kinds and multi-word text add."""
    score = 4 * min(code_refs, 5)
    if string_kind(text):
        score += 5
    if " " in text.strip():
        score += 2
    return score


# Compiler/CRT/runtime helpers that dominate naive xref ranking.
_RUNTIME_NAME_RE = re.compile(
    r"^(?:_start|start|_init|_fini|frame_dummy|register_tm_clones|deregister_tm_clones"
    r"|__do_global_(?:c|d)tors_aux|__libc_csu_\w+|_?_?(?:mem|str|wcs)(?:set|cpy|move|cmp|len|chr|ncpy|ncmp|cat)"
    r"|__security_\w+|__scrt_\w+|__acrt_\w+|__vcrt_\w+|__GSHandler\w*|_guard_\w+|__guard_\w+"
    r"|__report_\w+|__raise_securityfailure|_RTC_\w+|_CRT_\w+|__C_specific_handler"
    r"|__CxxFrameHandler\w*|__delayLoadHelper\w*|_?_?tailMerge\w*|__chkstk|_alloca_probe\w*"
    r"|\w*WARBIRD\w*|wil::.*|Microsoft::WRL::.*|std::.*|_?_?stack_chk_fail)$"
)


def is_runtime_function_name(name: str) -> bool:
    """True for CRT/compiler/WIL/WARBIRD helper names that are never triage targets."""
    return bool(_RUNTIME_NAME_RE.match(name))

