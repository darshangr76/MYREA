from __future__ import annotations
from .models import SectionInfo, ImportInfo


# Known "interesting" APIs — presence is not proof of malice,
# just a signal worth surfacing during triage.
SUSPICIOUS_APIS = {
    # memory / injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
    "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection",
    # execution / loading
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll",
    "ShellExecuteA", "ShellExecuteW", "WinExec", "CreateProcessA", "CreateProcessW",
    # persistence
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
    "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW",
    # anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW",
    "GetTickCount", "QueryPerformanceCounter",
    # crypto / encoding
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA",
    "CryptAcquireContextW",
    # networking
    "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
    "HttpSendRequestA", "HttpSendRequestW", "URLDownloadToFileA", "URLDownloadToFileW",
    "WSAStartup", "socket", "connect", "send", "recv",
    "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
}

# Common in nearly every Windows program — only interesting in combination
# with a real signal above, or when paired (e.g. LoadLibrary+GetProcAddress).
WEAK_SIGNAL_APIS = {
    "GetTickCount", "QueryPerformanceCounter", "IsDebuggerPresent",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "CreateProcessA", "CreateProcessW",
}

# Section names Windows/legit compilers typically emit. Anything else
# (e.g. UPX0, .aspack, .themida) is worth flagging.
COMMON_SECTION_NAMES = {
    ".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc",
    ".bss", ".idata", ".edata", ".tls", ".CRT", ".debug",
    "CODE", "DATA", ".itext",
}


def check_imports(imports: list[ImportInfo]) -> list[str]:
    hits = []
    for imp in imports:
        if imp.function in WEAK_SIGNAL_APIS:
            hits.append(f"[weak] {imp.library}!{imp.function}")
        elif imp.function in SUSPICIOUS_APIS:
            hits.append(f"[strong] {imp.library}!{imp.function}")
    return hits


def check_sections(sections: list[SectionInfo]) -> list[str]:
    findings = []
    for sec in sections:
        if sec.is_executable and sec.is_writable:
            findings.append(f"RWX section: {sec.name}")
        if sec.entropy > 7.0:
            findings.append(f"High entropy ({sec.entropy:.3f}): {sec.name} (possible packing/encryption)")
        if sec.name not in COMMON_SECTION_NAMES and sec.name.strip("\x00"):
            findings.append(f"Non-standard section name: {sec.name!r}")
    return findings


def run_heuristics(sections, imports) -> list[str]:
    return check_sections(sections) + check_imports(imports)
