rule Process_Injection_Combo {
    meta:
        description = "API string combo commonly used for process injection"
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
    condition:
        all of them
}

rule Command_Execution_Chain {
    meta:
        description = "References to cmd/powershell with an encoded command indicator"
    strings:
        $cmd = "cmd.exe" ascii nocase
        $ps = "powershell" ascii nocase
        $enc = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ ascii nocase
    condition:
        ($cmd or $ps) and $enc
}

rule Download_And_Execute {
    meta:
        description = "URLDownloadToFile combined with a shell exec API"
    strings:
        $dl = "URLDownloadToFile" ascii
        $se = "ShellExecute" ascii
        $we = "WinExec" ascii
    condition:
        $dl and ($se or $we)
}

rule Registry_Persistence {
    meta:
        description = "Registry persistence key strings"
    strings:
        $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii nocase
    condition:
        any of them
}

rule Anti_Debug_Combo {
    meta:
        description = "Common anti-debugging API strings together"
    strings:
        $a = "IsDebuggerPresent" ascii
        $b = "CheckRemoteDebuggerPresent" ascii
        $c = "NtQueryInformationProcess" ascii
    condition:
        2 of them
}

rule Ransomware_Indicators {
    meta:
        description = "Strings strongly associated with ransomware"
    strings:
        $ext1 = ".locked" ascii
        $ext2 = ".crypto" ascii
        $ext3 = ".encrypted" ascii
        $note1 = "your files have been encrypted" ascii nocase
        $note2 = "decrypt your files" ascii nocase
        $btc = "bitcoin" ascii nocase
    condition:
        any of them
}
