/*
   AgentWatch sample YARA rules.

   These are deliberately small and high-signal. They are loaded by the YARA
   bridge when the `yara` CLI is on PATH and this directory is passed as the
   rules directory (the CLI default when rules/yara exists).

   Rule severity defaults to `high` in AgentWatch until meta parsing lands.
*/

rule AgentWatch_Encoded_PowerShell
{
    meta:
        description = "PowerShell encoded command invocation"
        severity    = "high"
        author      = "agentwatch"
    strings:
        $ps  = "powershell" nocase
        $enc = "-enc" nocase
    condition:
        $ps and $enc
}

rule AgentWatch_Reverse_Shell_DevTcp
{
    meta:
        description = "bash /dev/tcp reverse shell"
        severity    = "high"
    strings:
        $a = "/dev/tcp/" nocase
        $b = ">&"
    condition:
        $a and $b
}

rule AgentWatch_EICAR
{
    meta:
        description = "EICAR antivirus test string"
        severity    = "high"
    strings:
        $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $e
}
