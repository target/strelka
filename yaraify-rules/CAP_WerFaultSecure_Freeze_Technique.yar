import "pe"

rule CAP_WerFaultSecure_Freeze_Technique
{
  meta:
    description = "Detects binaries implementing the WER freeze technique via WerFaultSecure + MiniDumpWriteDump + privilege escalation + handle manipulation"
    author = "Itamar Hallstrom"
    date = "2025-09-26"
    confidence = "high"
    mitre_technique = "T1562.001"
    yarahub_uuid = "ceca5add-26e3-42f3-87ef-fe99f383e850"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "FFAC2D7F148BA0EE786A455F30A762F3"

  strings:
    // CLI flags observed in runtime invocation of WerFaultSecure.exe
    $wer        = "WerFaultSecure.exe" ascii wide nocase
    $flag_pid   = "/pid " ascii wide
    $flag_tid   = "/tid " ascii wide
    $flag_enc   = "/encfile " ascii wide
    $flag_can   = "/cancel " ascii wide
    $flag_h     = " /h" ascii wide
    $flag_type  = "/type " ascii wide   // present in runtime CLI  optional but strong indicator

    // Indicators of dump file artifact behavior
    $dumpfile   = "dump_" ascii wide
    $tfile      = "t.txt" ascii wide

    // Core TTP: MiniDumpWriteDump + suspension primitives
    $mini       = "MiniDumpWriteDump" ascii wide nocase
    $ntsp       = "NtSuspendProcess" ascii wide nocase
    $zwsp       = "ZwSuspendProcess" ascii wide nocase
    $ntst       = "NtSuspendThread" ascii wide nocase
    $zwst       = "ZwSuspendThread" ascii wide nocase

  condition:
    // Must reference WerFaultSecure or MiniDumpWriteDump (core elements of the technique)
    ( $wer or $mini )

    // Must include at least 2 core CLI flags (with /type allowed but not required)
    and 2 of ($flag_enc, $flag_can, $flag_pid, $flag_tid, $flag_h, $flag_type)

    // Must show file + event handle creation typical of this technique
    and pe.imports("KERNEL32.dll", "CreateFileW")
    and pe.imports("KERNEL32.dll", "CreateEventW")

    // Must attempt privilege escalation or thread suspension
    and (
         ( pe.imports("ADVAPI32.dll", "AdjustTokenPrivileges")
           and pe.imports("ADVAPI32.dll", "LookupPrivilegeValueW")
           and pe.imports("ADVAPI32.dll", "OpenProcessToken") )
         or any of ($ntsp, $zwsp, $ntst, $zwst)
        )

    // Require presence of dump-related artifacts (filename patterns)
    and any of ($dumpfile, $tfile)
}