import "pe"

rule Indicator_MiniDumpWriteDump : MiniDumpWriteDump
{
    meta:
        author                       = "Obscurity Labs LLC"
        description                  = "Detects PE files and PowerShell scripts that use MiniDumpWriteDump either through direct imports or string references"
        date                         = "2025-06-06"
        version                      = "1.0.1"
        yarahub_author_twitter       = "@obscuritylabs"
        yarahub_reference_md5        = "c3fc97f82241d6d91c6d037190b3753c"
        yarahub_uuid                 = "90626ac0-e544-4d5b-b8c3-e70a7feb2b75"
        yarahub_license              = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp    = "TLP:WHITE"
        yarahub_rule_sharing_tlp     = "TLP:WHITE"
        mitre_attack_tactic          = "TA0006"
        mitre_attack_technique       = "T1003"

    strings:
        // Plain text versions
        $dll_name_plain  = "DbgHelp.dll"         nocase
        $proc_name_plain = "MiniDumpWriteDump"   nocase
        
        // XOR and wide versions
        $dll_name_xor    = "DbgHelp.dll"         xor wide ascii
        $proc_name_xor   = "MiniDumpWriteDump"   xor wide ascii
        
        // Base64 encoded versions
        $dll_name_b64    = "DbgHelp.dll"         base64
        $proc_name_b64   = "MiniDumpWriteDump"   base64

    condition:
        (
            // Case 1: PE file with direct import
            pe.is_pe and pe.imports("DbgHelp.dll", "MiniDumpWriteDump")
        )
        or
        (
            // Case 2: String presence in any file type
            any of ($dll_name_plain, $dll_name_xor, $dll_name_b64)     // the code references "DbgHelp.dll"
            and
            any of ($proc_name_plain, $proc_name_xor, $proc_name_b64)    // the code references "MiniDumpWriteDump"
        )
}

