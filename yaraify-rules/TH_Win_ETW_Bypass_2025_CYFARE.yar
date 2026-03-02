import "pe"

rule TH_Win_ETW_Bypass_2025_CYFARE
{
    meta:
        author                       = "CYFARE"
        description                  = "Windows ETW Bypass Detection Rule - 2025"
        reference                    = "https://cyfare.net/"
        date                         = "2025-10-13"
        version                      = "1.0.0"
        yarahub_uuid                 = "581df72c-c06c-4999-8ca2-be4492cf24ac"
        yarahub_license              = "CC0 1.0"
        yarahub_rule_matching_tlp    = "TLP:WHITE"
        yarahub_rule_sharing_tlp     = "TLP:WHITE"
        yarahub_reference_md5        = "3954d61f3868749e75add46987b7a2fa"
    strings:
        // Common ETW-related API - patching/bypassing
        $etw_write          = "EtwEventWrite" ascii wide nocase
        $etw_write_full     = "EtwEventWriteFull" ascii wide nocase
        $etw_write_ex       = "EtwEventWriteEx" ascii wide nocase
        $etw_write_xfer     = "EtwEventWriteTransfer" ascii wide nocase
        $etw_register       = "EtwEventRegister" ascii wide nocase
        $etw_unregister     = "EtwEventUnregister" ascii wide nocase
        $nt_trace_event     = "NtTraceEvent" ascii wide nocase

        // Dynamic resolution / patching helpers
        $getproc            = "GetProcAddress" ascii wide nocase
        $getmodA            = "GetModuleHandleA" ascii wide nocase
        $getmodW            = "GetModuleHandleW" ascii wide nocase
        $ntdll_str          = "ntdll.dll" ascii wide nocase
        $vprotect           = "VirtualProtect" ascii wide nocase
        $wpm                = "WriteProcessMemory" ascii wide nocase

        // Inline patch stubs - EtwEventWrite / NtTraceEvent
        // x64: xor rax, rax ; ret
        $patch_x64          = { 48 31 C0 C3 }
        // x86: xor eax, eax ; ret 0x14
        $patch_x86_stack    = { 33 C0 C2 14 00 }
        // x86/x64: xor eax, eax ; ret
        $patch_x86_short    = { 33 C0 C3 }

    condition:
        uint16(0) == 0x5A4D and  // 'MZ'
        filesize < 50MB and
        pe.is_pe and
        (
            // Case A: Statically importing EtwEventWrite from ntdll and shows patch stub
            (
                pe.imports("ntdll.dll", "EtwEventWrite") and
                (
                    (pe.machine == pe.MACHINE_AMD64 and any of ($patch_x64))
                    or
                    (pe.machine == pe.MACHINE_I386 and (any of ($patch_x86_stack, $patch_x86_short)))
                )
            )
            or
            // Case B: Dynamic resolution of ntdll!Etw* plus memory/permission APIs and patch stub present
            (
                (1 of ($etw_write, $etw_write_full, $etw_write_ex, $etw_write_xfer, $etw_register, $etw_unregister, $nt_trace_event)) and
                (1 of ($getproc, $getmodA, $getmodW)) and
                $ntdll_str and
                (1 of ($vprotect, $wpm)) and
                (
                    (pe.machine == pe.MACHINE_AMD64 and any of ($patch_x64))
                    or
                    (pe.machine == pe.MACHINE_I386 and (any of ($patch_x86_stack, $patch_x86_short)))
                )
            )
        )
}

