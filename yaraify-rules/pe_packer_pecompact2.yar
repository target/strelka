import "pe"

rule pe_packer_pecompact2 {
    meta:
        date = "2023-09-07"
        yarahub_uuid = "8f58ee66-b658-4720-a986-4916308812d1"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "b204bee0440f1d7b82c64107610ea9b5"
        desc = "Detects PECompact2"
        author = "@jstrosch"

    strings:

        /*
            CODE:00401000 B8 74 C4 45 00       mov     eax, offset loc_45C474
            CODE:00401005 50                   push    eax
            CODE:00401006 64 FF 35 00 00 00 00 push    large dword ptr fs:0
            CODE:0040100D 64 89 25 00 00 00 00 mov     large fs:0, esp
            CODE:00401014 33 C0                xor     eax, eax
            CODE:00401016 89 08                mov     [eax], ecx
        */

        $x1 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 }
        $s1 = "PECompact2"

    condition:
         uint16(0) == 0x5a4d and $x1 at pe.entry_point and $s1 in (1024..1056) 
}