import "pe"

rule LockbitBlack_Loader {
    meta:
        date = "2022-07-03"
        description = "Hunting rule for the Lockbit Black loader, based on https://twitter.com/vxunderground/status/1543661557883740161"
        author = "Zander Work"
        yarahub_author_twitter = "@captainGeech42"
        yarahub_uuid = "e4800674-46f7-4ba9-9d00-b9f2a5f51371"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "38745539b71cf201bb502437f891d799"
    strings:
        $c1 = { 02 f1 2a f1 8b c8 d3 ca 03 d0 }
        $c2 = { 8a 54 ?? 00 02 d3 8a 5c ?? 00 8a 54 ?? 00 8a 54 ?? 00 fe c2 8a 44 ?? 00 30 07 }
        $c3 = { 8b d8 8b 5b 08 8b 73 3c 03 f3 0f b7 7e 06 8d b6 f8 00 00 00 }
        $hash1 = { 3d 75 ba 0e 64 }
        $hash2 = { 3d 75 80 91 76 }
        $hash3 = { 3d 1b a4 04 00 }
        $hash4 = { 3d 9b b4 84 0b }
    condition:
        pe.is_pe and
        filesize > 100KB and filesize < 200KB and
        5 of them and
        pe.section_index(".itext") >= 0 and
        pe.section_index(".pdata") >= 0
}