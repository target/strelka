import "magic"
rule Win_b64_pwshl{
    meta:
        date = "2025-03-14"
        yarahub_reference_md5= "6c616329b8de73aa86711998f06b1e51"
        yarahub_uuid = "f85647f0-3899-474c-98e9-e8680abda7ba"
        yarahub_license="CC BY-NC-ND 4.0"
        yarahub_rule_matching_tlp="TLP:WHITE"
        yarahub_rule_sharing_tlp="TLP:AMBER"
    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $s1 = "powershell -windowstyle hidden -encodedcommand" nocase wide
        $s2 = "powershell -ws h -encodedcommand" nocase wide
        $s3 = "powershell -windowstyle h -encodedcommand" nocase wide
        $s4 = "powershell -ws hidden -encodedcommand" nocase wide
        $s5 = "powershell -windowstyle hidden -ec" nocase wide
        $s6 = "powershell -ws h -ec" nocase wide
        $s7 = "powershell -windowstyle h -ec" nocase wide
        $s8 = "powershell -ws hidden -ec" nocase wide



    condition:
        filesize > 2KB and (($lnk_magic at 0 or magic.mime_type() contains "x-ms-shortcut") and (any of ($s*)))
}