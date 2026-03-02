import "magic"
rule apt43_machine_names{
    meta:
        description = "Rule to detect APT43 LNK files via known usernames"
        author = "SpaceGh0t"
        date = "2025-03-01"
        yarahub_reference_md5="8b541e4da55cb41e3304bda5ea568eb7"
        yarahub_uuid = "b925e3c9-0144-4b02-a729-5eee5376cdf0"
        yarahub_license="CC BY-NC-ND 4.0"
        yarahub_rule_matching_tlp="TLP:GREEN"
        yarahub_rule_sharing_tlp="TLP:AMBER"
    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $s1 = "jooyoung"
        $s2 = "14_g2_itl"
        $s3 = "desktop-0jpcpit"
    condition:
        filesize > 2MB and (($lnk_magic at 0 or magic.mime_type() contains "x-ms-shortcut") and (any of ($s*)))
}