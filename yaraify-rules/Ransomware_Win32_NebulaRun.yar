import "pe"

rule Ransomware_Win32_NebulaRun {
    meta:
        author = "github.com/keegan31"
        description = "Detects NebulaRun Ransomware variant"
        date = "2024-01-15"
        yarahub_uuid = "7058483b-e193-4dfc-b43d-cffc618cf077"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "9d82b9408af99a97511ce4f40b04b176"
        hash_sha256 = "6a3ebc7e04c827188054cf16dc7a3b1546355a3e6cbd67352be4ddb34f0ff3dd"
        malware_family = "Nebula"
        confidence = "high"
        threat_name = "Ransomware.Win32.NebulaRun"

    strings:
        $s1 = "NebulaRun.Nbl.resources" ascii wide
        $s2 = "NebulaRun.LAN+<SpreadAsync>d__8" ascii wide
        $s3 = "pictureBoxNebula" ascii wide
        $s4 = "GetBase64IV" ascii wide
        $s5 = "Your Files Are Encrypted" ascii wide
        $s6 = "LoopUsbSpread" ascii wide
        $s7 = "LoopLANSpread" ascii wide
        $s8 = "TryScheduleRemoteExecutionAsync" ascii wide
        $webhook1 = "https://discord.com/api/webhooks/1394025750595899596/IcBSS1apGOrYrR7QN9DxL2HJMUMakRS3zAR3bMK8UJZidYYRjfQZq5L0q1Z5SvIeDKg9" ascii
        $sys1 = "WriteAllBytes" ascii wide
        $sys2 = "CreateEncryptor" ascii wide
        $sys3 = "CreateDecryptor" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($webhook*) and 2 of ($sys*)) or
            (4 of ($s*) and 1 of ($sys*)) or
            (3 of ($s1,$s2,$s3,$s4) and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744")
        )
} 
