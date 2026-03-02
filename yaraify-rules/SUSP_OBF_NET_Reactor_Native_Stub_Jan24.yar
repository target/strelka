import "pe"
rule SUSP_OBF_NET_Reactor_Native_Stub_Jan24 {
    meta:
        description = "Detects native packer stub for version 4.5-4.7 of .NET Reactor. A pirated copy of version 4.5 of this commercial obfuscation solution is used by various malware families like BlackBit, RedLine, AgentTesla etc."
        author = "Jonathan Peters"
        date = "2024-01-05"
        reference = "https://notes.netbytesec.com/2023/08/understand-ransomware-ttps-blackbit.html"
        hash = "6e8a7adf680bede7b8429a18815c232004057607fdfbf0f4b0fb1deba71c5df7"
        score = 70
        yarahub_uuid = "526808de-7fc0-4910-a4a7-22ac296c51c8"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "cfbdc5baf26cb1e919caddb8c5d48c10"
    strings:
        $op = "{C6 44 24 18 E0 C6 44 24 19 3B C6 44 24 1A 8D C6 44 24 1B 2A C6 44 24 1C A2 C6 44 24 1D 2A C6 44 24 1E 2A C6 44 24 1F 41 C6 44 24 20 D3 C6 44 24 21 20 C6 44 24 22 64 C6 44 24 23 06 C6 44 24 24 8A C6 44 24 25 F7 C6 44 24 26 3D C6 44 24 27 9D C6 44 24 28 D9 C6 44 24 29 EE C6 44 24 2A 15 C6 44 24 2B 68 C6 44 24 2C F4 C6 44 24 2D 76 C6 44 24 2E B9 C6 44 24 2F 34 C6 44 24 30 BF C6 44 24 31 1E C6 44 24 32 E7 C6 44 24 33 78 C6 44 24 34 98 C6 44 24 35 E9 C6 44 24 36 6F C6 44 24 37 B4}"
    condition:
        for any i in ( 0 .. pe.number_of_resources - 1 ) : ( pe.resources [ i ] . name_string == "_\x00_\x00" ) and $op
}