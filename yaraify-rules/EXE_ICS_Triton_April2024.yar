import "pe"

rule EXE_ICS_Triton_April2024 {
    meta:
        Description = "Detects Triton ICS malware used to target SIS (Safety Instrumentation Systems)"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://www.mandiant.com/resources/blog/attackers-deploy-new-ics-attack-framework-triton"
        File_Hash = "e8542c07b2af63ee7e72ce5d97d91036c5da56e2b091aa2afe737b224305d230"
        date = "2024-04-08"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "6c39c3f4a08d3d78f2eb973a94bd7718"
        yarahub_uuid = "98f5a9c0-a973-41fd-82e4-79cfc596de0a"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.triton"

    strings:
        $python = "PYTHONSCRIPT" wide fullword

        $antivm1 = "QueryPerformanceCounter"
        $antivm2 = "GetTickCount"
        $antivm3 = "IsDebuggerPresent"

        $lib = "library.zip" fullword // Custom communication library for interaction with Triconex controller
        $payload = "payload"
        $inject = "inject.bin"

        $str1 = "Blackhole"
        $str2 = "GetCpStatus" fullword
        $str3 = "UploadDummyForce" fullword

        $info1 = "countdown: %di" fullword
        $info2 = "time left = s" fullword
        $info3 = "DebugInfo:s" fullword

    condition:
        pe.imphash() == "b28c641d753fb51b62a00fe6115070ae"
        and $python
        and $lib
        and $payload
        and $inject
        and any of ($antivm*)
        and any of ($str*)
        and any of ($info*)
        and filesize < 100KB
        
 }









