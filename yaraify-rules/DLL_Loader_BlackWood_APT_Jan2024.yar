import "pe"

rule DLL_Loader_BlackWood_APT_Jan2024 {
    meta:
        Description = "Detects the Dll Loader for the NSPX30 implant used by the Black Wood APT"
        Author = "RustyNoob619"
        Reference = "https://blog.sonicwall.com/en-us/2024/01/blackwood-apt-group-has-a-new-dll-loader/"
        Hash = "72b81424d6235f17b3fc393958481e0316c63ca7ab9907914b5a737ba1ad2374"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        date = "2024-01-31"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "d8c80dc68e24a6b3c2ac31e1ef489612"
        yarahub_uuid = "10e2151a-01cb-4977-b6dd-1560e826872e"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        
    strings:
        $s1 = "Update.ini"
        $s2 = "333333333333333.txt"
    condition:
        pe.dll_name == "agent.dll"
        and pe.number_of_exports == 1
        and pe.export_details[0].ordinal == 1
        and any of them    
       
 }