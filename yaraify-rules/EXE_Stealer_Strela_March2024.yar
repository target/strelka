
import "pe"

rule EXE_Stealer_Strela_March2024 {
    meta:
        Description = "Detects Strela Stealer malware primarily based on the PE Imphash"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Hash = "3b1b5dfb8c3605227c131e388379ad19d2ad6d240e69beb858d5ea50a7d506f9"
        date = "2024-03-15"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "95caaebc8023b12215a0853fa8d1a9f7"
        yarahub_uuid = "8ab4b624-ba79-405e-91ed-7b2914811cde"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.strelastealer"

    strings:
        $str1 = "GCC: (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r3) 13.2.0"
        $str2 = "GCC: (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders) 13.2.0"
        
    condition:
        pe.imphash() == "f9e3bc32d194f624b25a23d75badfcf"
        and any of them
        
}





 

 


 




 

 




 

 


 










 


 