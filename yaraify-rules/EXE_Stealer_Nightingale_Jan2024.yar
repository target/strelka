import "pe"

rule EXE_Stealer_Nightingale_Jan2024 {
    meta:
        Description = "Detects Nightingale Stealer samples"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Yogesh Londhe @suyog41 for sharing the File Hash on Twitter"
        Reference = "https://twitter.com/suyog41/status/1751930165230469619"
        Hash = "0c0cc6d724ac017163b40866c820fd67df6ac89924a623490ec1de2ecacf1d0219"
        date = "2024-01-30"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "a1d8eceb8c701feb83b225d73fc237be"
        yarahub_uuid = "4d74266f-5afb-4662-9ff4-365aaa31d333"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    condition:
        pe.import_details[1].library_name == "ucrtbase.dll"
        and for 5 function in pe.import_details[0].functions: //KERNEL32.dll
        (function.name endswith "CriticalSection" or function.name == "Sleep")
        and for 7 section in pe.sections:
        (section.full_name startswith ".debug")
       
 }

