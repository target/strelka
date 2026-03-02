
import "pe"

rule EXE_Ransomware_Tuga_March2024
{
  meta:
    author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
    description = "Detects Tuga Ransomware Samples"
    file_hash = "79a4c04639a0a9983467370b38de262641da79ccd51a0cdcd53aba20158f1b3a"
    credits = "@suyog41 for sharing the malware file hash on Twitter"
    reference = "https://twitter.com/suyog41/status/1769614794703991255"
    date = "2024-03-18"
    yarahub_author_twitter = "@RustyNoob619"
    yarahub_reference_md5 = "9b8ecdecbe7ac4bbf4568817f6f1fc39"
    yarahub_uuid = "9012a005-0319-4623-9218-6d64b1c8972c"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
  
  strings:
    $tuga = "C:\\Users\\shade\\Downloads\\RansomTuga-master" 

  condition:
    (pe.version_info["InternalName"] == "RansomTuga.exe" 
    or pe.version_info["InternalName"] == "Tuga.exe" 
    or $tuga)
    and pe.number_of_sections == 7
    and pe.imports("KERNEL32.dll","AreFileApisANSI")
    and (pe.imports("ADVAPI32.dll","GetUserNameW")
    or pe.imports("USER32.dll","GetClipboardData"))
    
}

 

 




 

 


 




 

 




 

 


 










 


 