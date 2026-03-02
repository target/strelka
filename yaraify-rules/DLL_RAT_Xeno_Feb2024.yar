
import "pe"

rule DLL_RAT_Xeno_Feb2024 {
    meta:
        Description = "Detects Xeno RAT malware based on PE properties"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://www.cyfirma.com/outofband/xeno-rat-a-new-remote-access-trojan-with-advance-capabilities/"
        Hash = "1762536a663879d5fb8a94c1d145331e1d001fb27f787d79691f9f8208fc68f2"
        date = "2024-02-28"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "7704241dd8770b11b50b1448647197a5"
        yarahub_uuid = "c2c4ab61-e1b0-45cd-b880-22806d9e6bab"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
        pe.imphash() == "ed4aa283499e90f2a02acb700ea35a45"
        or pe.pdb_path == "C:\\Users\\IEUser\\Desktop\\samcli-FINAL\\x64\\Release\\samcli.pdb"
        and pe.number_of_exports == 36
        and pe.number_of_signatures == 1
        and for all export in pe.export_details:
        (export.name startswith "Net" and export.forward_name startswith "C:\\Windows\\System32\\samcli.Net")
        and for all resource in pe.resources:
        (resource.language == 2057 or resource.language == 1033) // English US and UK
        and pe.version_info["LegalCopyright"] == "\xa9 Microsoft Corporation. All rights reserved." // Impersonating Microsoft
       
 }



 

 