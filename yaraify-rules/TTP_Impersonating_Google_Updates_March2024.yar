
import "pe"

rule TTP_Impersonating_Google_Updates_March2024 {
    meta:
        Description = "Detects Windows executables which are impersonating Google Update utilities"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "@ULTRAFRAUD shared a signed Async RAT sample disguised as Google Chrome"
        Reference = "https://twitter.com/ULTRAFRAUD/status/1771590513973395666"
        File_Hash = "3f4ab98919c1e1191dddcceac3d8962390b2ac9f08f13986b0965bdaa0cff202"
        date = "2024-03-24"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "59aeea49aac78a74854837f549a51e11"
        yarahub_uuid = "2991b087-4930-41c3-b272-bb5a3337fc5e"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
        pe.version_info["LegalCopyright"] == "Copyright 2018 Google LLC"
        and pe.version_info["ProductName"] == "Google Update"
        and pe.number_of_signatures > 0 
        and not (for any sig in pe.signatures:
        (sig.thumbprint == "2673EA6CC23BEFFDA49AC715B121544098A1284C"       // 2021 to 2024 (most recent)
        or sig.thumbprint == "A3958AE522F3C54B878B20D7B0F63711E08666B2"    // 2019 to 2022 (Revoked)
        or sig.thumbprint == "CB7E84887F3C6015FE7EDFB4F8F36DF7DC10590E")) // 2018 to 2021 (Revoked)
 }