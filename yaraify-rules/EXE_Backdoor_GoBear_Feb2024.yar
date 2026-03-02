import "pe"

rule EXE_Backdoor_GoBear_Feb2024 {
    meta:
        Description = "Detects the Go Bear Backdoor used by Kimsuky based on the PE export property"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://medium.com/s2wblog/kimsuky-disguised-as-a-korean-company-signed-with-a-valid-certificate-to-distribute-troll-stealer-cfa5d54314e2"
        Hash = "a8c24a3e54a4b323973f61630c92ecaad067598ef2547350c9d108bc175774b9"
        date = "2024-02-12"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "87429e9223d45e0359cd1c41c0301836"
        yarahub_uuid = "36cace0a-d236-4d8c-b9ed-e9b9f78f55ac"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
        pe.export_details[0].name contains "._:|"
        and pe.signatures[0].subject contains "D2innovation"
        and pe.signatures[0].serial == "00:88:90:ca:b1:cd:51:0c:d2:0d:ab:4c:e5:94:8c:bc:3a"

}


  