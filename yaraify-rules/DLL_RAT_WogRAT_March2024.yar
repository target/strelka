
import "dotnet"

rule DLL_RAT_WogRAT_March2024 {
    meta:
        Description = "Detects the Windows Version of WogRAT malware Developed in .NET"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://asec.ahnlab.com/en/62446/"
        Hash = "685636f918689b63f3a6ede86c29dc70d12a16c48f9396cd7446d4022063bf00"
        date = "2024-03-06"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "290789ea9d99813a07294ac848f808c9"
        yarahub_uuid = "beda5970-5b49-47d4-aa0b-bb43d6c9018d"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
        dotnet.assembly.name == "WingsOfGod"
        or dotnet.module_name == "WingsOfGod.dll"
        or dotnet.classes[0].namespace == "WingsOfGod"
        and dotnet.version == "v4.0.30319" // Remove for broader matching
        and dotnet.number_of_streams == 5
        and dotnet.classes[0].number_of_methods == 9
        and for 5 str in dotnet.user_strings:
        (str == "h\x00t\x00t\x00p\x00s\x00:\x00/\x00/\x00t\x000\x00r\x00g\x00u\x00a\x00r\x00d\x00.\x00n\x00e\x00t\x00/\x00c\x00/\x00"
        or str == "f\x00t\x00p\x00:\x00/\x00/\x00f\x00t\x00p\x00.\x00a\x00b\x00c\x00.\x00c\x00o\x00m\x00:\x002\x001\x00/\x00"
        or str == "t\x00a\x00s\x00k\x00_\x00i\x00d\x00"
        or str == "t\x00a\x00s\x00k\x00_\x00t\x00y\x00p\x00e\x00"
        or str == "t\x00a\x00s\x00k\x00_\x00d\x00a\x00t\x00a\x00")

}




 




 

 


 




 

 