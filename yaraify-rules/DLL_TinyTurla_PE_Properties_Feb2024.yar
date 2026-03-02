import "pe"

rule DLL_TinyTurla_PE_Properties_Feb2024 {
    meta:
        Description = "Detects Tiny Turla Implant used by Turla APT based on PE import and export properties"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://blog.talosintelligence.com/tinyturla-next-generation/"
        Hash = "267071df79927abd1e57f57106924dd8a68e1c4ed74e7b69403cdcdf6e6a453b"
        date = "2024-02-20"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "e4c356cf822cda0ca8e8161cb5bf6c39"
        yarahub_uuid = "d7e7e3fd-50e7-48fb-b5bf-283bf20e5157"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.tinyturla_ng"
        
    condition:
        pe.imphash() == "2240ae6f0dcbc0537836dfd9205a1f2b"
        or
        (pe.imports("KERNEL32.dll","RtlPcToFileHeader")
        and pe.imports("KERNEL32.dll","GetUserDefaultLCID")
        and pe.imports("KERNEL32.dll","GetOEMCP")
        and pe.imports("ADVAPI32.dll","RegisterServiceCtrlHandlerW")
        and pe.imports("ADVAPI32.dll","SetServiceStatus")  
        and pe.imports("WINHTTP.dll","WinHttpQueryDataAvailable")
        and pe.imports("WINHTTP.dll","WinHttpWriteData"))
        and pe.export_details[0].name == "ServiceMain"
       
 }
