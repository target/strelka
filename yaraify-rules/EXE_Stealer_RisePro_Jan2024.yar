import "pe"

rule EXE_Stealer_RisePro_Jan2024 {
    meta:
        Description = "Detects Rise Pro Stealer samples based on properties in the resources, manifest settings and PE Rich Header"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://bazaar.abuse.ch/browse/signature/RiseProStealer/"
        Hash = "957ca1ae2bbb01a37d1108b314160716643933ec9ef9072a4c50c39b224662df"
        SampleSize = "Tested against 3 RisePro samples and wider malware collection"
        date = "2024-01-28"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "81c2db976c46628b590c6e02d4e54d67"
        yarahub_uuid = "04c6c57f-d27e-4ec7-963e-480e89ad7b1c"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.risepro"
        
    strings: 
        $s1 = "'1.0' encoding" 
        $s2 = "'UTF-8' standalone" 
        $s3 = "'yes'?" 
        $s4 = "'urn:schemas-microsoft-com:asm.v1' manifestVersion" 
        $s5 = "trustInfo xmlns" 
        $s6 = "urn:schemas-microsoft-com:asm.v3" 
        $s7 = "security" 
        $s8 = "requestedPrivileges" 
        $s9 = "requestedExecutionLevel level" 
        $s10 = "'asInvoker' uiAccess" 
        $s11 = "'false' /" 
// The above strings need to be adjusted to only pick dynamic XML parameters 
    condition:
       pe.rich_signature.key== 3099257863  //can be removed for broader matching
       and pe.RESOURCE_TYPE_ICON == 3
       and for 5 resource in pe.resources: 
       (resource.language == 1049) // Checking for Russian Language related resources
       and  pe.resources[pe.number_of_resources-1].type == 24 // Searching for XML Manifest Type
       and all of them in (filesize-700000..filesize) // Checking for the XML Manifest settings near the end
 }
