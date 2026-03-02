import "pe"
rule Credential_Leak_Detector_API_2
{
meta:
    {
    date = "2025-11-07"
    yarahub_uuid = "7ea9bc68-b9e7-49e1-9fea-aa07c0580072"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "00000000000000000000000000000000"
    }

    meta:
    
        description = "Detects Api keys from google or openai"
 
        
    strings:
   
       //Google
        $g_keyword_or = /(access_key|secret_key|access_token|api_key|apikey|api_secret|apiSecret|app_secret|application_key|app_key|appkey|auth_token|authsecret)/ wide ascii nocase
        $g_signature = "AIza" wide ascii
        $g_word = "generativelanguage" wide ascii nocase

        //OpenAI
        $o_key_regex = /sk-[a-zA-Z0-9]{48}/ wide ascii
        $o_keyword_openai = "openai" wide ascii nocase
        $o_keyword_gpt = "gpt" wide ascii nocase
        
    condition:
        pe.is_pe and       


        (
            // Goolge
            $g_keyword_or and $g_signature and $g_word
        ) 
        or 
        (
            // Openai
            $o_key_regex and ($o_keyword_openai or $o_keyword_gpt)
        )
}

