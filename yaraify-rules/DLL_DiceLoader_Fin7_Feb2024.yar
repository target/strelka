import "pe"

rule DLL_DiceLoader_Fin7_Feb2024 {
    meta:
        Description = "Detects Dice Loader malware used by Fin7 APT based on the export properties"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Sekoia for providing the intel and malware sample"
        Reference = "https://blog.sekoia.io/unveiling-the-intricacies-of-diceloader/"
        Hash = "8a287fbd024544c34b5db983af093504d25be864a821010f4cd2d00a2a6ad435"
        date = "2024-02-02"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "6ab83f7de850de708722440d96007ea2"
        yarahub_uuid = "eace0b51-0a32-47b4-9403-b605fd40ad1f"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.diceloader"

    strings:
       $exp_func = /[a-zA-z]{16}\x00/ //Random name of the export function 
       $s1 = "GetQueuedCompletionStatus"
       $s2 = "PostQueuedCompletionStatus"
       $s3 = "CreateIoCompletionPort"
       $s4 = "ResetEvent"
       $s5 = "CreateMutexA"
       $s6 = "ReleaseMutex"
       $s7 = "GetComputerNameExA"
       $net1 = "gethostbyname"
       $net2 = "closesocket"
       $net3 = "recv"
       $net4 = "htons"
       $net5 = "inet_addr"
       $net6 = "connect"
       $other = "GetAdaptersInfo"
       
    condition:
        pe.imphash() == "37af5cd8fc35f39f0815827f7b80b304" //matches on 7 Dice Loader Samples
        or 
        (pe.number_of_exports == 1
        and pe.export_details[0].ordinal == 1  
        and ($exp_func at (0x2888) or $exp_func at (0x2338))) //Checking for export function name 
        and 5 of ($s*) and 4 of ($net*) and $other
            
 }
