
import "pe"

rule EXE_Loader_XDealer_March2024 {
    meta:
        Description = "Detects Loader used to deliver the XDealer Malware aka DinodasRAT which is used by Chinese APT Earth Krahang "
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://www.trendmicro.com/en_us/research/24/c/earth-krahang.html"
        Credits = "@smica83 for uploading the malware sample to Malware Bazaar"
        File_Hash_1 = "2e3645c8441f2be4182869db5ae320da00c513e0cb643142c70a833f529f28aa"
        File_Hash_2 = "8218c23361e9f1b25ee1a93796ef471ca8ca5ac672b7db69ad05f42eb90b0b8d"
        date = "2024-03-31"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "87fb1af534b0913bb23fe923afd34064"
        yarahub_uuid = "802f4c9e-a839-4174-aeba-37ddf364d8a7"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.dinodas_rat"

    strings: 
        $reg = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" wide
        $exe = "\\calc.exe" wide
        $str = "okernel32" wide
        $dll = "gntdll.dll" wide
        
    condition:
        all of them
        and (pe.imphash() == "79ed833f90b585ce7dfa89a34d1b1961"
        or for any signature in pe.signatures:
            (signature.thumbprint == "be9de0d818b4096d80ce7d88110917b2a4e8273f"     
            or signature.thumbprint == "be31e841820586e9106407d78ae190915f2c012d"))  
        
 }











