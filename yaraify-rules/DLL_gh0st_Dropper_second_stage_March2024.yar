import "pe"

rule DLL_gh0st_Dropper_second_stage_March2024
{
  meta:
    author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
    description = "Detects gh0st RAT which is the second stage paylaod dropped by gh0st Loader"
    file_hash = "86390c9407c61353595e43aa87475ffe96d9892cfac3324d02b374d11747184d"
    reference = "https://www.first.org/resources/papers/conference2010/cummings-slides.pdf"
    date = "2024-03-23"
    yarahub_author_twitter = "@RustyNoob619"
    yarahub_reference_md5 = "1b41c32c859068ccd215b12344604329"
    yarahub_uuid = "2f051a57-68ce-4004-80bf-ce0cc1d17481"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    malpedia_family = "win.ghostnet"
  condition:
    pe.imphash() == "6fc18c74c016f984b6cb657a45d03cab"
    or (pe.imports("IMM32.dll","ImmGetContext")
    and pe.imports("WINMM.dll","mixerGetDevCapsW")
    and pe.imports("WININET.dll","InternetOpenW")
    and pe.imports("USERENV.dll","CreateEnvironmentBlock")
    and pe.imports("PSAPI.DLL","EnumProcessModules")
    and pe.imports("SHELL32.dll","ShellExecuteExW"))
    and pe.exports("Install")
    and pe.exports("Launch")
    and pe.exports("ServiceMain")
    and pe.exports("Uninstall")
    and pe.resources[0].language == 2052
    and pe.pdb_path contains "gh0st"
    and not pe.pdb_path contains "i386"
    
}