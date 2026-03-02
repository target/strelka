import "pe"
import "math"

rule EXE_Python_Stealer_Jan2024 {
    meta:
        Description = "Detects Python Stealer based on generic strings and high entropy in resources"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://bazaar.abuse.ch/browse.php?search=signature%3Apython"
        Hash = "f0b789e7ac0c5eee6f264daeb13620aaf4baaa09a3e519a1c136822b63241c3e"
        date = "2024-01-27"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "6b1266f334d8f6c9986d1c94275a63fa"
        yarahub_uuid = "d04ba371-0426-42a0-aa51-891d5795f5d2"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
      
    strings:
        $s1 = "%TEMP%\\onefile_%PID%_%TIME%" wide
        $s2 = "CACHE_DIR" wide
        $s3 = "%PROGRAM%" wide
        $s4 = ".%HOME%" wide
        $s5 = "else_( ,, ,_s. =;_=if == 'METADATA'el.txte_os..("
    condition:
        3 of them
        and for any section in pe.sections:
        (math.entropy(section.raw_data_offset, section.raw_data_size) >= 7.7 and section.name == ".rsrc")
 }
