import "pe"
import "math"
import "console"

rule RANSOM_Lockbit_Black_Packer : Ransomware {

   meta:
      author = "SECUINFRA Falcon Team"
      description = "Detects the packer used by Lockbit Black (Version 3)"
      reference = "https://twitter.com/vxunderground/status/1543661557883740161"
      date = "2022-07-04"
      tlp = "WHITE"
      yarahub_uuid = "de99eca0-9502-4942-a30a-b3f9303953e3"
      yarahub_reference_md5 = "38745539b71cf201bb502437f891d799"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      yarahub_author_twitter = "@SI_FalconTeam"
      hash0 = "80e8defa5377018b093b5b90de0f2957f7062144c83a09a56bba1fe4eda932ce"
      hash1 = "506f3b12853375a1fbbf85c82ddf13341cf941c5acd4a39a51d6addf145a7a51"
      hash2 = "d61af007f6c792b8fb6c677143b7d0e2533394e28c50737588e40da475c040ee"

   strings:
      $sectionname0 = ".rdata$zzzdbg" ascii
      $sectionname1 = ".xyz" ascii fullword
      
      // hash checks
      $check0 = {3d 75 80 91 76 ?? ?? 3d 1b a4 04 00 ?? ?? 3d 9b b4 84 0b}
      $check1 = {3d 75 ba 0e 64}
      
      // hex/ascii calculations
      $asciiCalc = {66 83 f8 41 ?? ?? 66 83 f8 46 ?? ?? 66 83 e8 37}
      
   condition:
      uint16(0) == 0x5a4d
      and filesize > 111KB // Size on Disk/1.5
      and filesize < 270KB // Size of Image*1.5
      and all of ($sectionname*)
      and any of ($check*)
      and $asciiCalc
      and for any i in (0..pe.number_of_sections - 1): 
      (math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.9
      and (pe.sections[i].name == ".text" or pe.sections[i].name == ".data" or pe.sections[i].name == ".pdata")//)
      // console requires Yara 4.2.0. For older versions uncomment closing bracket above und comment out the line below
      and console.log("High Entropy section found:", pe.sections[i].name))
}
