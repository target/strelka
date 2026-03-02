import "hash"

rule RedCurl_FSABIN
{ 

meta:

date = "2024-09-29"

yarahub_uuid = "81720f2f-7e0e-422a-9249-253e00b30c1a"
yarahub_license = "CC0 1.0"
yarahub_rule_matching_tlp = "TLP:WHITE"
yarahub_rule_sharing_tlp = "TLP:WHITE"
yarahub_reference_md5 = "b9321d5e65d8aec0c47c63382c308b91"

condition: 

           (hash.sha256(0,filesize) == "c218f8bbb8197b3c18f168e9cc688e5c6feed944703a157f6b28420739de7860" or
            hash.sha256(0,filesize) == "0f02a77ecc502db1b4041d4607881ed390c06633de9281affc86a5ace8faee76" or
            hash.sha256(0,filesize) == "fb53a1e2d2f67113b76465c9e248ac67cc5604e4149de50b2bc030a21792e594" or
            hash.sha256(0,filesize) == "403992d864d52c62870a033af072822d50d0eaca6c4652583065734fc0c950f0") 

}