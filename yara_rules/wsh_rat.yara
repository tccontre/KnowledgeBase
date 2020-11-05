import "pe"

rule wsh_rat_plugins {
    meta:
        author =  "tcontre"
        description = "detecting wshrat_plugins"
        date =  "2020-02-26"
        sha256_rdp = "d65a3033e440575a7d32f4399176e0cdb1b7e4efa108452fcdde658e90722653"
        sha256_reverseproxy = "bb2bb116cc414b05ebc9b637b22fa77e5d45e8f616c4dc396846283c875bd129"
        sha256_keylogger = "272e64291748fa8be01109faa46c0ea919bf4baf4924177ea6ac2ee0574f1c1a"

    strings:
        $mz = { 4d 5a }

        $code_reverse_proxy = {25 28 1C 00 00 0A 0C 00 02 7B 0E 00 00 04 6F 40 00 00 0A 00 02 7B 0F 00 00 04 6F 40 00 00 0A 00 28 20 00 00 0A DE 00 }
        $wsh_rvp1 = "WSH Inc" fullword
        $wsh_rvp2 = "ReverseProxy.pdb" fullword
       
        $code_rdp = {5A 28 3A 00 00 0A B7 6F 3C 00 00 0A 00 73 3D 00 00 0A 13 05 07 11 05 28 3E 00 00 0A}
        $wsh_rdp1 = "WSHRat Plugin" fullword
        $wsh_rdp2 = "open-rdp" fullword wide
       
        $code_key = {9A 02 17 9A 28 4F 00 00 0A 6F 50 00 00 0A 00 72 CD 00 00 70 02 18 9A 72 23 01 00 70 28 51 00 00 0A }
        $wsh_key1 = "Keylogger.pdb" fullword
        $wsh_key2 = "open-keylogger" fullword wide
       
    
    condition:
        ($mz at 0) and 1 of ($code*) and 2 of ($wsh*)

    }
