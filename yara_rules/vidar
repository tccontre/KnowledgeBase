import "pe"

rule vidar_win32_unpack {
    meta:
        author =  "tcontre"
        description = "detecting vidar unpack malware"
        date =  "2019-03-11"
        sha256 = "076bf8356f73165ba8f3997a7855809f33781639ad02635b3e74c381de9c5e2c"
 
    strings:
        $mz = { 4d 5a }
     
        $s1 = "SELECT host, name, value FROM moz_cookies" fullword     
        $s2 = "Vidar Version:" fullword
        $s3 = "card_number_encrypted FROM credit_cards" fullword

        $c0 = "softokn3.dll" fullword
        $c1 = "nss3.dll" fullword
        $c2 = "mozglue.dll" fullword
        $c3 = "freebl3.dll" fullword

        $code1 = { C6 45 FC 30 E8 ?? ?? ?? ?? 83 78 14 08 C6 45 FC 31 72 02 }
              
    condition:
        ($mz at 0) and all of ($s*) and 2 of ($c*) and all of ($code*)
     
    }
