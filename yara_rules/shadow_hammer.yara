import "pe"

rule shadow_hammer_win32_ {
    meta:
        author =  "tcontre"
        description = "detecting shadowhammer malware"
        date =  "2019-04-10"
        sha256 = "9a72f971944fcb7a143017bc5c6c2db913bbb59f923110198ebd5a78809ea5fc"
 
    strings:
        $mz = { 4d 5a }
     
        $code1 = { BA 7C C2 11 00 03 D0 8B 3A 89 7D F8 6A 40 68 00 }
        $code2 = { C1 E0 07 B9 33 33 33 33 2B }
        $code3 = { C1 E0 09 B9 44 44 44 44 2B }     
    condition:
        ($mz at 0) and  2 of  ($code*)
     
    }
