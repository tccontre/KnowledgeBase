 import "pe"

rule unpack_lokibot_win32_ {
    meta:
        author =  "tcontre"
        description = "detecting lokibot malware"
        date =  "2019-09-27"
        sha256 = "2945f613f90355a1b5b4b5e6a0b13ff752e460ad3b03ed37d3abe861bfb6ad26"

    strings:
        $mz = { 4d 5a }
   
        $code1 = { 58 6A 33 5B 6A 32 5F 6A 2E 5A 6A 64 59 6A 6C 5E }
        $code2 = { 0F B6 06 4A 33 C8 46 6A 08 58 F6 C1 01 74 06 81 F1 ?? ?? ?? ?? D1 E9 48 75 F0 }
      
        $s1 = "POP3 Password2" fullword wide
        $s2 = "HTTPMail Password2" fullword wide
        $s3 = "%s\\32BitFtp.ini" fullword wide
        $s4 = "%s\\Data\\AccCfg\\Accounts.tdat" fullword wide
        $s5 = "Software\\SimonTatham\\PuTTY\\Sessions" fullword wide
        $s6 = "{.:CRED:.}" fullword wide
        $s7 = "Software\\Martin Prikryl" fullword wide
        $s8 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword wide
       
    condition:
        ($mz at 0) and 1 of ($code*) and 3 of ($s*)
   
    }
