import "pe"

rule azorult_win32_unpack {
    meta:
        author =  "tccontre"
        description = "detecting azorult malware"
        date =  "2019-01-23"
        sha256 = "ae75cd28bc2309f085f79bc8bd480e797b5e42f852c40a8cc733e1a51a7c5fa9"
  
    strings:
        $mz = { 4d 5a }
      
        $s1 = "FROM moz_places, moz_historyvisits WHERE" fullword
      
        $c0 = "\\accounts.xml" fullword wide
        $c1 = "PortNumber" fullword wide
        $c2 = "\\places.sqlite" fullword wide

        $code1 = { 81 F1 8A 45 21 65 03 D9 8B CB C1 E1 0D 8B F3 C1 EE 13 0B CE 2B D9 42 48 }
               
    condition:
        ($mz at 0) and all of ($s*) and 2 of ($c*) and all of ($code*)
      
    }
