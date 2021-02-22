import "pe"

rule gh0st_rat_loader {
    meta:
        author =  "tcontre"
        description = "detecting gh0strat_loader"
        date =  "2021-02-22"
				sha256 = "70ac339c41eb7a3f868736f98afa311674da61ae12164042e44d6e641338ff1f"

    strings:
        $mz = { 4d 5a }

        $code = { 40 33 FF 89 45 E8 57 8A 04 10 8A 14 0E 32 D0 88 14 0E FF 15 ?? ?? ?? ?? 8B C6 B9 ?? 00 00 00 }
        $str1 = "Shellex"
        $str2 = "VirtualProtect"
       
    
    condition:
        ($mz at 0) and $code and all of ($str*)

    }
    
rule gh0st_rat_payload {
    meta:
        author =  "tcontre"
        description = "detecting gh0strat_payload in memory without MZ header in memory"
        date =  "2021-02-22"
				sha256 = "edffd5fc8eb86e2b20dd44e0482b97f74666edc2ec52966be19a6fe43358a5db"

    strings:
		    $dos = "DOS mode"	
		    $av_str1 = "f-secure.exe"	
		    $av_str2 = "Mcshield.exe"
		    $av_str3 = "Sunbelt"
		    $av_str4 = "baiduSafeTray.exe"
		    
		    $clsid = "{4D36E972-E325-11CE-BFC1-08002BE10318}"
		    $s1 = "[WIN]"
		    $s2 = "[Print Screen]"
		    $s3 = "Shellex"
		    $s4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
		    $s5 = "%s\\%d.bak"

    
    condition:
        ($dos at 0x6c) and 2 of ($av_str*) and 4 of ($s*) and $clsid

    }
    