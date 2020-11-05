 import "pe"

rule covid_mbr_gui {
    meta:
        author =  "tcontre"
        description = "detecting covid_19_main_window"
        date =  "2020-04-08"
        sha256 = "b780e24e14885c6ab836aae84747aa0d975017f5fc5b7f031d51c7469793eabe"

    strings:
        $mz = { 4d 5a }
        $s1 = "coronavirus has infected your PC!" fullword
        $s2 = "Task Manager are disabled" fullword wide
  
    condition:
        ($mz at 0) and all of ($s*)

    }

 import "pe"

rule covid_mbr_killer {
    meta:
        author =  "tcontre"
        description = "detecting covid_19_end_exe"
        date =  "2020-04-08"
        sha256 = "c3f11936fe43d62982160a876cc000f906cb34bb589f4e76e54d0a5589b2fdb9"

    strings:
        $mz = { 4d 5a }
        $c1 = {8A 03 C1 E8 04 40 BA DC 83 40 00 8A 44 02 FF 5A 88 02 8B C5 }
        $c2 = {8B D6 03 D2 42 03 C2 50 8A 03 24 0F 25 FF 00 00 00 40 BA DC 83 40 00 8A 44 02 FF 5A 88 02}
        $d1 = {6A 00 68 F4 B7 40 00 68 00 02 00 00 68 FC C5 40 00 53 E8 ?? ?? ?? ?? 6A 00 6A 00 68 00 02 00 00}                                  
        $d2 = {53 E8 ?? ?? ?? ?? 6A 00 68 F8 B7 40 00 A1 F4 B7 40 00 50 68 FC C5 40 00 53 E8 ?? ?? ?? ?? 53 E8}                                   
        $s1 = "WobbyChip" fullword
   
    condition:
        ($mz at 0) and $s1 and 1 of ($c*) and 1 of ($d*)

    }
  import "pe"

rule covid_runner {
    meta:
        author =  "tcontre"
        description = "detecting covid_19_unpack_run_exe"
        date =  "2020-04-08"
        sha256 = "c46c3d2bea1e42b628d6988063d247918f3f8b69b5a1c376028a2a0cadd53986"

    strings:
        $mz = { 4d 5a }
        $c = {68 0A 00 00 00 FF 74 24 04 FF 74 24 14 E8 ?? ?? ?? ?? 89 44 24 04 83 7C 24 04 00 74 24 FF 74 24 04 FF 74 24 10 E8}
        $s1 = "%homedrive%\\COVID-19" fullword
        $s2 = "disabletaskmgr" fullword
        $s3 = "NoChangingWallPaper" fullword
        $s4 = "ADD HKLM\\software\\Microsoft\\Windows\\CurrentVersion\\Run" fullword
  
    condition:
        ($mz at 0) and 2 of ($s*) and $c

    }
