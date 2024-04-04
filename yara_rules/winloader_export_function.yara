import "pe"

rule possible_wine_loader_export_function {
    meta:
        author =  "@tccontre18 - Br3akp0int"
        description = "possible wine loader export function start code"
        date =  "2024-04-03"
        sha256 = "72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4"
    
    strings:
        $exp_loader = {48 83 EC 08 48 8D 0D ?? ?? ?? ?? 48 C7 C2 28 80 00 00 E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? 00 00 48 C7 05 ?? ?? ?? ?? 28 80 00 00 E8 ?? ?? 00 00 48 83 C4 08 C3}

    condition:
        uint16(0) == 0x5a4d and $exp_loader and pe.number_of_exports != 0 
        
    }
