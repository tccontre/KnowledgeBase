

import os
import argparse

def parse_byte_array(byte_array_str):
    # Convert the string representation back to a byte array
    byte_array = bytes.fromhex(byte_array_str)
    return byte_array

"""
__author__ = "tccontre" - Br3akp0int
description = simple xor tool
"""



def xored(enc_file, dec_key):
    with open(enc_file, "rb") as f:
        buff = f.read()

    ### iterate and xor
    xored_buff = bytearray(len(buff))

    for i in range(0, len(buff)):
        
        xored_buff[i] = buff[i] ^ dec_key[i % len(dec_key)]
    return xored_buff


def main():
    parser = argparse.ArgumentParser(description="simple xor tool for 1 file or folder of files")
    parser.add_argument('-f', '--enc_file', help="the encrypted file to decrypt", required=True)
    parser.add_argument('-k', '--dec_key', type=parse_byte_array, help="decryption key in bytes format e.g 48656C6C6F20576F726C64", required=True)
    
    args = vars(parser.parse_args())
    enc_file = args['enc_file']
    dec_key = args['dec_key']
    
    xored_buff = xored(enc_file, dec_key)

    xored_file_name = "xored_" + os.path.basename(enc_file)

    with open(xored_file_name, "wb") as f:
        f.write(xored_buff)
    print(f"[+] File Name: {enc_file}")
    print(f"[+] Xor Key: {dec_key}")
    print(f"[+] File Size to be xor-ed: {len(xored_buff)}")
    print(f"[+] Successfully xored {enc_file} -> {xored_file_name}")
    return


if __name__ == "__main__":
    main()

