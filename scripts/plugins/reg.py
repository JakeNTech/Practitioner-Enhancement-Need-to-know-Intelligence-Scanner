# Description: Windows Reg File identification
# Author: @JakeNTech
# Dependencies: binascii
# Version: 1
# Date: 17/09/2022

import binascii

def process_header_python(file):
    try:
        # Open file and convert bytes to hex
        this_file = open(file,"rb")
        hex_header = binascii.hexlify(this_file.read()[48:112]).decode("utf-8")
        this_file.close()
        # Split into Nibbles
        hex_header = [hex_header[i:i+2] for i in range(0, len(hex_header), 2)]
        decoded_header = ""
        # Convert Nibbles from HEX into ASCII/UTF-8
        for nibble in hex_header:
            if nibble != "00":
                decoded_header = decoded_header + bytearray.fromhex(nibble).decode("utf-8")
        decoded_header = decoded_header.upper()
    
        if "SYSTEM32" in decoded_header:
            decoded_header = decoded_header.replace("SYSTEM32","SYS32")
    except:
        decoded_header = "Failed to Load Registry File Header"
    return decoded_header

def identify_single_file(file):
    #file_header = process_header_hexdump(file)
    file_header = process_header_python(file)
    identified_type = ""
    
    if "SAM" in file_header:
        identified_type = "SAM"
    
    elif "SECURITY" in file_header:
        identified_type = "SECURITY"
    
    elif "SYSTEM" in file_header:
        identified_type = "SYSTEM"
    
    elif "SOFTWARE" in file_header:
        identified_type = "SOFTWARE"
    
    elif "NTUSER" in file_header:
        identified_type = "NTUSER"
    
    elif "USRCLASS.DAT" in file_header:
        identified_type = "USRCLASS"
    
    elif "AMCACHE" in file_header:
        identified_type = "AMCACHE"
    
    else:
        identified_type = "UNKNOWN"
    
    this_line = [identified_type, file_header]
    additional_parsing = identified_type
    
    return additional_parsing, this_line

__artifacts__ = {
    "octet-stream": (
        "File Analysis",
        "hive,full_hive_area",
        identify_single_file)
}