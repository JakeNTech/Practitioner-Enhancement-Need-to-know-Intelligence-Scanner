# All functions to do with file actions
import os
import subprocess
import shutil
import psutil
import time

from hachoir.parser import createParser
from hachoir.metadata import extractMetadata
from hachoir.core import config as HachoirConfig

import hashlib
from datetime import datetime

def get_file_size(file):
    try:
        size = round(os.path.getsize(file)/1000,2)
    except:
        size = 0
    return size

def move_file(source_filepath,target_path,file_name):
    # move the file - > https://www.cgsecurity.org/wiki/After_Using_PhotoRec
    if os.path.exists(target_path+file_name):
        log_for_logging = open("Log.txt","a")
        log_for_logging.write(f"WARNING: this file was not copied: {str(source_filepath)}\n")
        log_for_logging.close()
    else:
        isExist = os.path.exists(target_path)
        if isExist == False:
            os.makedirs(target_path)
        shutil.move(source_filepath,target_path+file_name)

def copy_file(source_filepath,target_path,file_name):
    # copy the file - > https://www.cgsecurity.org/wiki/After_Using_PhotoRec
    if os.path.exists(target_path+file_name):
        log_for_logging = open("Log.txt","a")
        log_for_logging.write(f"WARNING: this file was not copied: {str(source_filepath)}\n")
        log_for_logging.close()
    else:
        isExist = os.path.exists(target_path)
        if isExist == False:
            os.makedirs(target_path)
        shutil.copy(source_filepath,target_path+file_name)

# hachoir Supported Formats: MOV, AVI, EXE
def fetch_hachoir(file):
    HachoirConfig.quiet = True
    try:
        parser = createParser(file)
        metadata = extractMetadata(parser).exportPlaintext()
        for i in range(0,len(metadata)):
            metadata[i] = metadata[i].replace("- ","")
            metadata[i] = metadata[i].replace("Comment:","")
            metadata[i] = metadata[i].strip()
            
        # To get more info you need to do this.
        new_metadata = {}
        for i in range(0,len(metadata)):
            new_metadata[str(metadata[i].split(":")[0]).lower()] = ":".join(metadata[i].split(":")[1::])

    except Exception:
        new_metadata = {"Error_Loading_File":"Error"}

    return new_metadata

# Calculate the hash for a given file
def SHA1_hash(file):
    calculated_hash = ""
    # try:
    #     result = subprocess.run(['SHA1sum', file], stdout=subprocess.PIPE)
    #     result = result.stdout.split()[0].decode("ASCII").upper()
    #     calculated_hash = result
    # except:
    #     pass
    try:
        hash = hashlib.sha1()
        with open(file, 'rb') as file:
            buffer = file.read()
            hash.update(buffer)
        calculated_hash =  hash.hexdigest().upper()
    except:
        calculated_hash = ""
    return calculated_hash

# https://www.debugpointer.com/python/create-SHA1-hash-of-a-file-in-python
def section_SHA1(file):
    hash_SHA1 = hashlib.sha1()
    
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_SHA1.update(chunk)

    return hash_SHA1.hexdigest().upper()

# Add to log file
def error_logging(output_path,error_message):
    log_file = open(output_path+"/log.txt","a")
    log_file.write(datetime.now().strftime("%d/%m/%Y %H:%M:%S") + error_message + "\n")
    log_file.close()

def mount_disk_image(arsenal_image_path,filepath):
    # Mount the disk image
    subprocess.run([arsenal_image_path,"--mount","--readonly","--filename="+filepath,"--background"])
    # Windows has decided to mount my USB stick as E: and i can't be bothered to change it
    time.sleep(10)
    potential_drive_letters = ["D:","E:","F:"]
    storage = {}
    # Cycle through mounted drive letters and get total storage for each mounted partition
    # Because it doesn't seem to work we have to assume the image is mounted to either D: F: or G:
    for drive_letter in potential_drive_letters:
        try:
            obj_Disk = psutil.disk_usage(drive_letter)
            storage[drive_letter] = float((obj_Disk.total / (1024.0 ** 3)))
        except:
            storage[drive_letter] = 0
    # Return the biggest partition
    return max(storage, key=storage.get)

def unmount_disk_image(arsenal_image_path):
    subprocess.run([arsenal_image_path,"--dismount=000000"])
    time.sleep(5)

def file_carving(photo_rec_path,carved_output_path):
    print("\nCarving files...")
    print("\nPhotoRec doesn't use command line arguments")
    print("The output you select once the tool loads has to match! "+str(carved_output_path))
    print("Or you will need to run the tool again but with -f as the input directory")
    if os.path.isdir(carved_output_path) == False:
        os.mkdir(str(carved_output_path))
    # Time out to display above text 
    time.sleep(5)
    subprocess.run(photo_rec_path)
    print("File Carve Complete! Returning to main script!")