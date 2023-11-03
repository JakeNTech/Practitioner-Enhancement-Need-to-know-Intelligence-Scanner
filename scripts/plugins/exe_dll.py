# Description: EXE metadata scraper
# Author: @JakeNTech
# Dependencies: file_utilites
# Version: 1
# Date: 25/09/2022

from scripts import utilities
# from scripts import threat_intelligence

def exe(file):
    this_line = []
    additional_parsing = ""
   
    metadata = utilities.fetch_hachoir(file)
    # Title,Author,Version,CreationDate,Copyright
    try:
        this_line.append(metadata.get('title'))
    except:
        this_line.append("N/A")

    try:
        this_line.append(metadata.get('author'))
    except:
        this_line.append("N/A")
    
    try:
        this_line.append(metadata.get('version'))
    except:
        this_line.append("N/A")
    
    try:
        this_line.append(metadata.get('creation_date'))
    except:
        this_line.append("N/A")
    
    try:
        this_line.append(metadata.get('copyright'))
    except:
        this_line.append("N/A")

    return additional_parsing, this_line

__artifacts__ = {
    "x-dosexec": (
        "File Analysis",
        "title,author,version,creation_date,copyright",
        exe)
}