# Description: Microsoft Office 97-2007 Excel spreadsheets.
# Author: @JakeNTech
# Dependencies: N/A
# Version: 1
# Date: 19/09/2022

from scripts import utilities

def xls(file):
    this_line = []
    additional_parsing = ""
    
    metadata = utilities.fetch_hachoir(file)
    # print(metadata)
    
    try:
        this_line.append(metadata['creation date'])
    except:
        this_line.append("N/A")
    
    try:
        this_line.append(metadata['last modification'])
    except:
        this_line.append("N/A")

    try:
        this_line.append(metadata['author'])
    except:
        this_line.append("N/A")

    try:
        this_line.append(metadata['security'])
    except:
        this_line.append("N/A")

    return additional_parsing, this_line

__artifacts__ = {
    "MSO XLS Identification": (
        "File Analysis",
        "creation_date,last_modification,author,security",
        xls)
}