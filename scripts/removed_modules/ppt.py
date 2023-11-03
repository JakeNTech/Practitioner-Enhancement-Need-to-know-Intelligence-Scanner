# Description: Microsoft Office 97-2007 PowerPoint Presentations.
# Author: @JakeNTech
# Dependencies: N/A
# Version: 1
# Date: 19/09/2022

from scripts import utilities
from scripts.modules.docx import docx

def ppt(file):
    this_line = []
    additional_parsing = ""
    
    metadata = utilities.fetch_hachoir(file)
    # print(metadata)

    try:
        this_line.append(metadata["creation date"])
    except:
        this_line.append("N/A")
    
    try:
        this_line.append(metadata["last modification"])
    except:
        this_line.append("N/A")

    try:
        this_line.append(metadata["title"])
    except:
        this_line.append("N/A")

    try:
        this_line.append(metadata["author"])
    except:
        this_line.append("N/A")
    
    try:
        this_line.append(metadata["numslides"])
    except:
        this_line.append("N/A")

    try:
        this_line.append(metadata["numhiddenslides"])
    except:
        this_line.append("N/A")

    try:
        this_line.append(str(metadata["totaleditingtime"]).replace(".",":"))
    except:
        this_line.append("N/A")

    try:
        this_line.append(metadata["numwords"])
    except:
        this_line.append("N/A")

    return additional_parsing, this_line

__artifacts__ = {
    "MSO ppt Identification": (
        "File Analysis",
        "creation_date,last_modification,title,author,slide_count,hidden_slide_count,total_editing_time,word_count",
        ppt)
}