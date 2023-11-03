# Description: MOV metadata extraction
# Author: @JakeNTech
# Dependencies: N/A
# Version: 1
# Date: 27/01/2023

from scripts import utilities

def mov(file):
    this_line = []
        
    metadata = utilities.fetch_hachoir(file)
    #filename,size(KB),CreteDate,Duration,ImageSize
    try:
        this_line.append(metadata.get('creation_date'))
    except:
        this_line.append("N/A")

    try:
        this_line.append(metadata.get('duration'))
    except:
        this_line.append("N/A")
    
    try:
        this_line.append(f"{metadata.get('image_height')}X{metadata.get('image_width')}")
    except:
        this_line.append("N/A")

    return "",this_line

__artifacts__ = {
    "quicktime": (
        "File Analysis",
        "creation_date,duration,dimensions",
        mov)
}