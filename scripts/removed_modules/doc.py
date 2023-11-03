# Description: Microsoft Office 97-2007 Word Document files.
# Author: @JakeNTech
# Dependencies: N/A
# Version: 1
# Date: 19/09/2022

from scripts import utilities

def doc(file):
    this_line = []
    additional_parsing = ""
    
    metadata = utilities.fetch_hachoir(file)
    # metadata = fetch_hachoir(file)
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
        this_line.append(metadata["author"])
    except:
        this_line.append("N/A")
    
    try:
        this_line.append(metadata["nb page"])
    except:
        this_line.append("N/A")

    try:
        this_line.append(metadata["numlines"])
    except:
        this_line.append("N/A")

    try:
        this_line.append(metadata["numwords"])
    except:
        this_line.append("N/A")

    try:
        this_line.append(metadata["template"])
    except:
        this_line.append("N/A")

    return additional_parsing, this_line

__artifacts__ = {
    "MSO doc Identification": (
        "File Analysis",
        "creation_date,last_modification,author,pages,line_count,word_count,template",
        doc)
}

# if __name__ == "__main__":
#     print(doc("../../test_files/testdoc.doc"))