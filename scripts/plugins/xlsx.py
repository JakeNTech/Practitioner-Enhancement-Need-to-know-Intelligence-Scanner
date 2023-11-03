# Description: Microsoft Office 2007+ Excel spreadsheets.
# Author: @JakeNTech
# Dependencies: zipfile,xml.dom.minidom
# Version: 1
# Date: 19/09/2022

import zipfile
import xml.dom.minidom

def xlsx(file):
    this_line = []
    additional_parsing = ""

    try:
        myFile = zipfile.ZipFile(file,'r')
        doc = xml.dom.minidom.parseString(myFile.read('docProps/core.xml'))
        xml.dom.minidom.parseString(myFile.read('docProps/core.xml')).toprettyxml()

        # https://github.com/profHajal/Microsoft-Office-Documents-Metadata-with-Python/blob/main/mso_md.py

        try:
            this_line.append(str(doc.getElementsByTagName('dc:creator')[0].childNodes[0].data).replace(',','.'))
        except:
            this_line.append("N/A")

        try:
            this_line.append(str(doc.getElementsByTagName('cp:lastModifiedBy')[0].childNodes[0].data).replace(',','.'))
        except:
            this_line.append("N/A")

        try:
            this_line.append(doc.getElementsByTagName('dcterms:created')[0].childNodes[0].data.strip())
        except:
            this_line.append("N/A")

        try:
            this_line.append(doc.getElementsByTagName('dcterms:modified')[0].childNodes[0].data.strip())
        except:
            this_line.append("N/A")

    except:
        this_line = ["Failed_to_Load","N/A","N/A","N/A"]
    
    return additional_parsing, this_line

__artifacts__ = {
    "vnd.openxmlformats-officedocument.spreadsheetml.sheet": (
        "File Analysis",
        "author,last_modified_by,date_created,date_modified",
        xlsx)
}