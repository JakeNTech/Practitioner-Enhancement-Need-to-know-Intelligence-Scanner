# Description: JPG File metadata
# Author: @JakeNTech
# Dependencies: exif
# Version: 3.1
# Date: 19/09/2022

from exif import Image
    
# https://medium.com/spatial-data-science/how-to-extract-gps-coordinates-from-images-in-python-e66e542af354
def decimal_coords(coords, ref):
    decimal_degrees = coords[0] + coords[1] / 60 + coords[2] / 3600
    if ref == "S" or ref == "W":
        decimal_degrees = -decimal_degrees
    
    return decimal_degrees

def jpg(file):
    jpg_meta = []
    additional_parsing = ""

    # Open file
    try:
        with open(file, "rb") as src:
            img = Image(src)

        if img.has_exif == False:
            jpg_meta = ["Image Failed to Load!","","","","","",""]
        
        else:
            try:
                jpg_meta.append(img["datetime"])
            except:
                jpg_meta.append("")

            try:
                jpg_meta.append(img["image_width"])
            except:
                jpg_meta.append("")
                
            try:
                jpg_meta.append(img["image_height"])
            except:
                jpg_meta.append("")

            try:
                jpg_meta.append(img["make"])
            except:
                jpg_meta.append("")

            try:
                jpg_meta.append(img["model"])
            except:
                jpg_meta.append("")

            try:
                jpg_meta.append(img["software"])
            except:
                jpg_meta.append("")

            try:
                coordinates = str(decimal_coords(img.gps_latitude,img.gps_latitude_ref))+","+str(decimal_coords(img.gps_longitude,img.gps_longitude_ref))
                # coordinates = "na"
                jpg_meta.append(coordinates)
            except:
                jpg_meta.append("")
    except:
        jpg_meta = ["Image Failed to Load!","","","","","",""]
    # Send back Year of Image for more Structured sorting
    # structured_destination = str(year)+"/"
    
    # Calculate Image Megapixels
    # image_megapixel = (image_width * image_height)/1000000
   
    # jpg_meta.append(str(image_megapixel))

    return additional_parsing, jpg_meta

__artifacts__ = {
    "jpeg": (
        "File Analysis",
        "date_time,image_width,image_height,make,model,software,coordinates",
        jpg)
}

# if __name__ == "__main__":
#     print(jpg("../../test_files/f09.jpg"))