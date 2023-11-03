# Description: Get metadata for mp4 files
# Author: @JakeNTech
# Dependencies: tinytag
# Version: 1
# Date: 27/01/2023

from tinytag import TinyTag

def fetch_TinyTag(file):
    try:
        metadata = TinyTag.get(file)
    except Exception:
        metadata = type('obj', (object,) ,{"album":"","albumartist":"","artist":"","audio_offset":"","bitrate":"","channels":"","comment":"","composer":"","disc":"","disc_total":"","duration":"","genre":"","samplerate":"","title":"","track":"","track_total":"","year":""})
    
    return metadata

def mp4(file):
    metadata = fetch_TinyTag(file)
    this_line =[
        metadata.album,
        metadata.albumartist,
        metadata.artist,
        metadata.audio_offset,
        metadata.bitrate,
        metadata.channels,
        metadata.comment,
        metadata.composer,
        metadata.disc,
        metadata.disc_total,
        metadata.duration,
        metadata.genre,
        metadata.samplerate,
        metadata.title,
        metadata.track,
        metadata.track_total,
        metadata.year
    ]
    return "", this_line

__artifacts__ = {
    "mp4": (
        "File Analysis",
        "album,albumartist,artist,audio_offset,bitrate,channels,comment,composer,disc,disc_total,duration,genre,samplerate,title,track,track_total,year",
        mp4)
}

if __name__ == "__main__":
    print(fetch_TinyTag("../../test_files/f25.mp4"))