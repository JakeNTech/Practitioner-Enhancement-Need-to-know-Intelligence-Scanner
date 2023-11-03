# Description: I do alot of cool things sometimes
# Author: @JakeNTech
# Dependencies: tinytag
# Version: 1
# Date: 26/11/2022

from tinytag import TinyTag
import json

def fetch_TinyTag(file):
    try:
        metadata = TinyTag.get(file)
    except Exception:
        metadata = type('obj', (object,) ,{"album":"","albumartist":"","artist":"","audio_offset":"","bitrate":"","channels":"","comment":"","composer":"","disc":"","disc_total":"","duration":"","genre":"","samplerate":"","title":"","track":"","track_total":"","year":""})
    
    return metadata

def mp3(file):
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
    "mpeg": (
        "File Analysis",
        "album,album_artist,artist,audio_offset,bitrate,channels,comment,composer,disc,disc_total,duration,genre,sample_rate,title,track,track_total,year",
        mp3)
}

if __name__ == "__main__":
    print(fetch_TinyTag("../../test_files/f26.mov"))