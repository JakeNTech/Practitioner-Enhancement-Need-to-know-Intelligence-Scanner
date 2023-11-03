# forensic_analysis_with_OSINT
A tool to compare a disk image/file set to a known "clean" set with options to check unknown files on VirusTotal and AlienVault OTX.
This was a tool created as part of the final project (dissertation) for BSc (Hons) Forensic Computing and Security at Bournemouth University.

## Features
-   REG file type detection
-   Media Metadata collection
-   Internet Browser History Identification and Parsing
-   Other files sorted via type (Although commented out by default)
-   OSINT Source scanning (Will need to get your own API key)
    - VirusTotal, AlienVault OTX
- Disk image mounting

## Requirements
Developed with Python 3.9.2. Other versions of Python 3 *should* work but with no guarantee. Designed for usage on a Windows host, although may work on Linux if you don't want to mount a disk image.
### Dependencies
The required libraries and modules can be found in the `requirements.txt`. To install:
```console
$ pip3 install -r requirements.txt
```
Additionally Arsenal Image Mounter is required if you wish to mount a disk image, API keys for VirusTotal and AlienVault otx are also needed if you with to check files and URL's on those sources.

## CLI Usage
This is a command line based tool, although that may change!\
Below is a command used for testing the test directory against OSINT sources:
```console
> python .\DFIR_with_OSINT.py -f .\test_files\ --config .\test_config.json -i
> python .\DFIR_with_OSINT.py -d ..\test_image.E01 --config .\test_config.json -i --carve .\PhotoRec_Output
```

### Help
```console
> python .\DFIR_with_OSINT.py -h
usage: DFIR_with_OSINT.py [-h] [-f <path>] [-d <path>] [-m <path>] [-c <path>] [-o <path>] [-i] [--config <path>] [--clear_cache] [--carve <Output carve directory>]

FileCarve Explorer CLI. For all your snooping needs!

optional arguments:
  -h, --help            show this help message and exit
  -f <path>, --files <path>
                        Directory of files to scan.
  -d <path>, --disk_image <path>
                        Location of disk image
  -m <path>, --move <path>
                        Move Files into sorted directory structure.
  -c <path>, --copy <path>
                        Copy Files into sorted directory structure.
  -o <path>, --output <path>
                        output_path
  -i, --osint           Add flag to run OSINT modules
  --config <path>       JSON config file containing API keys
  --clear_cache         Clears the cache in the local intelligence folder
  --carve <Output carve directory>
                        Run Photorec against a disk image then analyze files. Disk image must be supplied with -d
```

## Make your own!
What makes this version better then the previous one is to make it easier if someone wants to add more file types for analysis or expand on the parsing.\
Everything is now a module rather then hard coded, because I am the biggest brain brain and keep thinking of stuff to add. So to make it quicker to add stuff im spending more time redoing everything. I have all the logic. Don't question me.\

### Module file templates
There are two types of template:
-   File Analysis
    -   E.G. Take an SQLite file and work out what that is a SQLite for (e.g. Chrome History)
-   File Parsing
    -   Take a known file and get some more information from it (e.g. Extract information from Chrome history file)
#### File Analysis
```python
# Description: I do alot of cool things sometimes
# Author: its me. keith.
# Dependencies: N/A
# Version: 69
# Date: yesterday

def main_function(file):
    data =["Chromium_history","META URLS SQLITE_SEQUENCE VISITS VISIT_SOURCE KEYWORD_SEARCH_TERMS DOWNLOADS DOWNLOADS_URL_CHAINS DOWNLOADS_SLICES DOWNLOADS_REROUTE_INFO SEGMENTS SEGMENT_USAGE TYPED_URL_SYNC_METADATA CONTENT_ANNOTATIONS CONTEXT_ANNOTATIONS CLUSTERS CLUSTERS_AND_VISITS"]
    additional_parsing = "Chromium_history"
    return additional_parsing, data

__artifacts__ = {
    "<magic_file_type>": (
        "File Analysis",
        "<sqlite_table_headers>",
        main_function)
}
```
#### File Parsing
```python
# Description: I do alot of cool things sometimes
# Author: its me. keith.
# Dependencies: N/A
# Version: 69
# Date: yesterday

def main_function(file):
    data = [["row1"],["row2"]]
    return data

__artifacts__ = {
    "<Artefact> Parsing": (
        "File Parsing",
        "<sqlite_table_headers>",
        main_function)
}
```

### SQL Commands
```sql
-- Join VirusTotal EXE and file names together
SELECT DISTINCT SHA1_hash, filename, times_submitted, harmless_votes, malicous_votes 
    FROM (SELECT tbl_VT_exe_dll.*, tbl_files.filename FROM tbl_VT_exe_dll 
    JOIN tbl_files on tbl_VT_exe_dll.SHA1 = tbl_files.SHA1_hash)
-- Join OTX Inidcator and file names together
SELECT tbl_otx_dll_exe_indicator.*, tbl_files.filename FROM tbl_otx_dll_exe_indicator
    JOIN tbl_files on tbl_otx_dll_exe_indicator.SHA1 = tbl_files.SHA1_hash 
    WHERE tbl_otx_dll_exe_indicator.cuckoo_score != "Not found on AlienVault"
```