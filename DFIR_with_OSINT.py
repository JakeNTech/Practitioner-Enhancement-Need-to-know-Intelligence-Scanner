# Starting with the CLI seems much easier
import argparse
import os
import sqlite3
from datetime import datetime, timedelta
import json
import magic
import ctypes
from func_timeout import func_timeout, FunctionTimedOut
# https://stackoverflow.com/questions/22029562/python-how-to-make-simple-animated-loading-while-process-is-running
import threading
import itertools
import threading
import sys
import time
# Custom scripts
import scripts.module_loader as module_loader
from scripts import utilities
from scripts import osint

def get_args():
    parser = argparse.ArgumentParser(description='FileCarve Explorer CLI. For all your snooping needs!')
    # Required - either -f -d must be used
    parser.add_argument("-f", "--files", dest="input_directory", help="Directory of files to scan.", metavar="<path>")
    parser.add_argument("-d", "--disk_image", dest="input_image_path", help="Location of disk image", metavar="<path>")
    # Optional - Sorting
    parser.add_argument("-m", "--move", dest="move", help="Move Files into sorted directory structure.", metavar="<path>")
    parser.add_argument("-c", "--copy", dest="copy", help="Copy Files into sorted directory structure.", metavar="<path>")
    # Optional - Output directory
    parser.add_argument("-o", "--output", dest="output_dir", help="output_path",metavar='<path>',default="./output")
    # Optional - Run OSINT
    parser.add_argument("-i", "--osint", dest="osint", help="Add flag to run OSINT modules",action="store_true")
    # Optional - Configuration file -> usage also implies you want to run OSINT/API stuff
    parser.add_argument("--config", dest="config_file", help="JSON config file containing API keys", metavar="<path>",default="./config.json")
    # Optional - Clear Cache in Local intelligence file
    parser.add_argument("--clear_cache", dest="clear_cache", help="Clears the cache in the local intelligence folder",action="store_true")
    # Optional - Carve files (USE FOR DISK IMAGE)
    parser.add_argument("--carve", dest="carve_files", help="Run Photorec against a disk image then analyze files. Disk image must be supplied with -d",metavar="<Output carve directory>")
    # Optional - No hashing
    parser.add_argument("--no_hash", dest="no_hash", help="Run the tool without using file hashing",action="store_true")

    return parser.parse_args()

# https://stackoverflow.com/questions/22029562/python-how-to-make-simple-animated-loading-while-process-is-running
def running(section):
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if analysis_completed:
            break
        sys.stdout.write('\r'+section+' Analysis Running ' + c)
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\rFile Identification completed!     ')

if __name__ == "__main__":
    arguments = get_args()
    start_time = datetime.now()
    module_loader = module_loader.PluginLoader()

    # Open configure file
    print("Opening and reading configuration file...")
    with open(arguments.config_file) as f:
        config_file = json.load(f)
    
    if arguments.input_directory and arguments.input_image_path:
        print("Too many arguments!")
        print("Please use -f for pointing at a directory or -d for mounting a disk image")
        exit()
     # Mount disk image if selected
    elif arguments.input_image_path:
        # Must be admin user to execute
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if is_admin == 0:
            print("\nTo mount a disk image you must run the script as Administrator!")
            print("Exiting...")
            exit()
        # hash the disk image
        print("Hashing disk image...")
        start_hash = utilities.section_SHA1(arguments.input_image_path)
        # start_hash = "bob"
        # Mount the disk image
        print("Hash complete!\nMounting Disk Image")
        if "tool_paths" in config_file and "arsenal_image_mounter" in config_file["tool_paths"]:
            # If the user has defined a path
            arsenal_image_path = config_file["tool_paths"]["arsenal_image_mounter"]
        else:
            # assume its on environment variables
            arsenal_image_path = "ami_cli.exe"
        input_directory = utilities.mount_disk_image(arsenal_image_path,arguments.input_image_path)
        # if the user wants to run file carving first
        if arguments.carve_files:
            # Has the user defined a custom path to Photorec?
            if "tool_paths" in config_file and "photo_rec" in config_file["tool_paths"]:
                photo_rec_path = config_file["tool_paths"]["photo_rec"]
            else:
                photo_rec_path = "photorec_win.exe"
            # Hand over to file utilities function
            print("Starting Photorec file carving!")
            utilities.file_carving(photo_rec_path,arguments.carve_files)
            # Use carved files instead of disk image
            input_directory = arguments.carve_files
    # If the input is a directory instead of a disk image
    elif arguments.input_directory:
        # May be able to hash a directory?
        start_hash = "N/A"
        input_directory = arguments.input_directory
    else:
        print("No Input disk image or file directory given!")
        print("Exiting...")
        exit()

    print("Creating and loading databases..")
    # Create and open SQLITE database
    # Check to see if output directory
    if os.path.exists(arguments.output_dir):
        if os.path.exists(arguments.output_dir+"/SQLITE_DB_OUT.sqlite"):
            os.rename(arguments.output_dir+"/SQLITE_DB_OUT.sqlite",f"./{arguments.output_dir}/{datetime.now().strftime('%Y-%m-%dT%H%M_%S')}_Old.sqlite")
    else:
        os.mkdir(arguments.output_dir)
    
    # Create file and open database
    conn_threat_intel = sqlite3.connect("./scripts/local_intelligence.sqlite")
    conn_results = sqlite3.connect(arguments.output_dir+"/SQLITE_DB_OUT.sqlite")
    threat_intel_db = conn_threat_intel.cursor()
    DFIR_results_db = conn_results.cursor()

    # Create initial table
    print("Creating Run table...")
    DFIR_results_db.execute("CREATE TABLE tbl_runinfo_start (start_date_time,input_path,output_path,file_action,start_hash)")
    # Define information for initial table
    if arguments.move:
        this_row = [start_time.strftime('%d/%m/%Y %H:%M:%S'),input_directory,arguments.move,"Move",start_hash]
    elif arguments.copy:
        this_row = [start_time.strftime('%d/%m/%Y %H:%M:%S'),input_directory,arguments.copy,"Copy",start_hash]
    else:
        this_row = [start_time.strftime('%d/%m/%Y %H:%M:%S'),input_directory,"N/A","Analysis",start_hash]
    # Add to table
    DFIR_results_db.execute("INSERT INTO tbl_runinfo_start VALUES (?,?,?,?,?)",this_row)

    DFIR_results_db.execute("CREATE TABLE tbl_files (SHA1_hash,filename,file_type,file_path,known,module,new_file_path)")

    print("File Identification Running...\n")

    files_analyzed = 0
    unknown_files = 0

    # https://stackoverflow.com/questions/22029562/python-how-to-make-simple-animated-loading-while-process-is-running
    analysis_completed = False
    t = threading.Thread(target=running,args=["File"])
    t.start()

    # Start looking through files
    for root, dirs, files in os.walk(input_directory, topdown=False):
        for filename in files:
            files_analyzed = files_analyzed + 1
            # get entire file path
            source_filepath = os.path.join(root,filename)
            # attempt to get file type
            try:
                file_type = magic.from_file(source_filepath, mime=True).split("/")[1]
            except:
                file_type = "N/A"

            # Initial Analysis
            for plugin in module_loader.plugins:
                if file_type == plugin.name:                   
                    if arguments.no_hash:
                        SHA1_file_hash = ""
                    else:
                        # if there is a module for the file type then hash to see if its known about
                        try:
                            SHA1_file_hash = func_timeout(60,utilities.SHA1_hash,args=([str(source_filepath)]))
                        except FunctionTimedOut:
                            utilities.error_logging(arguments.output_dir,"Timed out with file "+source_filepath)
                            SHA1_file_hash = ""
                        except Exception as error:
                            utilities.error_logging(arguments.output_dir,error)
                            exit()

                    # If file is not on known list in the local intelligence database
                    threat_intel_db.execute(f"SELECT EXISTS(SELECT SHA1_Hash from tbl_known_files WHERE SHA1_Hash='{SHA1_file_hash}')")
                    if threat_intel_db.fetchone()[0] != 1:
                        # Increase unknown file counter
                        unknown_files = unknown_files + 1

                        # Pass file to file identification module
                        additional_parsing, file_info = plugin.function(source_filepath)

                        # Add the return from the identification function to a table
                        file_info = [SHA1_file_hash] + file_info

                        # Write results to database
                        DFIR_results_db.execute(f"SELECT count(name) FROM sqlite_master WHERE type='table' AND name='tbl_{plugin.module_name}'")
                        # Check if the table exists, if not make it
                        if DFIR_results_db.fetchone()[0] != 1 :
                            DFIR_results_db.execute(f"CREATE TABLE tbl_{plugin.module_name} (SHA1_Hash,{plugin.tbl_headers})")
                        # Add the data to the table
                        value_q_marks = "?,"*(len(plugin.tbl_headers.split(","))+1)
                        DFIR_results_db.execute(f"INSERT INTO tbl_{plugin.module_name} VALUES ({value_q_marks[:-1]})",file_info)

                        # Additional Parsing
                        if additional_parsing != "":
                            for parsing_plugin in module_loader.plugins:
                                parsed = None
                                if parsing_plugin.module_name == additional_parsing.lower() and parsing_plugin.category == "File Parsing":
                                    parsed = parsing_plugin.function(source_filepath)

                                # Additional section for Internet history so it all gets added to the same table
                                elif (additional_parsing.lower() == "chromium_history" or additional_parsing.lower() == "mozilla_history" or additional_parsing.lower() == "safari_history_sql" or additional_parsing.lower() == "safari_history_plist") and parsing_plugin.module_name == "internet_history":        
                                    parsed = parsing_plugin.function(source_filepath,additional_parsing.lower())
        
                                # Additional parsing for registry files
                                elif (additional_parsing == "SOFTWARE" or additional_parsing == "NTUSER" or additional_parsing == "SYSTEM") and parsing_plugin.module_name == "registry_parser":
                                    parsed = parsing_plugin.function(source_filepath,additional_parsing)
                                
                                if parsed != None:
                                    # Add SHA1 to each row
                                    for i in range(0,len(parsed)):
                                        parsed[i].insert(0,SHA1_file_hash)

                                    # if table dont exist, make it
                                    DFIR_results_db.execute(f"SELECT count(name) FROM sqlite_master WHERE type='table' AND name='tbl_{parsing_plugin.module_name}'")
                                    if DFIR_results_db.fetchone()[0] != 1 :
                                        DFIR_results_db.execute(f"CREATE TABLE tbl_{parsing_plugin.module_name} (SHA1_hash,{parsing_plugin.tbl_headers})")
                                    
                                    # add rows to table
                                    value_q_marks = "?,"*(len(parsing_plugin.tbl_headers.split(","))+1)
                                    DFIR_results_db.executemany(f"INSERT INTO tbl_{parsing_plugin.module_name} VALUES ({value_q_marks[:-1]})",parsed)

                        # File copying/moving
                        if arguments.move:
                            target_file_path = arguments.move+"/unknown/"+str(file_type).replace(".","_")+"/"
                            utilities.move_file(source_filepath,target_file_path,filename)
                        elif arguments.copy:
                            target_file_path = arguments.copy+"/unknown/"+str(file_type).replace(".","_")+"/"
                            utilities.copy_file(source_filepath,target_file_path,filename)
                        else:
                            target_file_path = ""
                        
                        DFIR_results_db.execute("INSERT INTO tbl_files VALUES (?,?,?,?,?,?,?)",[SHA1_file_hash,filename,file_type,source_filepath,False,plugin.module_name,target_file_path+filename])
                    # else:
                    # Add file details to tbl_files if not on known list
                    # if arguments.move:
                    #     target_file_path = arguments.move+"/known/"+str(file_type).replace(".","_")+"/"
                    #     file_utilites.move_file(source_filepath,target_file_path,filename)
                    # elif arguments.copy:
                    #     target_file_path = arguments.copy+"/known/"+str(file_type).replace(".","_")+"/"
                    #     file_utilites.copy_file(source_filepath,target_file_path,filename)
                    # DFIR_results_db.execute("INSERT INTO tbl_files VALUES (?,?,?,?,?,?,?)",[SHA1_file_hash,filename,file_type,source_filepath,True,"",target_file_path+filename])

    analysis_completed = True
     
    conn_threat_intel.commit()
    conn_results.commit()
   
    file_end_time = datetime.now()
    time.sleep(0.3)
    
    if arguments.input_image_path:
        # unmount the disk image
        input_directory = utilities.unmount_disk_image(arsenal_image_path)
        # hash the disk image
        print("Hashing Disk image...")
        end_hash = utilities.section_SHA1(arguments.input_image_path)
    elif arguments.input_directory:
        end_hash = "N/A"
    # check the end hash matches with the original one
    if start_hash == end_hash:
        match = True
    else:
        match = False

    # Build row, create end table and write to the DB
    filerun_time = (file_end_time-start_time).total_seconds()
    filerun_time = timedelta(seconds = filerun_time)
    
    conn_threat_intel.commit()
    conn_results.commit()

    print("\nQuickStats!")
    print("Files Analyzed: "+str(files_analyzed)+" Unknown Files: "+str(unknown_files)+" Known Files: "+str((files_analyzed-unknown_files)))
    
    if arguments.osint:
        if arguments.clear_cache:
            osint.clear_threat_intel_cache(threat_intel_db)

        print("\n\nStarting OSINT Analysis!"+" "*30)
        osint_start_time = datetime.now()
        VT_lookup_count = 0

        #VirusTotal
        if "virus_total" in config_file:
            if "vt_lookup_count" in config_file["virus_total"]:
                VT_lookup_count = config_file["virus_total"]["vt_lookup_count"]
            else:
                VT_lookup_count = 0
            
            VT_lookup_count = osint.exe_dll_table_VT(config_file["virus_total"]["API_key"],config_file["virus_total"]["timeout"],config_file["virus_total"]["lookup_limit"],VT_lookup_count,threat_intel_db,DFIR_results_db)
            conn_results.commit()
            conn_threat_intel.commit()
            VT_lookup_count = osint.VT_internet_history(config_file["virus_total"]["API_key"],config_file["virus_total"]["timeout"],config_file["virus_total"]["lookup_limit"],VT_lookup_count,threat_intel_db,DFIR_results_db)
            conn_results.commit()
            conn_threat_intel.commit()

        if "alien_vault_otx" in config_file:
            osint.exe_dll_table_OTX(config_file["alien_vault_otx"]["API_key"],DFIR_results_db)
            conn_results.commit()
            osint.internet_history_OTX(config_file["alien_vault_otx"]["API_key"],DFIR_results_db)
            conn_results.commit()
        
        # GPS
        if "bing_maps" in config_file:
            osint.bing_maps(config_file["bing_maps"]["API_key"],threat_intel_db,DFIR_results_db)
            conn_results.commit()

        # create OSINT run table
        print("\nOSINT Scanning complete! Creating end table...")
        osint_run_time = (datetime.now()-osint_start_time).total_seconds()
        osint_run_time = timedelta(seconds = osint_run_time)
        this_row = [osint_start_time.strftime('%d/%m/%Y %H:%M:%S'),str(osint_run_time),VT_lookup_count]
        DFIR_results_db.execute("CREATE TABLE tbl_runinfo_osint (end_date_time,runtime_minutes,VirusTotal_lookups)")
        DFIR_results_db.execute("INSERT INTO tbl_runinfo_osint VALUES (?,?,?)",this_row)

    # End the things
    print("\nScript complete! Creating end running information and closing databases...")
    total_end_time = datetime.now()
    total_runtime = (total_end_time-start_time).total_seconds()
    total_runtime = timedelta(seconds = total_runtime)
    this_row = [total_end_time.strftime('%d/%m/%Y %H:%M:%S'),str(filerun_time),str(total_runtime),files_analyzed,unknown_files,(files_analyzed-unknown_files),end_hash,match]
    DFIR_results_db.execute("CREATE TABLE tbl_runinfo_end (end_date_time,file_analysis_runtime,total_runtime,files_analyzed,unknown_files,known_files,hash,match_with_initial_hash)")
    DFIR_results_db.execute("INSERT INTO tbl_runinfo_end VALUES (?,?,?,?,?,?,?,?)",this_row)

    threat_intel_db.close()
    DFIR_results_db.close()
    conn_threat_intel.commit()
    conn_threat_intel.close()
    conn_results.commit()
    conn_results.close()
    
    print("\nExiting!")