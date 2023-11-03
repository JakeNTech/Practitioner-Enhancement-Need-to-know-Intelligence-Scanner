# Threats!
import json
import time
import requests
import sqlite3
import os
from datetime import datetime, timedelta

try:
    from scripts.OTXv2 import OTXv2
    from scripts.OTXv2 import IndicatorTypes
except:
    from OTXv2 import OTXv2
    from OTXv2 import IndicatorTypes

def create_threat_db():
    # create file, if one already exists delate
    if os.path.exists("./local_intelligence.sqlite"):
        os.remove("./local_intelligence.sqlite")

    conn = sqlite3.connect("./local_intelligence.sqlite")
    # connect to file
    threat_intel_db = conn.cursor()
    # create information table
    threat_intel_db.execute("CREATE TABLE tbl_known_files (SHA1_hash,filename,note)")
    threat_intel_db.execute("CREATE TABLE tbl_known_non_malicious_urls (domain,url,note)")

    # Crete Cache tables
    threat_intel_db.execute("CREATE TABLE tbl_historic_VT_url (domain,whois,last_https_certificate_date,last_analysis_date,harmless_detections,malicious_detections,suspicious_detections,undetected_detections,categories)")
    threat_intel_db.execute("CREATE TABLE tbl_historic_VT_exe_dll (SHA1_hash,times_submitted,harmless_votes,malicious_votes,meaningful_name,last_submission_date)")
    threat_intel_db.execute("CREATE TABLE tbl_historic_gps (coordinates,address_line,locality,region,town_city,country,post_code)")
    
    threat_intel_db.close()
    conn.commit()
    conn.close()

def clear_threat_intel_cache(threat_intel_db):
    # drop tables
    threat_intel_db.execute("DROP tbl_TABLE historic_VT_url")
    threat_intel_db.execute("DROP TABLE tbl_historic_VT_exe_dll")
    threat_intel_db.execute("DROP TABLE historic_gps")
    # recreate tables
    threat_intel_db.execute("CREATE tbl_TABLE tbl_historic_VT_url (domain,whois,last_https_certificate_date,last_analysis_date,harmless_detections,malicious_detections,suspicious_detections,undetected_detections,categories)")
    threat_intel_db.execute("CREATE tbl_TABLE tbl_historic_VT_exe_dll (SHA1_hash,times_submitted,harmless_votes,malicious_votes,meaningful_name,last_submission_date)")
    threat_intel_db.execute("CREATE tbl_TABLE tbl_historic_gps (coordinates,address_line,locality,region,town_city,country,post_code)")

def bulk_hasher(threat_intel_db,directory):
    # Clear table for new values
    threat_intel_db.execute("DROP TABLE tbl_known_files")
    threat_intel_db.execute("CREATE TABLE tbl_known_files (SHA1_hash,filename,note)")

    for root, dirs, files in os.walk(directory, topdown=False):
        for filename in files:
            filepath = os.path.join(root,filename)
            try:
                print(filepath)
                try:
                    # filehash = hash_item(filepath)
                    filehash = func_timeout(60,SHA1_hash,args=([str(filepath)]))
                except FunctionTimedOut:
                    error_logging("./","Timed out with file "+filepath)
                    filehash = ""
                except Exception as error:
                    error_logging("./","Error! "+filepath+" "+str(error))
                
                if filehash != "":
                # print([filehash,filename,"from Local SHA1_hash collection"])
                    threat_intel_db.execute("INSERT INTO tbL_known_files VALUES (?,?,?)",[filehash,filename,"from Local SHA1_hash collection"])
            except Exception as error:
                error_logging("./","Error! "+filepath+" "+str(error))

# Private Scan of website
def urlscan_io_scan(api_key,url):
    search_submission = requests.post('https://urlscan.io/api/v1/scan/',headers={'API-Key':api_key,'Content-Type':'application/json'}, data=json.dumps({"url": url, "visibility": "private"})).json()
    print(search_submission["api"])
    # Have to give them time to scan the site
    time.sleep(11)
    json_response = requests.get(str(search_submission["api"])).json()
    print(json_response)

# VirusTotal API handlers
def virustotal_v3_domain_report(api_key, domain): 
    try:
        response = requests.get('https://www.virustotal.com/api/v3/domains/'+domain, headers={'x-apikey': api_key}  )
        report = response.json()
    except Exception as err:
        print("[!] ERROR: Cannot obtain results from VirusTotal: {0}\n".format(err))
        time.sleep(20)
    return report
def virustotal_v3_url_report(api_key,url):
    try:
        response = requests.get('https://www.virustotal.com/api/v3/urls/'+url, headers={'x-apikey': api_key})
        report = response.json()
    except Exception as err:
        print("[!] ERROR: Cannot obtain results from VirusTotal: {0}\n".format(err))
        time.sleep(20)    
    return report
def virustotal_v3_ip_report(api_key,ip_address):
    try:
        response = requests.get('https://www.virustotal.com/api/v3/ip_addresses/'+ip_address, headers={'x-apikey': api_key})
        report = response.json()
    except Exception as err:
        print("[!] ERROR: Cannot obtain results from VirusTotal: {0}\n".format(err))
        time.sleep(20)   
    return report
def virustotal_v3_file_report(api_key, hash):
    try:
        response = requests.get('https://www.virustotal.com/api/v3/files/'+hash, headers={"accept":"application/json",'x-apikey': api_key})
        report = response.json()
    except Exception as err:
        print("[!] ERROR: Cannot obtain results from VirusTotal: {0}\n".format(err))
        time.sleep(20)
    return report   

# AlienVaultOTX
def OTX_SHA1_indicator_search(api_key,hash):
    otx = OTXv2(api_key)
    details = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA1, hash)
    return details
def OTX_domain_indicator_search(api_key,domain):
    otx = OTXv2(api_key)
    details = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)
    return details

# VirusTotal
def exe_dll_table_VT(VT_API_key,VT_timeout,VT_lookup_limit,VT_lookup_count,threat_intel_db,dfir_db):
    # if there is a exe_dll table on DFIR database, continue
    dfir_db.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='tbl_exe_dll'")
    if dfir_db.fetchone()[0] == 1 :
        # check if OSINT_exe table exists, if not make it
        dfir_db.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='tbl_VT_exe_dll'")
        if dfir_db.fetchone()[0] != 1 :
            dfir_db.execute("CREATE TABLE tbl_VT_exe_dll (SHA1_hash,times_submitted,harmless_votes,malicous_votes,meaingful_name,last_submission_date)")
    
        # Get hashes from within EXE table and format to uppercase into an array for searching
        dfir_db.execute("SELECT DISTINCT SHA1_hash FROM tbl_exe_dll")
        hashes = dfir_db.fetchall()
        parsed_hashes = []
        for i in range(0,len(hashes)):
            parsed_hashes.append(hashes[i][0].upper())
        
        # (Groom 2023) ~~(geeksforgeeks 2022)~~
        remaining_time = len(parsed_hashes)*VT_timeout
        remaining_time = timedelta(seconds = remaining_time)

        print("Hashes to check: VirusTotal "+str(len(parsed_hashes))+". Estimated time: "+str(remaining_time)+" Minutes")
        # For the parsed hashes see if it exists within local intelligence
        for hash in parsed_hashes:
            # has it been searched for before?
            threat_intel_db.execute(f"SELECT EXISTS(SELECT SHA1_hash FROM tbl_historic_VT_exe_dll WHERE SHA1_hash='"+hash+"')")
            if threat_intel_db.fetchone()[0] == 1:
                # if the hash has been searched for before fetch the details from local intelligence database and add to DFIR database
                threat_intel_db.execute("SELECT * FROM tbl_historic_VT_exe_dll WHERE SHA1_hash='"+hash+"'")
                this_line = threat_intel_db.fetchone()
            
                dfir_db.execute("INSERT INTO tbl_VT_exe_dll VALUES (?,?,?,?,?,?)",this_line)
            else:
                if VT_lookup_count < VT_lookup_limit:
                    VT_results = virustotal_v3_file_report(VT_API_key,hash)
                    if "error" in VT_results:
                        this_line = [hash,"Error",VT_results["error"]["message"],VT_results["error"]["code"],"",""]
                    else:
                        # write to array
                        this_line = [hash]
                        try:
                            this_line.append(VT_results["data"]["attributes"]["times_submitted"])
                        except:
                            this_line.append("")
                        try:
                            this_line.append(VT_results["data"]["attributes"]["last_analysis_stats"]["harmless"])
                        except:
                            this_line.append("")
                        try:
                            this_line.append(VT_results["data"]["attributes"]["last_analysis_stats"]["malicious"])
                        except:
                            this_line.append("")
                        try:
                            this_line.append(VT_results["data"]["attributes"]["meaningful_name"])
                        except:
                            this_line.append("")
                        try:
                            this_line.append(VT_results["data"]["attributes"]["last_submission_date"])
                        except:
                            this_line.append("")
                        threat_intel_db.execute("INSERT INTO tbl_historic_VT_exe_dll VALUES (?,?,?,?,?,?)",this_line)
                    
                    dfir_db.execute("INSERT INTO tbl_VT_exe_dll VALUES (?,?,?,?,?,?)",this_line)
                    time.sleep(VT_timeout)
                    VT_lookup_count = VT_lookup_count + 1
                else:
                    print("\nVirusTotal lookup limit reached!...")
                    return VT_lookup_count
    
    return VT_lookup_count

def VT_internet_history(VT_API_key,VT_timeout,VT_lookup_limit,VT_lookup_count,threat_intel_db,dfir_db):
    dfir_db.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='tbl_internet_history'")
    if dfir_db.fetchone()[0] == 1 :
        # check if OSINT table exists
        dfir_db.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='tbl_VT_url'")
        if dfir_db.fetchone()[0] != 1 :
            dfir_db.execute("CREATE TABLE tbl_VT_url (domain,whois,last_https_certificate_date,last_analysis_date,harmless_detections,malicious_detections,suspicious_detections,undetected_detections,categories)")
        
        # Get urls from within internet_history table and format to uppercase into an array for searching
        dfir_db.execute("SELECT DISTINCT domain FROM tbl_internet_history")
        domains = dfir_db.fetchall()
        
        parsed_domains = []
        for i in range(0,len(domains)):
            parsed_domains.append(domains[i][0])

        # (Groom 2023) ~~(geeksforgeeks 2022)~~
        remaining_time = len(parsed_domains)*VT_timeout
        remaining_time = timedelta(seconds = remaining_time)

        print("Domains to check on VirusTotal: "+str(len(parsed_domains))+". Estimated time: "+str(remaining_time)+" Minutes")
        
        # For the parsed hashes see if it exists within local intelligence
        for domain in parsed_domains:
            # if domain isn't on the exclusion list, has it been searched for before?
            threat_intel_db.execute(f"SELECT EXISTS(SELECT domain FROM tbl_historic_VT_url WHERE domain='"+domain+"')")
            if threat_intel_db.fetchone()[0] == 1:
                # if the domain has been searched for before fetch the details from local intelligence database and add to DFIR database
                threat_intel_db.execute("SELECT * FROM tbl_historic_VT_url WHERE domain='"+domain+"'")
                this_line = threat_intel_db.fetchone()
            
                dfir_db.execute("INSERT INTO tbl_VT_url VALUES (?,?,?,?,?,?,?,?,?)",this_line)
            else:
                if VT_lookup_count < VT_lookup_limit:
                    VT_results = virustotal_v3_domain_report(VT_API_key,domain)
                    if "error" in VT_results:
                        this_line = [domain,"Error",VT_results["error"]["message"],VT_results["error"]["code"],"","","","",""]
                    else:
                        this_line = [domain,VT_results["data"]["attributes"]["whois"],VT_results["data"]["attributes"]["last_https_certificate_date"],VT_results["data"]["attributes"]["last_analysis_date"],VT_results["data"]["attributes"]["last_analysis_stats"]["harmless"],VT_results["data"]["attributes"]["last_analysis_stats"]["malicious"],VT_results["data"]["attributes"]["last_analysis_stats"]["suspicious"],VT_results["data"]["attributes"]["last_analysis_stats"]["undetected"],str(VT_results["data"]["attributes"]["categories"])]
                        threat_intel_db.execute("INSERT INTO tbl_historic_VT_url VALUES (?,?,?,?,?,?,?,?,?)",this_line)

                    dfir_db.execute("INSERT INTO tbl_VT_url VALUES (?,?,?,?,?,?,?,?,?)",this_line)
                    time.sleep(VT_timeout)
                    VT_lookup_count = VT_lookup_count + 1
                else:
                    print("\nVirusTotal lookup limit reached!...")
                    return VT_lookup_count
    
    return VT_lookup_count

# Bing Maps
def bing_maps(API_key,threat_intel_db,dfir_db):
    # Check table doesn't already exist
    dfir_db.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='tbl_osint_gps'")
    if dfir_db.fetchone()[0] != 1 :
        dfir_db.execute("CREATE TABLE tbl_osint_gps (coordinates,address_line,locality,region,town_city,country,post_code)")

    # Get Coordinates
    dfir_db.execute("SELECT DISTINCT coordinates FROM tbl_jpg")
    coordinates = dfir_db.fetchall()
    parsed_coordinates = []
    for i in range(0,len(coordinates)):
        if coordinates[i][0] != "":
            parsed_coordinates.append(coordinates[i][0])

    # (Groom 2023) ~~(geeksforgeeks 2022)~~
    remaining_time = len(parsed_coordinates)*0.5
    remaining_time = timedelta(seconds = remaining_time)

    print("Coordinates to check on BingMaps: "+str(len(parsed_coordinates))+". Estimated time: "+str(remaining_time)+" Minutes")
    # Collect information about coordinates
    for i in range(0,len(parsed_coordinates)):
        # does it exist in local DB?
        threat_intel_db.execute(f"SELECT EXISTS(SELECT coordinates FROM tbl_historic_gps WHERE coordinates='"+parsed_coordinates[i]+"')")
        if threat_intel_db.fetchone()[0] == 1:
                threat_intel_db.execute("SELECT * FROM tbl_historic_gps WHERE coordinates='"+parsed_coordinates[i]+"'")
                this_line = threat_intel_db.fetchone()
                dfir_db.execute("INSERT INTO tbl_osint_gps VALUES (?,?,?,?,?,?,?)",this_line)
        else:
            json_response = requests.get("http://dev.virtualearth.net/REST/v1/Locations/"+parsed_coordinates[i]+"?key="+API_key).json()
            coordinates_list = json_response["resourceSets"]
            # Extract Address information
            this_line = [parsed_coordinates[i],coordinates_list[0]["resources"][0]["address"]["addressLine"],coordinates_list[0]["resources"][0]["address"]["locality"],coordinates_list[0]["resources"][0]["address"]["adminDistrict"],coordinates_list[0]["resources"][0]["address"]["adminDistrict2"],coordinates_list[0]["resources"][0]["address"]["countryRegion"],coordinates_list[0]["resources"][0]["address"]["postalCode"]]
            # Write to Output sqlite and local intelligence file
            dfir_db.execute("INSERT INTO tbl_osint_gps VALUES (?,?,?,?,?,?,?)",this_line)
            threat_intel_db.execute("INSERT INTO tbl_historic_gps VALUES (?,?,?,?,?,?,?)",this_line)

# AlienVault OTX
def exe_dll_table_OTX(OTX_API_key,dfir_db):
    # if there is a exe_dll table on DFIR database, continue
    dfir_db.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='tbl_exe_dll'")

    if dfir_db.fetchone()[0] == 1 :
        # First table for Metadata and pulses count
        dfir_db.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='tbl_otx_exe_dll_indicator'")
        if dfir_db.fetchone()[0] != 1 :
            dfir_db.execute("CREATE TABLE tbl_otx_exe_dll_indicator (SHA1_hash,cuckoo_score,file_type,file_size)")
        # Second table for Pulses
        dfir_db.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='tbl_otx_exe_pulses'")
        if dfir_db.fetchone()[0] != 1 :
            dfir_db.execute("CREATE TABLE tbl_otx_exe_pulses (SHA1_hash,otx_id,pulse_name,confidence,TLP,indicator_count,subscriber_count)")
        
        # Get hashes from within EXE table and format to uppercase into an array for searching
        dfir_db.execute("SELECT DISTINCT SHA1_hash FROM tbl_exe_dll")
        hashes = dfir_db.fetchall()
        parsed_hashes = []
        for i in range(0,len(hashes)):
            parsed_hashes.append(hashes[i][0].upper())

        # (Groom 2023) ~~(geeksforgeeks 2022)~~
        remaining_time = len(parsed_hashes)*0.5
        remaining_time = timedelta(seconds = remaining_time)

        print("Hashes to check on AlienVaultOTX: "+str(len(parsed_hashes))+". Estimated time: "+str(remaining_time)+" Minutes.")
        
        # For the parsed hashes see if it exists within local intelligence
        for hash in parsed_hashes:
            OTX_indicator = OTX_SHA1_indicator_search(OTX_API_key,hash)

            if OTX_indicator["general"]["pulse_info"]["count"] != 0:
                for pulse in OTX_indicator["general"]["pulse_info"]["pulses"]:
                    upvotes = pulse["upvotes_count"]
                    downvotes = pulse["downvotes_count"]
                    if upvotes == 0 and downvotes == 0:
                        confidence = 0
                    else:
                        confidence = (upvotes - downvotes)/upvotes
                    
                    this_pulse = [hash,pulse["id"],pulse["name"],str(confidence),pulse["TLP"],str(pulse["indicator_count"]),str(pulse["subscriber_count"])]
                    dfir_db.execute("INSERT INTO tbl_otx_exe_pulses VALUES (?,?,?,?,?,?,?)",this_pulse)
            
            try:
                analysis = OTX_indicator["analysis"]["analysis"]
                analysis_info = hash,analysis["plugins"]["cuckoo"]["result"]["info"]["score"],analysis["info"]["results"]["file_type"],analysis["info"]["results"]["filesize"]
            except:
                analysis_info = hash,"Not found on AlienVault","",""
            dfir_db.execute("INSERT INTO tbl_otx_exe_dll_indicator VALUES (?,?,?,?)",analysis_info)
            time.sleep(0.7)

def internet_history_OTX(OTX_API_key,dfir_db):
    # if there is a exe_dll table on DFIR database, continue
    dfir_db.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='tbl_internet_history'")

    if dfir_db.fetchone()[0] == 1 :
        # First table for Metadata and pulses count
        dfir_db.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='tbl_otx_url'")
        if dfir_db.fetchone()[0] != 1 :
            dfir_db.execute("CREATE TABLE tbl_otx_url (domain,ASN,city,region,DNS)")
        # Second table for Pulses
        # dfir_db.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='tbl_otx_internet_pulses'")
        # if dfir_db.fetchone()[0] != 1 :
        #     dfir_db.execute("CREATE TABLE tbl_otx_internet_pulses (domain,id,pulse_name,confidence,TLP,indicator_count,subscriber_count)")
        
        # Get hashes from within EXE table and format to uppercase into an array for searching
        dfir_db.execute("SELECT DISTINCT domain FROM tbl_internet_history")
        domains = dfir_db.fetchall()
        parsed_domains = []
        for i in range(0,len(domains)):
            parsed_domains.append(domains[i][0])

        # (Groom 2023) ~~(geeksforgeeks 2022)~~
        remaining_time = len(parsed_domains)*0.5
        remaining_time = timedelta(seconds = remaining_time)

        print("Domains to check on AlienVaultOTX: "+str(len(parsed_domains))+". Estimated time: "+str(remaining_time)+" Minutes")
        # For the parsed hashes see if it exists within local intelligence
        for domain in parsed_domains:
            OTX_indicator = OTX_domain_indicator_search(OTX_API_key,domain)

            if len(OTX_indicator["general"]["validation"]) == 0:

                # for pulse in OTX_indicator["general"]["pulse_info"]["pulses"]:
                #     upvotes = pulse["upvotes_count"]
                #     downvotes = pulse["downvotes_count"]
                #     if upvotes == 0 and downvotes == 0:
                #         confidence = 0
                #     else:
                #         confidence = (upvotes - downvotes)/upvotes
                    
                #     this_pulse = [domain,pulse["id"],pulse["name"],str(confidence),pulse["TLP"],str(pulse["indicator_count"]),str(pulse["subscriber_count"])]
                #     dfir_db.execute("INSERT INTO tbl_otx_internet_pulses VALUES (?,?,?,?,?,?,?)",this_pulse)
            
                try:
                    analysis_info = domain,OTX_indicator["general"]["geo"]["asn"],OTX_indicator["general"]["geo"]["city"],OTX_indicator["general"]["geo"]["region"],str(OTX_indicator["general"]["passive_dns"]["passive_dns"])
                except:
                    analysis_info = [domain,"Not found on AlienVault","",""]

                dfir_db.execute("INSERT INTO tbl_otx_url VALUES (?,?,?,?,?)",analysis_info)
                time.sleep(0.7)
            
            else:
                analysis_info = [domain,str(OTX_indicator["general"]["validation"]),"","",""]
                dfir_db.execute("INSERT INTO tbl_otx_url VALUES (?,?,?,?,?)",analysis_info)

def get_args():
    parser = argparse.ArgumentParser(description='Need to create a local intelligence file? Want to clear the cache? or bulk hash some stuff!')
    # Optional - used for hashing 
    parser.add_argument("--files", dest="input_directory", help="Add files in a directory/mounted disk image to the known local intelligence database.", metavar="<path>")
    # Optional - Database actions
    parser.add_argument("-i", dest="plain_OSINT", help="Run OSINT Module against existing output database", action="store_true")
    parser.add_argument("-c", dest="create_db", help="Create local intelligence database",action="store_true")
    parser.add_argument("--clear_cache", dest="clear_cache", help="Clear the stored results for VirusTotal from the local intelligence database",action="store_true")
    # Optional - Database parameters
    parser.add_argument("--config", dest="config_file", help="Load the configuration file for API keys  for running with -i", metavar="<path>",default="../config.json")
    parser.add_argument("--dfir_database", dest="dfir_database", help="Alternative filepath for the output database from main tool. Default: ../output/SQLITE_DB_OUT.sqlite", metavar="<path>", default="../output/SQLITE_DB_OUT.sqlite")

    return parser.parse_args()

if __name__ == "__main__":
    # These imports aren't needed normally needed unless running standalone
    from utilities import SHA1_hash, error_logging
    from func_timeout import func_timeout, FunctionTimedOut
    import argparse
    
    # Get command line arguments
    arguments = get_args()
    # If the user wants to create the threat_intelligence_database
    if arguments.create_db:
        create_threat_db()

    # Open the databases
    conn_threat_intel = sqlite3.connect("./local_intelligence.sqlite")
    threat_intel_db = conn_threat_intel.cursor()
    
    if arguments.clear_cache:
        clear_threat_intel_cache(threat_intel_db)

    if arguments.input_directory:
        bulk_hasher(threat_intel_db,arguments.input_directory)
    elif arguments.plain_OSINT:
        conn_results = sqlite3.connect(arguments.dfir_database)
        DFIR_results_db = conn_results.cursor()
        # Open configure file
        print("Opening and reading configuration file...")
        with open(arguments.config_file) as f:
            config_file = json.load(f)
        osint_start_time = datetime.now()
        VT_lookup_count = 0

        #VirusTotal
        if "virus_total" in config_file:
            if "vt_lookup_count" in config_file["virus_total"]:
                VT_lookup_count = config_file["virus_total"]["vt_lookup_count"]
            else:
                VT_lookup_count = 0
            
            VT_lookup_count = exe_dll_table_VT(config_file["virus_total"]["API_key"],config_file["virus_total"]["timeout"],config_file["virus_total"]["lookup_limit"],VT_lookup_count,threat_intel_db,DFIR_results_db)
            conn_results.commit()
            conn_threat_intel.commit()
            VT_lookup_count = VT_internet_history(config_file["virus_total"]["API_key"],config_file["virus_total"]["timeout"],config_file["virus_total"]["lookup_limit"],VT_lookup_count,threat_intel_db,DFIR_results_db)
            conn_results.commit()
            conn_threat_intel.commit()

        if "alien_vault_otx" in config_file:
            exe_dll_table_OTX(config_file["alien_vault_otx"]["API_key"],DFIR_results_db)
            conn_results.commit()
            internet_history_OTX(config_file["alien_vault_otx"]["API_key"],DFIR_results_db)
            conn_results.commit()
        
        # GPS
        if "bing_maps" in config_file:
            bing_maps(config_file["bing_maps"]["API_key"],threat_intel_db,DFIR_results_db)
            conn_results.commit()

        # create OSINT run table
        osint_run_time = (datetime.now()-osint_start_time).total_seconds()
        osint_run_time = timedelta(seconds = osint_run_time)
        this_row = [osint_start_time.strftime('%d/%m/%Y %H:%M:%S'),str(osint_run_time),VT_lookup_count]
        DFIR_results_db.execute("CREATE TABLE tbl_runinfo_osint (end_date_time,runtime_minutes,VirusTotal_lookups)")
        DFIR_results_db.execute("INSERT INTO tbl_runinfo_osint VALUES (?,?,?)",this_row)
        DFIR_results_db.close()
        conn_results.commit()
        conn_results.close()

    # commit and close everything
    threat_intel_db.close()
    conn_threat_intel.commit()
    conn_threat_intel.close()