# Description: Collect Internet history and compile into a single table
# Author: @JakeNTech
# Dependencies: N/A
# Version: 1
# Date: 20/01/2023

# Combined internet forensics stuff
import sqlite3
import datetime
import biplist
from urllib.parse import urlparse

def date_from_webkit(webkit_timestamp):
    epoch_start = datetime.datetime(1601,1,1)
    delta = datetime.timedelta(microseconds=int(webkit_timestamp))
    time = epoch_start + delta
    time = time.strftime('%d-%m-%Y %H:%M')
    return time

def chrome_history_parser(chrome_hist_db):
    # Load SQLITE database and run Query to merge urls and visits table
    con = sqlite3.connect(chrome_hist_db)
    cursor = con.cursor()
    
    #https://sqliteforensictoolkit.com/chrome-history-with-recursive-common-table-expressions/
    cursor.execute("SELECT visits.visit_time, urls.url, urls.title FROM visits LEFT JOIN urls ON visits.url = urls.id")
    history_events = cursor.fetchall()
    # Format to add to CSV file and convert WebKit date to Human Readable
    history = []
    for i in range(0,len(history_events)):
        #this_line = np.asarray(history_events[i])
        this_line = list(history_events[i])
        this_line[0] = date_from_webkit(history_events[i][0])
        if type(this_line[2]) == "str":
            this_line[2] = this_line[2].strip()
            this_line[2] = this_line[2].replace(","," ")
            this_line[2] = this_line[2].replace("\n"," ")
        
        domain = urlparse(this_line[1]).netloc
        this_line.insert(2,domain)
        this_line.append("chromium")
        history.append(this_line)
    
    return history

def mozilla_history_parser(mozilla_hist_db):
    con = sqlite3.connect(mozilla_hist_db)
    cursor = con.cursor()
    
    cursor.execute("SELECT last_visit_date, url, title FROM moz_places;")
    history_events = cursor.fetchall()

    history = []
    for i in range(0,len(history_events)):
        #this_line = np.asarray(history_events[i])
        this_line = list(history_events[i])
        if type(this_line[2]) == "str":
            this_line[1] = this_line[1].strip()
            this_line[1] = this_line[1].replace(","," ")
            this_line[1] = this_line[1].replace("\n"," ")
        
        # My Sample file has blank last_visited in
        if this_line[0] != None:
            # if timestamp is present convert from UTC
            this_line[0] = datetime.datetime.utcfromtimestamp(float(this_line[0])/1000000).strftime("%d-%m-%Y %H:%M")
        
        domain = urlparse(this_line[1]).netloc
        this_line.insert(2,domain)
        this_line.append("mozilla")
        
        history.append(this_line)
        
    return history

def safari_history_sql_parser(safari_hist_db):
    con = sqlite3.connect(safari_hist_db)
    cursor = con.cursor()

    # I am the biggest brain
    cursor.execute("SELECT history_visits.visit_time, history_items.url, history_visits.title FROM history_visits LEFT JOIN history_items ON history_items.id = history_visits.history_item")
    history_events = cursor.fetchall()

    history = []
    for i in range(0,len(history_events)):
        #this_line = np.asarray(history_events[i])
        this_line = list(history_events[i])
        if type(this_line[1]) == "str":
            this_line[1] = this_line[1].replace(","," ")
        # http://2016.padjo.org/tutorials/sqlite-your-browser-history/
        this_line[0] = datetime.datetime.utcfromtimestamp(float(this_line[0])+978307200).strftime("%d-%m-%Y %H:%M")
        
        domain = urlparse(this_line[1]).netloc
        this_line.insert(2,domain)
        this_line.append("safari_sqlite")
        
        history.append(this_line)

    return history

def parse_safari_plist_history(plist_file):
    pl = biplist.readPlist(plist_file)

    pl = pl["WebHistoryDates"]
    history = []

    for i in range(0,len(pl)):
        this_line = []

        try:
            this_line.append(datetime.datetime.utcfromtimestamp(float(pl[i]["lastVisitedDate"])+978307200).strftime("%d-%m-%Y %H:%M"))
        except:
            this_line.append("")
        
        try:
            this_line.append(pl[i][""])
        except:
            this_line.append("")

        try:
            this_line.append(pl[i]["title"])
        except:
            this_line.append("")

        domain = urlparse(this_line[1]).netloc
        this_line.insert(2,domain)
        this_line.append("safari_plist")
        
        history.append(this_line)
    
    return history

def main(internet_hist_DB,type):
    if type == "chromium_history":
        history = chrome_history_parser(internet_hist_DB)
    elif type == "mozilla_history":
        history = mozilla_history_parser(internet_hist_DB)
    elif type == "safari_history_sql":
        history = safari_history_sql_parser(internet_hist_DB)
    elif type == "safari_history_plist":
        history = parse_safari_plist_history(internet_hist_DB)
    return history

__artifacts__ = {
    "Internet History Parsing": (
        "File Parsing",
        "date_time,url,domain,title,browser_type",
        main),
}

if __name__ == "__main__":
    parse_safari_plist_history("../../test_files/f28.plist")