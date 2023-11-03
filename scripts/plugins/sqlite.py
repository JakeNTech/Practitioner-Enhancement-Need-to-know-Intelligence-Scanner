# Description: Identify and parse SQLite Files
# Author: @JakeNTech
# Dependencies: sqlite3
# Version: 1
# Date: 17/09/2022

import sqlite3

def get_tables_python(file):
    try:
        con = sqlite3.connect(file)
        cursor = con.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        table_names = []
        #print(''.join(tables[0]))
        for table in tables:
            table_names.append(''.join(table).upper())
    except:
        table_names = ["Failed to Load SQLite"]
    return table_names

def sqlite(file):
    SQL_tables = get_tables_python(file)
    this_sql_type = ""
    
    # Chromium SQLite
    if "COOKIES" in SQL_tables:
        this_sql_type = "Chromium_Cookies"
    elif "VISITS" and "URLS" in SQL_tables:
        this_sql_type = "Chromium_history"
    elif "AUTOFILL" and "CREDIT_CARDS" in SQL_tables:
        this_sql_type = "Chromium_Autofill"
    
    # Mac OS X related SQLite files
    elif "LSQUARANTINEEVENT" in SQL_tables:
        this_sql_type = "MacOS_Download_History"
    elif "ZPUSHNOTIFICATIONENVIRONMENT" and "ZPUSHNOTIFICATION" in SQL_tables:
        this_sql_type = "itunesstored_private"
    elif "ALARM" and "EVENT" and "CALENDAR" in SQL_tables:
        this_sql_type = "MacOS_Calender"
    elif "ZICAUTHOR" and "Z_12NOTES" and "ZICNOTECHANGE" in SQL_tables:
        this_sql_type = "MacOS_Notes"
    elif "ACCOUNTSEXCHANGE" and "CONTACTS" and "O365GROUPS" in SQL_tables:
        this_sql_type = "MacOS_MSO_Outook"
    elif "ZFLOW" and "ZNETWORKATTACHMENT" and "ZLIVEUSAGE" in SQL_tables:
        this_sql_type = "MacOS_Netusage"
    elif "ZACCOUNT" and "ZCREDENTIALITEM" and "Z_1OWNINGACCOUNTTYPES" in SQL_tables:
        this_sql_type = "MacOS_Accounts"
    elif "ZICLOCATION" and "ZICNOTEDATA" and "ACHANGE" in SQL_tables:
        this_sql_type = "MacOS_NoteStore"
    elif "Z_PRIMARYKEY" and "Z_METADATA" and "Z_MODELCACHE" and "ZSUBSCRIPTION" in SQL_tables:
        this_sql_type = "MacOS_VSSubscriptions"

    # Safari SQLITE
    elif "HISTORY_VISITS" and "HISTORY_ITEMS" in SQL_tables:
        this_sql_type = "Safari_History_sql"
       
    #Mozilla Firefox related SQLite files
    elif "MOZ_PLACES" and "MOZ_HISTORYVISITS" in SQL_tables:
        this_sql_type = "Mozilla_History"
    elif "MOZ_COOKIES" in SQL_tables:
        this_sql_type = "Mozilla_Cookies"
    elif "MOZ_FORMHISTORY" and "MOZ_DELETED_FORMHISTORY" in SQL_tables:
        this_sql_type = "Mozilla_AutoComplete_History"
    elif "MOZ_PERMS" and "MOZ_HOSTS" in SQL_tables:
        this_sql_type = "Mozilla_Permissions"
    # Everything I don't know what they are ;)        
    else:
        this_sql_type = "Unknown"
    
    return this_sql_type, [this_sql_type," ".join(SQL_tables)]
    
__artifacts__ = {
    "x-sqlite3": (
        "File Analysis",
        "identified_type,sql_tables",
        sqlite),
}