# Description: plist identification
# Author: @JakeNTech
# Dependencies: biplist
# Version: 1
# Date: 17/09/2022

import biplist

# https://docs.python.org/3/library/plistlib.html#plistlib.load
def plist_loader(plist_file):
    # Determine if file is Binary PLIST or XML Plist -> Not needed for PhotoRec Output
    # this_file = open(plist_file,"rb")
    # hex_header = binascii.hexlify(this_file.read()[0:12]).decode("utf-8")
    # this_file.close()
    # if hex_header.upper() == "62706C697374":
    #     decoded_header = "BPLIST"
    # else:
    #     decoded_header = "XML"
    try:
        #pl = plistlib.readPlist(plist_file)
        pl = biplist.readPlist(plist_file)
    except Exception as e :
        pl = {"Failed_To_Load":e}
    return pl

# Identify Plist_Files when run against a directory
def plist(file):
    additional_parsing = ""
    
    pl = plist_loader(file)

    # additional_information set to blank before to make it nicer to work with
    additional_information = ""

    # For when the PLIST don't work
    if pl is None or pl is str:
        return "Failed_To_Load"

    if "Failed_To_Load" in pl:
        return "Failed_To_Load"

    elif "List of known networks" in pl:
        identified_type = "com.apple.wifi.plist"
    
    elif "RegistrationInfo" in pl:
        identified_type = "AppleSetupDone"
        try:
            additional_information = f"ExistingEmailAddress: {pl['Address']['ExistingEmailAddress']} FirstName: {pl['Address']['FirstName']} LastName: {pl['Address']['LastName']}"
        except:
            pass
    
    elif "mailboxes" in pl:
        identified_type = "BackupTOC_Mail"
        try:
            additional_information = f"Path: {pl['mailboxes'][0]['mailboxes'][0]['path']}"
        except:
            pass

    elif "PANDevices" in pl and "ControllerPowerState" in pl:
        identified_type = "com.apple.Bluetooth"

    elif "persistent-others" in pl:
        identified_type = "com.apple.dock"

    elif "Devices" in pl:
        identified_type = "com.apple.iPod"

    elif "SessionItems" in pl:
        identified_type = "com.apple.loginitems"

    elif "lastUser" in pl and "RetriesUntilHint" in pl and "lastUserName" in pl:
        identified_type = "com.apple.loginwindow"

    elif "MailShowToDos" in pl and "InboxViewerAttributes" in pl:
        identified_type = "com.apple.mail"

    elif "RecentApplications" in pl:
        identified_type = "com.apple.recentitems"

    elif "LastDisplayedWelcomePageVersionString" in pl and "CachedBookmarksFileDateSeconds" in pl and "RecentSearchStrings" in pl:
        identified_type = "com.apple.Safari"
        try:
            additional_information = f"Recent_Searches: {pl['RecentSearchStrings']}"
        except:
            pass

    elif "useritems" in pl:
        identified_type = "com.apple.sidebarlists"

    elif "LastSuccessfulDate" in pl and "LastAttemptDate" in pl:
        identified_type = "com.apple.SoftwareUpdate"

    elif "ExcludeByPath" in pl:
        identified_type = "com.apple.TimeMachine"

    elif "com.apple.springing.delay" in pl and "AppleLocale" in pl and "AppleLanguages" in pl and "AppleScrollAnimationEnabled" in pl:
        identified_type = "GlobalPreferences.plist"

    elif "WebHistoryFileVersion" in pl and "WebHistoryDates":
        identified_type = "Safari_History_Plist"
        additional_parsing = "Safari_History_Plist"

    elif "SessionVersion" in pl and "SessionWindows" in pl:
        identified_type = "Safari_LastSession"


    elif "DisplayedSitesLastModified" in pl and "BannedURLStrings" in pl:
        identified_type = "Safari_TopSites"

    else:
        identified_type = "Unidentified_file"

    this_line = [identified_type,additional_information]
    return additional_parsing, this_line

__artifacts__ = {
    "plist Identification": (
        "File Analysis",
        "identified_type,additional_info",
        plist)
}