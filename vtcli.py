import webbrowser
import requests
import json
import time
import sys
import os
#My class file
import FileHash

API_KEY = '<api_key>'


#This function uploads files
def UploadFile(Path_to_file):
    parameters = {'apikey': str(API_KEY)}
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    files = {'file': (str(Path_to_file), open(str(Path_to_file), 'rb'))}
    upload_it = requests.post(url,data=parameters,files=files)
    upload_response = upload_it.json()
    print("Uploading the file, results will be shown to you in 5 minutes(the time it takes for the file to be analysed)\nIf you're seeing a blank screen, just wait for a few more minutes and refresh the page")
    time.sleep(300)
    webbrowser.open(str(upload_response['permalink']))
#This function gets the latest report for the file
def GetFileReport(Path_to_file):

    hget = FileHash.File_Hash()
    file_HASH = hget.Discover_Hash(Path_to_file)
    parameters = {'apikey':str(API_KEY),'resource':str(file_HASH)}
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    get_file_report = requests.get(url,params=parameters)
    file_report = get_file_report.json()
    engine_count = 0
    flagged_virus = 0
    for engine in file_report['scans']:
        engine_count += 1
        print("Detection by {}:".format(engine) + str(file_report['scans'][engine]['result'])+" | Scan date: {}".format(file_report['scan_date']))
        detections = file_report['scans'][engine]['result']
        if bool(detections):
            flagged_virus+=1

    print("{}/{} of the AV engines flagged this file as a virus".format(flagged_virus, engine_count))
#This function uploads link for analysis
def UploadURL(link):
    parameters = {'apikey':str(API_KEY),'url':str(link)}
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    upload_url = requests.post(url, data=parameters)
    upload_response = upload_url.json()
    print(upload_response['verbose_msg']+"\nMeaning that you can check the results with the associated function\n It's suggested that you wait for 5 minutes(the time it takes for the URL to be analysed)")
#This function checks if a given link is malicious
def GetURLReport(link):
    parameters = {'apikey':str(API_KEY), 'resource':str(link)}
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    get_url_report = requests.get(url, params=parameters)
    url_report = get_url_report.json()
    url_engines = 0
    bad_urls = 0
    unrated_urls= 0
    for engines in url_report['scans']:
        url_engines+=1
        print("Detection by {}:".format((engines))+url_report['scans'][engines]['result']+" | Scan date: {}".format(url_report['scan_date']))
        if url_report['scans'][engines]['result'] != "clean site":
            bad_urls+=1
            if url_report['scans'][engines]['result'] == "unrated site":
                bad_urls-=1
                unrated_urls+=1
    print("\n{}/{} of the engines flagged this url as malicious and {} engines haven't rated it yet".format(bad_urls, url_engines,unrated_urls))
#----------------------------------------------------------------------------------------------------------------------
if __name__=='__main__':


      #To generate and present report file(get's the -r and -f)
    try:
        if sys.argv[1]=='':
            print("Use: {} -h".format(os.path.basename(__file__)))
        elif sys.argv[1]=='-h':
            print("""
                   Usage:
                   {} -r -f (filepath) -> This command will show you the scan results for the file
                   {} -u -f (filepath) -> This command will upload the file to Virustotal to scan it
                   {} -r -url (URL) -> This command will show you the scan results for the URL
                   {} -u -url (URL) -> This command will upload the URL to Virustotal to scan it
                   Note: You might need to select the directory that contains the file before using the commands 
                   Note2: When typing a file path, you need to type it inside quotes if it has spaces      
                   """.format(os.path.basename(__file__), os.path.basename(__file__), os.path.basename(__file__),
                              os.path.basename(__file__)))
        elif sys.argv[1]=='-r' and sys.argv[2]=='-f':
            GetFileReport(sys.argv[3])
        elif sys.argv[1]=='-u' and sys.argv[2]=='-f':
            UploadFile(sys.argv[3])
        elif sys.argv[1]=='-r' and sys.argv[2]=='-url':
            GetURLReport(sys.argv[3])
        elif sys.argv[1]=='-u' and sys.argv[2]=='-url':
            UploadURL(sys.argv[3])

    except IndexError:
        print("""
        Usage (in command line):
        {} -r -f (filepath) -> This command will show you the scan results for the file
        {} -u -f (filepath ) -> This command will upload the file to Virustotal to scan it
        {} -r -url (URL) -> This command will show you the scan results for the URL
        {} -u -url (URL) -> This command will upload the URL to Virustotal to scan it
        Note: You might need to select the directory that contains the file before using the commands
        Note2: When typing a file path, you need to type it inside quotes if it has spaces
        """.format(os.path.basename(__file__),os.path.basename(__file__),os.path.basename(__file__),os.path.basename(__file__)))
    except KeyError:
        print("This file was not found on VirusTotal database, please use the upload function to upload this file")
    except FileNotFoundError:
        print("File you're trying to upload for does not exist, please make sure path to your file is correct!\nIf path contains spaces in between folders use \" at the start and end of the path")
    except json.decoder.JSONDecodeError:
        print("The file you're trying to upload is over 32MB, this isn't allowed. This kind of big files cannot be uploaded\nPlease upload this file manualy to www.virustotal.com")
    except requests.exceptions.ConnectionError:
        print("Exceeded the request limit, try making another request. If that doesn't work, wait for a minute and then making another request/(oryou don't have internet connection)")


