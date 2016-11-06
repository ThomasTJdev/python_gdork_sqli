# Find SQL injections

 This python script is developed to show, how many vulnerables websites,
 which are laying around on the web. The main focus of the script is to
 generate a list of vuln urls. Please use the script with causing and
 alert the webadmins of vulnerable pages. The SQLmap implementation is
 just for showcasing.

## Requirements
* python3
* BeautifulSoup from bs4
* (optional) sqlmap

## The script
 The script is divided into 3 main sections.
 
### Section 1
   In this section you'll have to provide a search string, which 'connects' to
   the websites database, e.g. 'php?id='. The script then crawls
   Bing or Google for urls containing it. All of the urls can then be saved
   into a file. (Please be aware that you might get banned for crawling to
   fast, remember an appropriate break/sleep between request).
   *Example of searchs: php?bookid=, php?idproduct=, php?bookid=, php?catid=,*
                       *php?action=, php?cart_id=, php?title=, php?itemid=*

### Section 2
   This section adds a qoute ' to the websites url. If the website is
   prone to SQL injection, we'll catch this with some predefined error
   messages. The script will not add websites for blind SQL injections,
   due to the predefined error messages.

### Section 3
   This is just an activation of sqlmap with the bulk argument and no
   user interaction for validation of SQL injection.


**Stay safe and help the vulnerables**
