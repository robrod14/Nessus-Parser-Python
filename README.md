# Nessus-Parser-Python
Python Nessus Parser

This is my first python code and I am sure there are easier ways to code what I did.  I was hoping people could chime in and make the code look cleaner but still have the same ability to run on any size nessus files.

The purpose of this Nessus Parser is to read in any Nessus file, No matter how big the file is, and parse the data into something useable in excel.  I have seen many parsers but my Nesus files get very big and at times i have to consolidate several nessus scans that can total 7+ Gigs at a time.  The XML parser used is SAX and used on purpose so the system will not run out of memory.  I also used XlsxWriter so the computer doesn't run out of memory.  Currently the only issue I have is with excel running out of rows, but I just group my scans in a small enough size to fit excel.

What Does NEssus-Parser-Python produce?
At the end of the scan you will get a file called Report.xlsx (you must have office installed on your computer). The "Home Worksheet" displays Total Number of Systems discovered, Total count of Critical Vulnerabilities, Total count of High Vulnerabilities, Total count of Medium Vulnerabilities, Total count of Low Vulnerabilities, Total hosts missing BigFix,  Total hosts scanned with out of date mcafee, and Totla public exploits available.

The data is then spread out on different tabs, with Host Scan Data giving you all the vulnerabilities found, Exploits tab showing you which vulnerabilities have exploits and then a Critical, High, Modium, Low, and informational break down.

With this data, pivot tables, and filters you can gather all open ports and total count of insecure ports.  You can gather how many systems have certain operating systems and find unsupported operating systems, Top 10 Critical, High, Medium, and low vulnerabilities.  
The possibilities go on and on if you know how to manipulate the data.  For what i need this for it works perfect.

TO RUN THIS PROGRAM
You need to install "XlsxWriter-master.zip"
You need to have Excel installed on the computer
Create a folder on the desktop and place the Nessus_parser_1.0.py inside
Place all Nessus Files inside the same folder
Edit Nessus_parser_1.0.py line 7 path = 'path\to\your\files'
double click file or in command prompt type: python nessus_parser_1.0.py
A command prompt will appear just let file run until finished. Once done you should have a new folder called Report.xlsx

Future Designs:
Would like to make the exploit tab only have the vulnerabilities with Public Exploits and not everything.
Would like to create a tab for all unsupported software found during the scan
Would like to add a compliance tab
Would like to add a tab for out of date or missing patches
Would like to add the ability to injest Webinspect scans and Appdetective scans
Would like a tab for Plugin ID's found that mean system was compromised or could be very easily (like plugin ID 73026)
