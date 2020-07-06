#!/usr/bin/python

import os
import xml.sax
import xlsxwriter

path = '/mnt/c/Users/ron/Downloads/NessusParserPython'
Host = 0                   #Initialize the host variable.  This will count total number of hosts.
tagID = ""                 #Initialize the tagID string. This will hold the attribute name of "tag" IE: <tag name="Host End"> This holds Host End.
descriptList =[]           #Initialization of List to hold each line of the description. 
solutionList =[]           #Initialization of List to hold each line of the solution.
synopsisList =[]           #Initialization of List to hold each line of the synopsis.
plugin_outputList =[]      #Initialization of List to hold each line of the plugin_output.
complianceNameList = []
complianceResultList = []
workbook = ""
homeWorksheet = ""
hostScanData = ""
exploits = ""
critical = ""
high = ""
medium = ""
low = ""
compliance = ""
bigfix = ""
anti_virus = ""
informational = ""
criticalRow = 2
highRow = 2
mediumRow = 2
lowRow = 2
bigfixRow = 2
anti_virusRow = 2
tagRow = 2
RIrow = 2
informationalRow = 2
pluginOutputRow = 2
synopsisCount = 1
complianceNameCount = 2
complianceResultCount = 2
descriptionCount = 1
format = ""
synopsisSwitch = ""
descriptionSwitch = ""
startElementOS = ""
startElementIP = ""
startElementFQDN = ""
startElementMAC = ""
exploitColor = ""
lowHost = 0
bigfixHost = 0
anti_virusHost = 0
mediumHost = 0
highHost = 0
informationalHost = 0
criticalHost = 0
publicExploits = 0
        
class MovieHandler( xml.sax.ContentHandler ):
    def __init__(self):
        self.CurrentData = ""
        self.tag = ""
        self.description = ""
        self.risk_factor = ""
        self.exploit_available = ""
        self.compliance_check_name = ""
        self.compliance_result = ""
        self.PRICE = ""
        self.YEAR = ""

    # Call when an element starts... happens when it hits first < of a tag
    def startElement(self, tag, attributes):
        global Host
        global tagID
        global RIrow                                                    # Report Item index integer.  This makes the rows change so data can be printed down excel
        global lowRow
        global mediumRow
        global highRow
        global criticalRow
        global informationalRow
        global startElementOS
        global startElementIP 
        global startElementFQDN
        global startElementMAC
        global lowHost
        global bigfixHost
        global anti_virusHost
        global bigfixRow
        global anti_virusRow
        global mediumHost
        global highHost
        global criticalHost
        global informationalHost
        self.CurrentData = tag
        if tag == "ReportHost":                                         #This is true when the XML tag is called ReportHost
            print ("* * * * * I have a host * * * * * ")
            hName = attributes["name"]
            #print "Host Name:", hName
            Host = Host + 1
        if tag == "tag":                                                #This is true when the XML tag is actually called tag.
            tagID = attributes["name"]                                  #Stores the attribute name into tagID... see explanation at beginning of code
        if tag == "ReportItem":
            print ("* * * * * Report Item * * * * *")
            port = attributes["port"]                                   #Open Ports reported by nessus
            svc_name = attributes["svc_name"]                           #Service running on the port
            protocol = attributes["protocol"]                           #TCP or UDP protocol
            severity = attributes["severity"]                           #0-5, informational, low, medium, high, critical
            pluginID = attributes["pluginID"]                           #plugin ID used from nessus
            pluginName = attributes["pluginName"]                       #plugin Name used from
            pluginFamily = attributes["pluginFamily"]
            #print "Report Item:", "Port", port, "Service Name", svc_name, "Protocol", protocol, "Severity", severity, "PlugIn ID", pluginID, "PlugIn Name", pluginName
            hostScanData.write(RIrow, 7, port)
            hostScanData.write(RIrow, 6, protocol)
            hostScanData.write(RIrow, 8, severity)
            hostScanData.write(RIrow, 5, pluginID)
            hostScanData.write(RIrow, 9, pluginName)
            hostScanData.write(RIrow, 3, startElementOS)
            hostScanData.write(RIrow, 1, startElementIP)
            hostScanData.write(RIrow, 2, startElementFQDN)
            hostScanData.write(RIrow, 4, startElementMAC)
            hostScanData.write(RIrow, 0, filename)
            exploits.write(RIrow, 7, port)
            exploits.write(RIrow, 6, protocol)
            exploits.write(RIrow, 8, severity)
            exploits.write(RIrow, 5, pluginID)
            exploits.write(RIrow, 9, pluginName)
            exploits.write(RIrow, 3, startElementOS)
            exploits.write(RIrow, 1, startElementIP)
            exploits.write(RIrow, 2, startElementFQDN)
            exploits.write(RIrow, 4, startElementMAC)
            exploits.write(RIrow, 0, filename)
            #startElementFQDN = ''
            if pluginID == "62561" or pluginID == "55817":
                bigfix.write(bigfixRow, 7, port)
                bigfix.write(bigfixRow, 6, protocol)
                bigfix.write(bigfixRow, 8, severity)
                bigfix.write(bigfixRow, 5, pluginID)
                bigfix.write(bigfixRow, 9, pluginName)
                bigfix.write(bigfixRow, 3, startElementOS)
                bigfix.write(bigfixRow, 1, startElementIP)
                bigfix.write(bigfixRow, 2, startElementFQDN)
                bigfix.write(bigfixRow, 4, startElementMAC)
                bigfix.write(bigfixRow, 0, filename)
                bigfixRow += 1
                bigfixHost += 1
                #startElementFQDN = ''
            elif pluginID == "12107":
                anti_virus.write(anti_virusRow, 7, port)
                anti_virus.write(anti_virusRow, 6, protocol)
                anti_virus.write(anti_virusRow, 8, severity)
                anti_virus.write(anti_virusRow, 5, pluginID)
                anti_virus.write(anti_virusRow, 9, pluginName)
                anti_virus.write(anti_virusRow, 3, startElementOS)
                anti_virus.write(anti_virusRow, 1, startElementIP)
                anti_virus.write(anti_virusRow, 2, startElementFQDN)
                anti_virus.write(anti_virusRow, 4, startElementMAC)
                anti_virus.write(anti_virusRow, 0, filename)
                anti_virusRow += 1
                anti_virusHost += 1
                #startElementFQDN = ''
            elif severity == "0":
                informational.write(informationalRow, 7, port)
                informational.write(informationalRow, 6, protocol)
                informational.write(informationalRow, 8, severity)
                informational.write(informationalRow, 5, pluginID)
                informational.write(informationalRow, 9, pluginName)
                informational.write(informationalRow, 3, startElementOS)
                informational.write(informationalRow, 1, startElementIP)
                informational.write(informationalRow, 2, startElementFQDN)
                informational.write(informationalRow, 4, startElementMAC)
                informational.write(informationalRow, 0, filename)
                informationalRow += 1
                informationalHost += 1
                startElementFQDN = ''
            elif severity == "1":
                low.write(lowRow, 7, port)
                low.write(lowRow, 6, protocol)
                low.write(lowRow, 8, severity)
                low.write(lowRow, 5, pluginID)
                low.write(lowRow, 9, pluginName)
                low.write(lowRow, 3, startElementOS)
                low.write(lowRow, 1, startElementIP)
                low.write(lowRow, 2, startElementFQDN)
                low.write(lowRow, 4, startElementMAC)
                low.write(lowRow, 0, filename)
                lowRow += 1
                lowHost += 1
                startElementFQDN = ''
            elif severity == "2":
                medium.write(mediumRow, 7, port)
                medium.write(mediumRow, 6, protocol)
                medium.write(mediumRow, 8, severity)
                medium.write(mediumRow, 5, pluginID)
                medium.write(mediumRow, 9, pluginName)
                medium.write(mediumRow, 3, startElementOS)
                medium.write(mediumRow, 1, startElementIP)
                medium.write(mediumRow, 2, startElementFQDN)
                medium.write(mediumRow, 4, startElementMAC)
                medium.write(mediumRow, 0, filename)
                mediumRow += 1
                mediumHost += 1
                startElementFQDN = ''
            elif severity == "3":
                high.write(highRow, 7, port)
                high.write(highRow, 6, protocol)
                high.write(highRow, 8, severity)
                high.write(highRow, 5, pluginID)
                high.write(highRow, 9, pluginName)
                high.write(highRow, 3, startElementOS)
                high.write(highRow, 1, startElementIP)
                high.write(highRow, 2, startElementFQDN)
                high.write(highRow, 4, startElementMAC)
                high.write(highRow, 0, filename)
                highRow += 1
                highHost += 1
                startElementFQDN = ''
            elif severity == "4":
                critical.write(criticalRow, 7, port)
                critical.write(criticalRow, 6, protocol)
                critical.write(criticalRow, 8, severity)
                critical.write(criticalRow, 5, pluginID)
                critical.write(criticalRow, 9, pluginName)
                critical.write(criticalRow, 3, startElementOS)
                critical.write(criticalRow, 1, startElementIP)
                critical.write(criticalRow, 2, startElementFQDN)
                critical.write(criticalRow, 4, startElementMAC)
                critical.write(criticalRow, 0, filename)
                criticalRow += 1
                criticalHost += 1
                startElementFQDN = ''
            
            RIrow += 1                                                  #add one to RIrow so the row can increase down the excel page (RI is for ReportItem)
            
    # Call when an elements ends... happens when hits the /someword> of a tag
    def endElement(self, tag):
        global tagID    
        global descriptList
        global solutionList
        global synopsisList
        global complianceNameList
        global complianceResultList
        global plugin_outputList
        global hostScanData
        global tagRow
        global pluginOutputRow
        global format
        global startElementOS 
        global startElementIP
        global startElementFQDN
        global startElementMAC
        global synopsisSwitch
        global descriptionsSwitch
        global synopsisCount
        global complianceResultCount
        global complianceNameCount
        global descriptionCount
        global descriptionSwitch
        global exploitColor
        global publicExploits
        
        if self.CurrentData == "tag":
            if tagID == "operating-system":                             #Uses tagID from above to store attribute name. Allows me to print specific info.
                #print "Operating System:", self.tag                    #For tags that have attribute and more information. The information is in self.tag
                startElementOS = self.tag                               #stores content in startElementOS variable so it can be called above and printed for repeating rows
            elif tagID == "host-ip":
                #print "Host IP:", self.tag
                startElementIP = self.tag                               #stores content in startElementIP variable so it can be called above and printed for repeating rows
            elif tagID == "host-fqdn":
                #print "FQDN:", self.tag
                startElementFQDN = self.tag                             #stores content in startElementFQDN variable so it can be called above and printed for repeating rows
            elif tagID == "mac-address":
                #print "Mac Address:", self.tag
                startElementMAC = self.tag                              #stores content in startElementMAC variable so it can be called above and printed for repeating rows
            elif tagID == "nothing":
                print ("HOW DID YOU GET HERE?")
        elif self.CurrentData == "description":
            descriptionSentence = ""
            print ("Description:"),
            descriptionSentence = " ".join(descriptList)
            #print descriptionSentence
            #print ""
            descriptList = []                                           #After printing everything it sets descriptList back to empty so the next list starts clean
            descriptionCount += 1
            descriptionSwitch = "on"
        elif self.CurrentData == "risk_factor":
                        print ("Risk Factor:"),
            #print "Risk Factor:", self.risk_factor                     #Print the Risk Factor
        elif self.CurrentData == "solution":
            solutionSentence = ""
            #print "Solution:",
            solutionsSentence = " ".join(solutionList)
            #print solutionSentence
            #print ""
            solutionList = []                                           #After printing everything it sets solutionList back to empty so the next list starts clean
        elif self.CurrentData == "cm:compliance-check-name":
            complianceName = ""
            complianceName = " ".join(complianceNameList)
            complianceTab.write(complianceNameCount, 0, complianceName, format)
            complianceNameList = []
            complianceNameCount += 1
        elif self.CurrentData == "cm:compliance-result":
            complianceResult = ""
            complianceResult = " ".join(complianceResultList)
            complianceTab.write(complianceResultCount, 1, complianceResult, format)
            complianceResultList = []
            complianceResultCount += 1
        elif self.CurrentData == "synopsis":
            synopsisSentence = ""                                       #String created to hold the synopsis tag contents
            #print "Synopsis:",                                         #For loop to print everything in the list. comma is needed to print in one line.
            synopsisSentence = " ".join(synopsisList)                   #Concatenates the items in the list and makes them one long string
            #print synopsisSentence
            #print ""
            synopsisList = []                                           #After printing everything it sets synopsisList back to empty so the next list starts clean
            synopsisCount += 1
            synopsisSwitch = "on"
        elif self.CurrentData == "plugin_output" or synopsisSwitch == "on":
            if self.CurrentData == "plugin_output":
                plugin_outputSentence = ""
                #print "Plugin Output:",                                #For loop to print everything in the list. comma is needed to print in one line.
                plugin_outputSentence = " ".join(plugin_outputList)     #Concatenates the items in the list and makes them one long string
                hostScanData.write(synopsisCount, 10, plugin_outputSentence, format)
                pluginOutputRow += 1                                    #increases row by one 
                #print ""
                plugin_outputList = []                                  #After printing everything it sets plugin_outputList back to empty so the next list starts clean
                synopsisSwitch = "off"
            else:
                plugin_outputSentence = "N/A"
                hostScanData.write(synopsisCount, 10, plugin_outputSentence, format)
                pluginOutputRow = synopsisCount
                plugin_outputList = []
                synopsisSwitch = "off"
        elif self.CurrentData == "exploit_available" or descriptionSwitch == "on":
            if self.CurrentData == "exploit_available":
                #print "Exploit Available",                             #For loop to print everything in the list. comma is needed to print in one line.
                if self.exploit_available == "true":
                    exploits.write(descriptionCount, 10, self.exploit_available, exploitColor)
                    publicExploits += 1
                else:
                    exploits.write(descriptionCount, 10, self.exploit_available, format)
                #print ""
                descriptionSwitch = "off"
            else:
                exploit_availableSentence = "N/A"
                exploits.write(descriptionCount, 10, exploit_availableSentence, format)
                descriptionSwitch = "off"
        
        self.CurrentData = ""

    # Call when a character is read
    def characters(self, content):
        global descriptList
        if self.CurrentData == "tag":
            self.tag = content
        elif self.CurrentData == "description":                            
            self.description = content                                  #Stores content into self.description
            descriptList.append(self.description)                       #Adds the sentence in self.description to the list descriptList
        elif self.CurrentData == "risk_factor":
            self.risk_factor = content                                  #Store contents of Risk Factor tag into self.risk_factor
        elif self.CurrentData == "solution":                            
            self.solution = content                                     #Stores content into self.solution
            solutionList.append(self.solution)                          #Adds the sentence in self.solution to the list solutionList
        elif self.CurrentData == "synopsis":                            
            self.synopsis = content                                     #Stores content into self.synopsis
            synopsisList.append(self.synopsis)                          #Adds the sentence in self.synopsis to the list synopsisList
        elif self.CurrentData == "cm:compliance-check-name":
            self.compliance_check_name = content
            complianceNameList.append(self.compliance_check_name)
        elif self.CurrentData == "cm:compliance-result":
            self.compliance_result = content
            complianceResultList.append(self.compliance_result)
        elif self.CurrentData == "plugin_output":                            
            self.plugin_output = content                                #Stores content into self.plugin_output
            plugin_outputList.append(self.plugin_output)                #Adds the sentence in self.plugin_output to the list plugin_outputList
        elif self.CurrentData == "exploit_available":
            self.exploit_available = content
            
    # Call at when the report is ready to be generated
    def reportOpen(reportName):
        global workbook
        global homeWorksheet
        global hostScanData
        global exploits
        global critical
        global high
        global medium
        global low
        global bigfix
        global informational
        global anti_virus
        global complianceTab
        global exploitColor
        
        workbook = xlsxwriter.Workbook('Report.xlsx', {'constant memory': True})
        format = workbook.add_format({'text_wrap':True})                #sets format to text wrap so data fits in cell
        exploitColor = workbook.add_format()
        exploitColor.set_bg_color('red')
        titleBarColor = workbook.add_format()
        titleBarColor.set_bg_color('#939393')
        homeWorksheet = workbook.add_worksheet('Home Worksheet')
        hostScanData = workbook.add_worksheet('Host Scan Data')
        exploits = workbook.add_worksheet('Exploits')
        critical = workbook.add_worksheet('Critical')
        high = workbook.add_worksheet('High')
        medium = workbook.add_worksheet('Medium')
        low = workbook.add_worksheet('Low')
        informational = workbook.add_worksheet('Informational')
        bigfix = workbook.add_worksheet('BigFix')
        anti_virus = workbook.add_worksheet('Anti-Virus')
        complianceTab = workbook.add_worksheet('Compliance')
        
        critical.set_tab_color('red')
        high.set_tab_color('purple')
        medium.set_tab_color('orange')
        low.set_tab_color('yellow')
        informational.set_tab_color('green')
                
        homeWorksheet.set_column('A:A', 45)
        hostScanData.set_column('A:A', 15)
        hostScanData.set_column('B:B', 13)
        hostScanData.set_column('C:C', 23)
        hostScanData.set_column('D:D', 25)
        hostScanData.set_column('E:E', 25)
        hostScanData.set_column('F:F', 8)
        hostScanData.set_column('H:H', 5)
        hostScanData.set_column('I:I', 8)
        hostScanData.set_column('J:J', 40)
        hostScanData.set_column('K:K', 90)
        exploits.set_column('A:A', 15)
        exploits.set_column('B:B', 13)
        exploits.set_column('C:C', 23)
        exploits.set_column('D:D', 25)
        exploits.set_column('E:E', 25)
        exploits.set_column('F:F', 8)
        exploits.set_column('H:H', 5)
        exploits.set_column('I:I', 8)
        exploits.set_column('J:J', 40)
        exploits.set_column('K:K', 20)
        critical.set_column('A:A', 15)
        critical.set_column('B:B', 13)
        critical.set_column('C:C', 23)
        critical.set_column('D:D', 25)
        critical.set_column('E:E', 25)
        critical.set_column('F:F', 8)
        critical.set_column('H:H', 5)
        critical.set_column('I:I', 8)
        critical.set_column('J:J', 40)
        high.set_column('A:A', 15)
        high.set_column('B:B', 13)
        high.set_column('C:C', 23)
        high.set_column('D:D', 25)
        high.set_column('E:E', 25)
        high.set_column('F:F', 8)
        high.set_column('H:H', 5)
        high.set_column('I:I', 8)
        high.set_column('J:J', 40)
        medium.set_column('A:A', 15)
        medium.set_column('B:B', 13)
        medium.set_column('C:C', 23)
        medium.set_column('D:D', 25)
        medium.set_column('E:E', 25)
        medium.set_column('F:F', 8)
        medium.set_column('H:H', 5)
        medium.set_column('I:I', 8)
        medium.set_column('J:J', 40)
        low.set_column('A:A', 15)
        low.set_column('B:B', 13)
        low.set_column('C:C', 23)
        low.set_column('D:D', 25)
        low.set_column('E:E', 25)
        low.set_column('F:F', 8)
        low.set_column('H:H', 5)
        low.set_column('I:I', 8)
        low.set_column('J:J', 40)
        informational.set_column('A:A', 15)
        informational.set_column('B:B', 13)
        informational.set_column('C:C', 23)
        informational.set_column('D:D', 25)
        informational.set_column('E:E', 25)
        informational.set_column('F:F', 8)
        informational.set_column('H:H', 5)
        informational.set_column('I:I', 8)
        informational.set_column('J:J', 40)
        bigfix.set_column('A:A', 15)
        bigfix.set_column('B:B', 13)
        bigfix.set_column('C:C', 23)
        bigfix.set_column('D:D', 25)
        bigfix.set_column('E:E', 25)
        bigfix.set_column('F:F', 8)
        bigfix.set_column('H:H', 5)
        bigfix.set_column('I:I', 8)
        bigfix.set_column('J:J', 40)
        anti_virus.set_column('A:A', 15)
        anti_virus.set_column('B:B', 13)
        anti_virus.set_column('C:C', 23)
        anti_virus.set_column('D:D', 25)
        anti_virus.set_column('E:E', 25)
        anti_virus.set_column('F:F', 8)
        anti_virus.set_column('H:H', 5)
        anti_virus.set_column('I:I', 8)
        anti_virus.set_column('J:J', 40)
        complianceTab.set_column('A:A', 22)
        complianceTab.set_column('B:B', 17)
                
        homeWorksheet.write('A1', 'Total number of discovered systems')
        homeWorksheet.write('A3', 'Total count of Critical Severity Vulnerabilities')
        homeWorksheet.write('A4', 'Total count of High Severity Vulnerabilities')
        homeWorksheet.write('A5', 'Total count of Medium Severity Vulnerabilities')
        homeWorksheet.write('A6', 'Total count of Low Severity Vulnerabilities')
        homeWorksheet.write('A8', 'Total hosts scanned missing BigFix')
        homeWorksheet.write('A9', 'Total hosts scanned with out of date Anti-Virus')
        homeWorksheet.write('A11', 'Total public exploits available')
        
        
        hostScanData.write('A2', 'File', titleBarColor)
        hostScanData.write('B2', 'IP Address', titleBarColor)
        hostScanData.write('C2', 'FQDN', titleBarColor)
        hostScanData.write('D2', 'Operating System', titleBarColor)
        hostScanData.write('E2', 'Mac Address', titleBarColor)
        hostScanData.write('F2', 'Pugin ID', titleBarColor)
        hostScanData.write('G2', 'Protocol', titleBarColor)
        hostScanData.write('H2', 'Port', titleBarColor)
        hostScanData.write('I2', 'Severity', titleBarColor)
        hostScanData.write('J2', 'Plugin Name', titleBarColor)
        hostScanData.write('K2', 'Plugin Output', titleBarColor)
        
        exploits.write('A2', 'File', titleBarColor)
        exploits.write('B2', 'IP Address', titleBarColor)
        exploits.write('C2', 'FQDN', titleBarColor)
        exploits.write('D2', 'Operating System', titleBarColor)
        exploits.write('E2', 'Mac Address', titleBarColor)
        exploits.write('F2', 'Pugin ID', titleBarColor)
        exploits.write('G2', 'Protocol', titleBarColor)
        exploits.write('H2', 'Port', titleBarColor)
        exploits.write('I2', 'Severity', titleBarColor)
        exploits.write('J2', 'Plugin Name', titleBarColor)
        exploits.write('K2', 'Exploits Available', titleBarColor)
        
        low.write('A2', 'File', titleBarColor)
        low.write('B2', 'IP Address', titleBarColor)
        low.write('C2', 'FQDN', titleBarColor)
        low.write('D2', 'Operating System', titleBarColor)
        low.write('E2', 'Mac Address', titleBarColor)
        low.write('F2', 'Pugin ID', titleBarColor)
        low.write('G2', 'Protocol', titleBarColor)
        low.write('H2', 'Port', titleBarColor)
        low.write('I2', 'Severity', titleBarColor)
        low.write('J2', 'Plugin Name', titleBarColor)
        
        medium.write('A2', 'File', titleBarColor)
        medium.write('B2', 'IP Address', titleBarColor)
        medium.write('C2', 'FQDN', titleBarColor)
        medium.write('D2', 'Operating System', titleBarColor)
        medium.write('E2', 'Mac Address', titleBarColor)
        medium.write('F2', 'Pugin ID', titleBarColor)
        medium.write('G2', 'Protocol', titleBarColor)
        medium.write('H2', 'Port', titleBarColor)
        medium.write('I2', 'Severity', titleBarColor)
        medium.write('J2', 'Plugin Name', titleBarColor)
        
        high.write('A2', 'File', titleBarColor)
        high.write('B2', 'IP Address', titleBarColor)
        high.write('C2', 'FQDN', titleBarColor)
        high.write('D2', 'Operating System', titleBarColor)
        high.write('E2', 'Mac Address', titleBarColor)
        high.write('F2', 'Pugin ID', titleBarColor)
        high.write('G2', 'Protocol', titleBarColor)
        high.write('H2', 'Port', titleBarColor)
        high.write('I2', 'Severity', titleBarColor)
        high.write('J2', 'Plugin Name', titleBarColor)
        
        critical.write('A2', 'File', titleBarColor)
        critical.write('B2', 'IP Address', titleBarColor)
        critical.write('C2', 'FQDN', titleBarColor)
        critical.write('D2', 'Operating System', titleBarColor)
        critical.write('E2', 'Mac Address', titleBarColor)
        critical.write('F2', 'Pugin ID', titleBarColor)
        critical.write('G2', 'Protocol', titleBarColor)
        critical.write('H2', 'Port', titleBarColor)
        critical.write('I2', 'Severity', titleBarColor)
        critical.write('J2', 'Plugin Name', titleBarColor)
        
        informational.write('A2', 'File', titleBarColor)
        informational.write('B2', 'IP Address', titleBarColor)
        informational.write('C2', 'FQDN', titleBarColor)
        informational.write('D2', 'Operating System', titleBarColor)
        informational.write('E2', 'Mac Address', titleBarColor)
        informational.write('F2', 'Pugin ID', titleBarColor)
        informational.write('G2', 'Protocol', titleBarColor)
        informational.write('H2', 'Port', titleBarColor)
        informational.write('I2', 'Severity', titleBarColor)
        informational.write('J2', 'Plugin Name', titleBarColor)
        
        bigfix.write('A2', 'File', titleBarColor)
        bigfix.write('B2', 'IP Address', titleBarColor)
        bigfix.write('C2', 'FQDN', titleBarColor)
        bigfix.write('D2', 'Operating System', titleBarColor)
        bigfix.write('E2', 'Mac Address', titleBarColor)
        bigfix.write('F2', 'Pugin ID', titleBarColor)
        bigfix.write('G2', 'Protocol', titleBarColor)
        bigfix.write('H2', 'Port', titleBarColor)
        bigfix.write('I2', 'Severity', titleBarColor)
        bigfix.write('J2', 'Plugin Name', titleBarColor)
        
        anti_virus.write('A2', 'File', titleBarColor)
        anti_virus.write('B2', 'IP Address', titleBarColor)
        anti_virus.write('C2', 'FQDN', titleBarColor)
        anti_virus.write('D2', 'Operating System', titleBarColor)
        anti_virus.write('E2', 'Mac Address', titleBarColor)
        anti_virus.write('F2', 'Pugin ID', titleBarColor)
        anti_virus.write('G2', 'Protocol', titleBarColor)
        anti_virus.write('H2', 'Port', titleBarColor)
        anti_virus.write('I2', 'Severity', titleBarColor)
        anti_virus.write('J2', 'Plugin Name', titleBarColor)

        complianceTab.write('A2', 'Compliance Check Name', titleBarColor)
        complianceTab.write('B2', 'Compliance Result', titleBarColor)
    
    
    def reportClose(reportName):
        global workbook
        workbook.close()
        
    
        
if ( __name__ == "__main__"):

    # create an XMLReader
    parser = xml.sax.make_parser()    
    # turn off namepsaces
    parser.setFeature(xml.sax.handler.feature_namespaces, 0)
    
    # override the default ContextHandler
    Handler = MovieHandler()
    parser.setContentHandler( Handler )
    MovieHandler().reportOpen()
    for filename in os.listdir(path):
        if not filename.endswith('.nessus'): continue
        fullname = os.path.join(path, filename)
        parser.parse(fullname)
        homeWorksheet.write('B1', Host)
        homeWorksheet.write('B3', criticalHost)
        homeWorksheet.write('B4', highHost)
        homeWorksheet.write('B5', mediumHost)
        homeWorksheet.write('B6', lowHost)
        homeWorksheet.write('B9', anti_virusHost)
        missingBigFix = Host - bigfixHost
        homeWorksheet.write('B8', missingBigFix)
        homeWorksheet.write ('B11', publicExploits)
        print ("Total Host:"), Host
    MovieHandler().reportClose()
