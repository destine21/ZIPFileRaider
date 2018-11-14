# encoding: utf-8
from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from burp import IContextMenuFactory
from burp import IParameter
from StringIO import StringIO
from zipfile import ZipFile
from shutil import rmtree, make_archive, copytree, copy
from java.awt import GridLayout, Component, Color
from java.util import ArrayList
from javax.swing import JSplitPane, JTabbedPane, JButton, JPanel, JLabel, JTextArea, JList, BoxLayout, DefaultListModel, JScrollPane, JMenuItem, JTextField, JCheckBox
from jarray import array
from javax.swing.text import DefaultHighlighter
from time import sleep
import base64
import os
import threading

EXTENDER_FLAG = "zipFileRaiderFl4g"
ZIP_NAME = "myZip"
SCAN_ZIP_NAME = "myScanZip"
TEMP_PATH = "zipFileRaider" + os.sep + "tmp"
SCAN_TEMP_PATH = "zipFileRaider" + os.sep + "scan_tmp"
RUNNING_SCAN_PATH = "zipFileRaider" + os.sep + "running_scan_tmp"
INSETION_POINT_SYMBOL = u"§inserti0nP0int§"
PAYLOAD_PARAM_NAME = "extenderPayl0ad%d"
PAYLOAD_FILENAME = "extenderPayl0ad_filename"

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):

    #
    # implement IBurpExtender
    #

    def	registerExtenderCallbacks(self, callbacks):
        self.isLock = False
        self.magicParam = None
        self.scanMagicParam = None
        self.scanMessageInfo = None
        self.repeaterMessageInfo = None
        self.currentScanItem = None
        self.scanInsertionPoint = {}

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        self._callbacks = callbacks
        # set our extension name
        callbacks.setExtensionName("ZIP File Raider")
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        # register context menu
        callbacks.registerContextMenuFactory(self)

        self.initGUI()
        callbacks.addSuiteTab(self)
        print "[+]Init burp extender"

    ## implement IContextMenuFactory
    def createMenuItems(self, invocation):
        #get only  selected message
        self.messageInfo = invocation.getSelectedMessages()[0]
        menuItemList = ArrayList()
        menuItemList.add(JMenuItem("Send request to ZIP File Raider extender Repeater", actionPerformed = self.contextRepeaterClick))
        menuItemList.add(JMenuItem("Send request to ZIP File Raider extender Scanner", actionPerformed = self.contextScannerClick))
        return menuItemList

    def contextRepeaterClick(self, event):
        self.sendRequestToExtender("Repeater")

    def contextScannerClick(self, event):
        self.sendRequestToExtender("Scanner")

    def sendRequestToExtender(self, tab):
        #get filename
        zipfilename = "Archive(default_name).zip"
        filenameParam = self._helpers.getRequestParameter(self.messageInfo.getRequest(), "filename")
        if filenameParam == None:
            print "This request is not contain upload file"
            return
        if filenameParam.getType() == IParameter.PARAM_MULTIPART_ATTR:
            zipfilename = filenameParam.getValue()

        #get magicparam
        requestString = self._helpers.bytesToString(self.messageInfo.getRequest())
        magicParamStart, magicParamEnd = None, None

        initialIndex = filenameParam.getValueStart() - 12
        for i in range(initialIndex, 0 , -1):
            if requestString[i] == '"' :
                if magicParamEnd == None:
                    magicParamEnd = i
                elif requestString[i-6:i] == " name=":
                    magicParamStart = i + 1
                    break

        if magicParamStart == None:
            print "[-]Cannot detect file parameter name"
            return
        else:
            magicparam = requestString[magicParamStart:magicParamEnd]

        dataParameter = self._helpers.getRequestParameter(self.messageInfo.getRequest(), magicparam)
        #Check is zip upload or not
        if not dataParameter is None:
            value = dataParameter.getValue()
            if tab == "Repeater":
                self.repeaterMessageInfo = self.messageInfo
                self.extractZipFile(value, TEMP_PATH)
                self.showListFileDir(TEMP_PATH)
                self.repeaterZipFilename = zipfilename
                self.magicParam = magicparam
            else:
                self.removeDirectory(RUNNING_SCAN_PATH)
                self.scanTemplateFileName = []
                self.insertionPointCount = 0
                self.scanMessageInfo = self.messageInfo
                self.extractZipFile(value, SCAN_TEMP_PATH)
                self.showScanListFileDir(SCAN_TEMP_PATH)
                self.scanZipFilename = zipfilename
                self.scanMagicParam = magicparam
        else:
            print "no data param"

    ## implement IHttpListener
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if not messageIsRequest:
            return

        extenderFlag = self._helpers.getRequestParameter(messageInfo.getRequest(), EXTENDER_FLAG)

        if not extenderFlag is None:

            while self.isLock:
                sleep(0.5)
                # print "sleep"
                pass 
            self.isLock = True

            payloads = []

            for i in range(0, self.insertionPointCount):
                paramData = self._helpers.getRequestParameter(messageInfo.getRequest(), PAYLOAD_PARAM_NAME % i)
                try:
                    payloads.append(paramData.getValue())
                except Exception as e :
                    payloads.append("")

            payloadsIndex = 0

            for template in self.scanTemplateFileName:
                newFileContent = ""

                fileContentString = self._helpers.bytesToString(self.runningScanTemplate[template])
                contentStrings = fileContentString.split(INSETION_POINT_SYMBOL)
                for i, s in enumerate(contentStrings):
                    newFileContent += s
                    if i == len(contentStrings) - 1:
                        break
                    else:
                        newFileContent += payloads[payloadsIndex]
                        payloadsIndex += 1

                newFileContent = self._helpers.stringToBytes(newFileContent)
                try:
                    self.writeFile(RUNNING_SCAN_PATH + os.sep + template, newFileContent)
                except Exception as e :
                    print "Error1 %s" % e

            # ZipAndGo
            try:
                self.compressToZip(SCAN_ZIP_NAME, RUNNING_SCAN_PATH + os.sep + SCAN_TEMP_PATH)
                zipContent = self.readFile(SCAN_ZIP_NAME + ".zip")
                newRequest = self._helpers.updateParameter(messageInfo.getRequest(), self._helpers.buildParameter(self.scanMagicParam, zipContent, IParameter.PARAM_BODY))

                # add filename
                if self.isScanZipFilename:
                    filenamePayload = self._helpers.getRequestParameter(messageInfo.getRequest(), PAYLOAD_FILENAME).getValue()
                    newRequest = self.addMultipartFilenameParam(filenamePayload ,newRequest, self.scanMagicParam)
                    newRequest = self._helpers.removeParameter(newRequest, self._helpers.buildParameter(PAYLOAD_FILENAME, "none", IParameter.PARAM_BODY))
                else:
                    newRequest = self.addMultipartFilenameParam(self.scanZipFilename ,newRequest, self.scanMagicParam)
                
                #remove unnecessary param
                for i in range(0, self.insertionPointCount):
                    newRequest = self._helpers.removeParameter(newRequest, self._helpers.buildParameter(PAYLOAD_PARAM_NAME%i, "none", IParameter.PARAM_BODY))
                newRequest = self._helpers.removeParameter(newRequest, self._helpers.buildParameter(EXTENDER_FLAG, "none", IParameter.PARAM_BODY))
                
                # set to newRequest
                messageInfo.setRequest(newRequest)
            except Exception as e :
                print "Error2 %s" % e

            # print "[+]request sent"
            self.isLock = False
            return

        else:
            # not from our extender
            return

    def extractZipFile(self, data, des_path):
        b = base64.b64encode(data)
        zipfile = ZipFile(StringIO(base64.b64decode(b)))
        # remove tmp folder
        self.removeDirectory(des_path)
        zipfile.extractall(des_path)
        print "[*]extract done"

    def compressToZip(self, zipnName, zipDirPath):
        make_archive(zipnName, "zip", zipDirPath)
        return

    def removeDirectory(self, rm_path):
        if not os.path.exists(rm_path):
            return
        try:
            rmtree(rm_path)
        except Exception as e :
            print "[-]Error while remove %s folder %s" % (rm_path, e)

    def showListFileDir(self, mypath):
        self.filename = []
        self.fileDirList = []
        self.absFilePath = {}
        for root, dirs, files in os.walk(mypath):
            path = root.split(os.sep)
            fname = os.path.basename(root)
            dirPath = (len(path) - 3) * "---" + fname
            self.fileDirList.append(dirPath)
            self.filename.append(fname)
            for file in files:
                filePath = (len(path)-2) * "---" + file
                self.fileDirList.append(filePath)
                self.filename.append(file)
                self.absFilePath[filePath] = root + os.sep + file
        self.fileDirList.remove(TEMP_PATH.split(os.sep)[1])
        self.filename.remove(TEMP_PATH.split(os.sep)[1])
        self.dirList.setListData(self.fileDirList)

    def showScanListFileDir(self, mypath):
        self.scanFilename = []
        self.scanFileDirList = []
        self.scanAbsFilePath = {}
        for root, dirs, files in os.walk(mypath):
            path = root.split(os.sep)
            fname = os.path.basename(root)
            dirPath = (len(path) - 3) * "---" + fname
            self.scanFileDirList.append(dirPath)
            self.scanFilename.append(fname)
            for file in files:
                filePath = (len(path)-2) * "---" + file
                self.scanFileDirList.append(filePath)
                self.scanFilename.append(file)
                self.scanAbsFilePath[filePath] = root + os.sep + file
        self.scanFileDirList.remove(SCAN_TEMP_PATH.split(os.sep)[1])
        self.scanFilename.remove(SCAN_TEMP_PATH.split(os.sep)[1])
        self.scanDirList.setListData(self.scanFileDirList)

    def listSelect(self, event):
        index = self.dirList.selectedIndex
        key = self.fileDirList[index]
        self.lblFilename.text = self.filename[index]
        if key in self.absFilePath:
            self.editField.setMessage(self.readFile(self.absFilePath[key]), False)
        else:
            #dir
            self.editField.setMessage("/*Directory*/", False)

    def scanListSelect(self, event):
        index = self.scanDirList.selectedIndex
        key = self.scanFileDirList[index]
        self.scanLblFilename.text = self.scanFilename[index]
        if key in self.scanAbsFilePath:
            #file
            if self.scanAbsFilePath[key] in self.scanTemplateFileName:
                content = self.readFile(self.scanAbsFilePath[key])
                for idx, el in enumerate(self.scanInsertionPoint[self.scanAbsFilePath[key]]):
                    # print el
                    content = self.setInsertionMark(content, el[0] + idx*2, el[1] + idx*2)
                self.scanEditField.setMessage(content, False)
            else:
                self.scanEditField.setMessage(self.readFile(self.scanAbsFilePath[key]), False)
        else:
            #dir
            self.scanEditField.setMessage("/*Directory*/", False)

    def readFile(self, path):
        file = open(path, "rb")
        fileContent = file.read()
        file.close()
        return fileContent

    def writeFile(self, path, content):
        file = open(path, "wb")
        file.write(content)
        file.close()

    def updateContentLength(self, request):
        request = self._helpers.addParameter(request, self._helpers.buildParameter("dump", "none", IParameter.PARAM_BODY))
        request = self._helpers.removeParameter(request, self._helpers.buildParameter("dump", "none", IParameter.PARAM_BODY))
        return request

    def addMultipartFilenameParam(self, zipfilename, request, magicparam):
        dataParameter = self._helpers.getRequestParameter(request, magicparam)
        getFilenameOffset = dataParameter.getNameEnd() + 1

        filename = '; filename="%s"' % zipfilename
        try:
            requestString = self._helpers.bytesToString(request)
            requestString = requestString[:getFilenameOffset] + filename + requestString[getFilenameOffset:]
            request = self._helpers.stringToBytes(requestString)
            request = self.updateContentLength(request)
            return request
        except Exception as e :
            print(e)
            return

    def makeRequest(self, zipContent):
        print "[+]thread is running (making request)"
        request = self.repeaterMessageInfo.getRequest()
        request = self._helpers.updateParameter(request, self._helpers.buildParameter(self.magicParam, zipContent, IParameter.PARAM_BODY))
        
        # add filename
        request = self.addMultipartFilenameParam(self.repeaterZipFilename ,request, self.magicParam)

        # sending request
        result = self._callbacks.makeHttpRequest(self.repeaterMessageInfo.getHttpService(), request)
        self.requestPanel.setMessage(result.getRequest(), True)
        try:
            self.responsePanel.setMessage(result.getResponse(), False)
        except Exception as e :
            self.responsePanel.setMessage("An error occured", False)
        print "[+]done"

    def btnGoClick(self, event):
        if self.repeaterMessageInfo == None:
            return
        self.saveEditFile()
        self.compressToZip(ZIP_NAME, TEMP_PATH)
        zipContent = self.readFile(ZIP_NAME + ".zip")

        t1 = threading.Thread(target=self.makeRequest, args=[zipContent])
        t1.start()
        # print "[+]thread start"

    def saveEditFile(self):
        if self.repeaterMessageInfo == None:
            return
        index = self.dirList.selectedIndex
        key = self.fileDirList[index]

        if key in self.absFilePath:
            #file
            content = self.editField.getMessage()
            self.writeFile(self.absFilePath[key], content)

    def btnSaveClick(self, event):
        self.saveEditFile()

    def btnClearClick(self, event):
        self.dirList.setListData([])
        self.editField.setMessage("", False)
        self.lblFilename.text = "File name"
        self.requestPanel.setMessage("", True)
        self.responsePanel.setMessage("", False)
        self.repeaterMessageInfo = None
        self.removeDirectory(TEMP_PATH)

    def btnResetRepeaterClick(self, event):
        print "btnClick"
        if self.repeaterMessageInfo == None:
            print "return"
            return
        dataParameter = self._helpers.getRequestParameter(self.repeaterMessageInfo.getRequest(), self.magicParam)
        value = dataParameter.getValue()
        # print value
        self.extractZipFile(value, TEMP_PATH)
        # self.sendRequestToExtender("Repeater")
        self.listSelect(event)

    def scanBtnClearClick(self, event):
        self.scanTemplateFileName = []
        self.scanInsertionPoint = {}
        self.insertionPointCount = 0
        self.scanDirList.setListData([])
        self.scanEditField.setMessage("", False)
        self.scanLblFilename.text = "File name"
        self.scanMessageInfo = None
        self.removeDirectory(SCAN_TEMP_PATH)
        self.removeDirectory(RUNNING_SCAN_PATH)

    def scanBtnClearInsClick(self, event):
        self.scanTemplateFileName = []
        self.scanInsertionPoint = {}
        self.insertionPointCount = 0
        self.removeDirectory(RUNNING_SCAN_PATH)
        self.scanListSelect(event)

    def addInsertionPoint(self, insStart, insEnd):
        index = self.scanDirList.selectedIndex
        key = self.scanFileDirList[index]

        if key in self.scanAbsFilePath:
            #file
            if not self.scanAbsFilePath[key] in self.scanTemplateFileName:
                self.scanTemplateFileName.append(self.scanAbsFilePath[key])
                self.scanInsertionPoint[self.scanAbsFilePath[key]] = [[insStart, insEnd]]
            else:
                offset = len(self.scanInsertionPoint[self.scanAbsFilePath[key]]) * 2
                self.scanInsertionPoint[self.scanAbsFilePath[key]].append([insStart - offset, insEnd - offset])

    def btnSetInsertionPointClick(self, event):
        if self.scanMessageInfo == None:
            return
        # show in UI
        insertionPointChar = u"§"

        selectedText = self.scanEditField.getSelectedData()
        if selectedText == None:
            print "[-]No selected area"
            return
        start = self.scanEditField.getSelectionBounds()[0]
        end = start + len(selectedText)

        requestString = self.scanEditField.getMessage()

        newRequestString = self.setInsertionMark(requestString, start, end)

        self.scanEditField.setMessage(newRequestString, False)

        #save insertion point
        self.addInsertionPoint(start, end)
        self.insertionPointCount += 1

    def setInsertionMark(self, requestString, start, end):
        insertionPointChar = u"§"
        selectedText = requestString[start:end]
        newRequestString = self._helpers.bytesToString(requestString[:start]) + insertionPointChar + self._helpers.bytesToString(selectedText) + insertionPointChar + self._helpers.bytesToString(requestString[end:])
        newRequestString = self._helpers.stringToBytes(newRequestString)
        return newRequestString

    def prepareScanRequest(self, request):
        for i in range(0, self.insertionPointCount):
            param = self._helpers.buildParameter(PAYLOAD_PARAM_NAME % i, self.runningScanDefaultPayload[i], IParameter.PARAM_BODY)
            request = self._helpers.addParameter(request, param)
        # add flag
        param = self._helpers.buildParameter(EXTENDER_FLAG, "1", IParameter.PARAM_BODY)
        request = self._helpers.addParameter(request, param)
        # add filename scan
        if self.checkboxScanFilename.isSelected():
            self.isScanZipFilename = True
            param = self._helpers.buildParameter(PAYLOAD_FILENAME, self.scanZipFilename, IParameter.PARAM_BODY)
            request = self._helpers.addParameter(request, param)
        else:
            self.isScanZipFilename = False
        return request

    def prepareScanInsertionOffset(self, request, paramName):
        param = self._helpers.getRequestParameter(request, paramName)
        startOffset = param.getValueStart()
        endOffset = param.getValueEnd()
        return array([startOffset, endOffset], 'i')

    def btnScanClick(self, event):
        if self.scanMessageInfo == None:
            return
        self.runningScanTemplate = {}
        self.runningScanDefaultPayload = []
        self.removeDirectory(RUNNING_SCAN_PATH)

        os.makedirs(RUNNING_SCAN_PATH)
        copytree(SCAN_TEMP_PATH, RUNNING_SCAN_PATH + os.sep + SCAN_TEMP_PATH)

        # self.insertionPointCount = 3
        insertionPointNo = 0

        # read template
        for template in self.scanTemplateFileName:
            t = self._helpers.bytesToString(self.readFile(template))
            temp = ""
            insertionPointNoOfFile = 0
            # point to begin of file
            insPoint = []
            for el in self.scanInsertionPoint[template]:
                insPoint.append(el[0])
                insPoint.append(el[1])
            insPoint.sort()
            currentPoint = 0
            for i in xrange(0, len(insPoint) - 1, 2):
                # print p
                temp += t[currentPoint:insPoint[i]] + INSETION_POINT_SYMBOL
                currentPoint = insPoint[i + 1]
                self.runningScanDefaultPayload.append(t[insPoint[i]:insPoint[i + 1]])
                insertionPointNo += 1
            temp += t[currentPoint:]
            temp = self._helpers.stringToBytes(temp)

            self.runningScanTemplate[template] = temp

        if insertionPointNo != self.insertionPointCount:
            print "[-]Error while parsing template"
            return

        #send to scanner
        httpService = self.scanMessageInfo.getHttpService()
        # request = self.scanMessageInfo.getRequest()
        request = self.prepareScanRequest(self.scanMessageInfo.getRequest())
        isHttps = True if httpService.getProtocol() == 'https' else False
        insertionOffset = []

        for i in range(0, self.insertionPointCount):
            insertionOffset.append(self.prepareScanInsertionOffset(request,PAYLOAD_PARAM_NAME % i))
        if self.isScanZipFilename:
            insertionOffset.append(self.prepareScanInsertionOffset(request,PAYLOAD_FILENAME))
        self.currentScanItem = self._callbacks.doActiveScan(httpService.getHost(), httpService.getPort(), isHttps, request, insertionOffset)
        print "[*]Scanner is running"
        self._callbacks.issueAlert("Send to Active Scanner")
        t = threading.Thread(target=self.checkScannerStatus)
        t.start()
        
    def checkScannerStatus(self):
        self.disableScanUi()
        while True:
            if self.currentScanItem == None:
                self.scannerStatusLabel.text = "<html><i style='color:grey'> Canceled</i></html>"
                self.enableScanUi()
                return
            else:
                status = self.currentScanItem.getStatus()
                if status == "finished":
                    self.scannerStatusLabel.text = "<html><i style='color:green'> Complete</i></html>"
                    self.enableScanUi()
                    self._callbacks.issueAlert("Scan Complete")
                    return
                self.scannerStatusLabel.text = "<html><i style='color:orange'> %s</i></html>" % (status)
            #schedule run every 1 sec
            sleep(1)

    def cancelScan(self, event):
        self.currentScanItem.cancel()
        self.currentScanItem = None
        self.enableScanUi()

    def disableScanUi(self):
        self.scanBtnCancel.setEnabled(True)
        self.scanBtnGo.setEnabled(False)
        self.scanBtnSave.setEnabled(False)
        self.scanBtnClearInsertionPoint.setEnabled(False)
        self.scanBtnClear.setEnabled(False)
        self.scanDirList.setEnabled(False)
    
    def enableScanUi(self):
        self.scanBtnCancel.setEnabled(False)
        self.scanBtnGo.setEnabled(True)
        self.scanBtnSave.setEnabled(True)
        self.scanBtnClearInsertionPoint.setEnabled(True)
        self.scanBtnClear.setEnabled(True)
        self.scanEditField.setMessage("", False)
        self.scanDirList.setEnabled(True)

    #init extender GUI
    def initGUI(self):
        #
        # Manual tab
        #
        tabPane = JTabbedPane(JTabbedPane.TOP)
        reqRestabPane = JTabbedPane(JTabbedPane.TOP)
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        tabPane.addTab("Repeater", splitPane)
        splitPane2 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        splitPane.setLeftComponent(splitPane2)

        panel1 = JPanel()
        panel2 = JPanel()

        splitPane2.setLeftComponent(panel1)
        splitPane2.setRightComponent(panel2)
        splitPane.setRightComponent(reqRestabPane)

        panel1.setLayout(BoxLayout(panel1,BoxLayout.Y_AXIS))
        panel2.setLayout(BoxLayout(panel2,BoxLayout.Y_AXIS))

        self.requestPanel = self._callbacks.createMessageEditor(None, False)
        self.responsePanel = self._callbacks.createMessageEditor(None, False)

        label1 = JLabel("files and folders")
        self.lblFilename = JLabel("File name")
        label3 = JLabel("Response")
        self.editField = self._callbacks.createMessageEditor(None, True)
        self.dirList = JList([], valueChanged = self.listSelect)

        listFileDirPane = JScrollPane(self.dirList)

        ## Set left align
        listFileDirPane.setAlignmentX(Component.LEFT_ALIGNMENT)

        btnPanel = JPanel()
        btnGo = JButton("Compress & Go", actionPerformed = self.btnGoClick)
        btnSave = JButton("Save", actionPerformed = self.btnSaveClick)
        btnClear = JButton("Clear", actionPerformed = self.btnClearClick)
        btnReset = JButton("Reset", actionPerformed = self.btnResetRepeaterClick)
        btnPanel.add(btnGo)
        btnPanel.add(btnSave)
        btnPanel.add(btnReset)
        btnPanel.add(btnClear)
        btnPanel.setLayout(BoxLayout(btnPanel,BoxLayout.X_AXIS))

        panel1.add(label1)
        panel1.add(listFileDirPane)

        panel2.add(self.lblFilename)
        panel2.add(self.editField.getComponent())
        panel2.add(btnPanel)

        reqRestabPane.addTab("Response",self.responsePanel.getComponent())
        reqRestabPane.addTab("Request",self.requestPanel.getComponent())

        splitPane.setResizeWeight(0.6)

        #
        # Scanner tab
        #
        scanSplitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        tabPane.addTab("Scanner", scanSplitPane)
        scanSplitPane2 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        scanSplitPane.setLeftComponent(scanSplitPane2)

        scanPanel1 = JPanel()
        scanPanel2 = JPanel()
        scanPanel3 = JPanel()
        scanSplitPane2.setLeftComponent(scanPanel1)
        scanSplitPane2.setRightComponent(scanPanel2)
        scanSplitPane.setRightComponent(scanPanel3)

        scanPanel1.setLayout(BoxLayout(scanPanel1,BoxLayout.Y_AXIS))
        scanPanel2.setLayout(BoxLayout(scanPanel2,BoxLayout.Y_AXIS))
        scanPanel3.setLayout(BoxLayout(scanPanel3,BoxLayout.Y_AXIS))

        scanLabel1 = JLabel("files and folders")
        self.scanLblFilename = JLabel("File name")
        scanLabel3 = JLabel("<html><h3>Config scanner</h3></html>")
        scanLabel4 = JLabel("<html><h3>Scanner status</h3></html>")
        scanLabel5 = JLabel("""<html>
                                <div>
                                    <h3>Notice</h3>
                                    <ul>
                                        <li>Possible to run only a scan at time</li>
                                        <li>Work with .zip file only</li>
                                        <li>Cannot continue after exit Burp</li>
                                    </ul>
                                </div>
                            </html>""")
        self.scannerStatusLabel = JLabel("<html><i style='color:grey'> Not Running</i></html>")
        self.checkboxScanFilename = JCheckBox("Also scan zip filename (this may be upload several files to server)")
        self.scanEditField = self._callbacks.createMessageEditor(None, False)
        self.scanDirList = JList([], valueChanged = self.scanListSelect)

        scanListFileDirPane = JScrollPane(self.scanDirList)

        ## Set left align
        scanListFileDirPane.setAlignmentX(Component.LEFT_ALIGNMENT)

        scanBtnPanel = JPanel()
        self.scanBtnGo = JButton("Set insertion point", actionPerformed = self.btnSetInsertionPointClick)
        self.scanBtnSave = JButton("Send to scanner", actionPerformed = self.btnScanClick)
        self.scanBtnClearInsertionPoint = JButton("Clear insertion points", actionPerformed = self.scanBtnClearInsClick)
        self.scanBtnClear = JButton("Clear", actionPerformed = self.scanBtnClearClick)
        self.scanBtnCancel = JButton("Cancel", actionPerformed = self.cancelScan)
        scanBtnPanel.add(self.scanBtnGo)
        scanBtnPanel.add(self.scanBtnSave)
        scanBtnPanel.add(self.scanBtnClearInsertionPoint)
        scanBtnPanel.add(self.scanBtnClear)
        scanBtnPanel.setLayout(BoxLayout(scanBtnPanel,BoxLayout.X_AXIS))

        scanPanel1.add(scanLabel1)
        scanPanel1.add(scanListFileDirPane)

        scanPanel2.add(self.scanLblFilename)
        scanPanel2.add(self.scanEditField.getComponent())
        scanPanel2.add(scanBtnPanel)
        
        scanPanel3.add(scanLabel3)
        scanPanel3.add(self.checkboxScanFilename)
        scanPanel3.add(scanLabel4)
        scanPanel3.add(self.scannerStatusLabel)
        scanPanel3.add(self.scanBtnCancel)
        self.scanBtnCancel.setEnabled(False)
        scanPanel3.add(scanLabel5)

        scanSplitPane.setResizeWeight(0.6)

        self.tab = tabPane

    # implement ITab
    def getTabCaption(self):
        return "ZIP File Raider"

    def getUiComponent(self):
        return self.tab
