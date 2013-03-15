#!/usr/bin/python

# File		: wolvm_configure.py
#
# Description	: Generates the KERNEL_CONFIG_FILE (vm.list) by asking for the appropriate
#		  information to the vm managers configured in wolvm_configure.xml.
#
# Usage		: see wolvm.man
#
# Last Modif	: 06/24/2012
#
# Authors	: MERLINI Adrien - <adrien.merlini@telecom-bretagne.eu>
#
# Contact	: BEGLIN   Marianne - <marianne.beglin@telecom-bretagne.eu>
#		  MERLINI  Adrien   - <adrien.merlini@telecom-bretagne.eu>
#		  NGUYEN   Olivier  - <olivier.nguyen@telecom-bretagne.eu>
#		  Zhang    Chi	    - <chi.zhang@telecom-bretagne.eu>
# 

from xml.dom import minidom
from xml.parsers.expat import ExpatError
import re, os, sys, platform
import subprocess
from traceback import print_exc

##################################################################################################
#			      		   DECLARATIONS					  	 #
##################################################################################################


######################################## GLOBAL VARIABLES ########################################

operatingSystem=platform.system()

############################################ FUNCTIONS ###########################################

# DEBUG
def check_output(cmd):
	p=subprocess.Popen(cmd, shell=True, stdout=subprocess.STDOUT, stderr=subprocess.stdout)
	return p.stdout.readlines()

def usingVMtype(VMtype, toConfig):
	if VMtype in toConfig.keys():
		return True
	return False

def openXML(xmlFile):
	try:
		doc = minidom.parse(xmlFile)
	except ExpatError as pError:
		print ("----------------------------------------------------------")
		print ("(FF) In the xml configuration file, invalid syntax:")
		print ("(FF) ", pError)
		print_exc()
		print ("(FF) Aborting configuration!")
		print ("----------------------------------------------------------")
		sys.exit(-1)
	except IOError as ioErr:
		print ("----------------------------------------------------------")
		print ("(FF)", ioErr)
		print_exc()
		print ("----------------------------------------------------------")
		sys.exit(-1)
	return doc

def fillToConfig(toConfig, doc):
	for field in doc.getElementsByTagName('WolVM'):
		for node in field.getElementsByTagName('VMmanagers'):
			for element in node.getElementsByTagName('VMmanager'):
				dic=dict()
				try:
					VMType	    =	str(element.getAttribute('type'))
					dic['name'] =	str(element.getAttribute('name'))
					dic['path'] =	str(element.getAttribute('path'))


					toConfig[VMType]=dic
				except IndexError as IE:
					print ("----------------------------------------------------------")
					print ("(EE) In the xml configuration file, missing field,")
					print ("(EE) Please check this file and correct errors.")
					print ("(EE)", IE)
					print_exc()
					print ("----------------------------------------------------------")
					continue
	return toConfig

def fillSuperDic(superDic, toConfig, doc):
	# Filling in superdic with data coming from the xml configuration file
	for element in doc.getElementsByTagName('WolVM'):
		for node in element.getElementsByTagName('VMType'):
			dic=dict()
		
			try:
				identifier	 = str(node.getAttribute('id'))

				if not usingVMtype(identifier, toConfig):
					continue

				path		 = toConfig[identifier]['path']
				name		 = str(node.getAttribute('name'))

				dic['location']  = os.path.join(path,str(xmlGetElement(node, 'check')))

				listField	 = node.getElementsByTagName('list')[0]
				dic['list'] 	 = os.path.join(path,str(xmlGetElement(node, 'list')))
				dic['regexList'] = str(listField.getAttribute('regex'))
				dic['listGroup'] = int(listField.getAttribute('numRegexGroup'))
				dic['parseFolder'] = str(listField.getAttribute('parseFolder'))
				tmp = str(listField.getAttribute('recursive'))
				if tmp == 'true':
					dic['recursive'] = True
				else:
					dic['recursive'] = False



				macField	 = node.getElementsByTagName('mac')[0]
				dic['mac'] 	 = os.path.join(path,str(xmlGetElement(node, 'mac')))
				dic['regexMAC']  = str(macField.getAttribute('regex'))
				dic['macGroup']  = int(macField.getAttribute('numRegexGroup'))

				dic['launchVM']  = os.path.join(path,str(xmlGetElement(node, 'launchVM')))


				superDic[name] = dic
			except IndexError as IE:
				print ("----------------------------------------------------------")
				print ("(EE) In the xml configuration file, missing field,")
				print ("(EE) Please check this file and correct errors.")
				print ("(EE)", IE)
				print_exc()
				print ("----------------------------------------------------------")
				continue
	return superDic

def is_exe(fpath):
	if 'Windows' in operatingSystem:
		# TODO will have to find a better solution...
		return True
	return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

def isReadableFile(fpath):
	return os.path.isfile(fpath) and os.access(fpath, os.R_OK)

def xmlGetElement(node, elementName):
	a=node.getElementsByTagName(elementName)
	#print (a[0].firstChild.nodeValue)
	return a[0].firstChild.nodeValue

def formatMac(mac):
	fMac=mac.replace(":","")
	fMac=fMac.replace(" ","0")
	fMac=fMac.lower()
	return fMac

def parseXML(xmlFile):
	doc=openXML(xmlFile)

	# Will contain the type of every installed VMmanager (found in <VMmanagers>)
	toConfig=dict()
	toConfig=fillToConfig(toConfig, doc)

	# Will contain every VMManager and its associated fields (obtained from the xml configuration file)
	superdic=dict()
	superdic=fillSuperDic(superdic, toConfig, doc)

	return superdic

def getVMAndMac(superdic):
	vmMac=dict() # Will contain the VM <---> MAC association for every VMManager

	# Filling in vmMac
	for key in superdic.keys():

		# Checking if the provided location path is existing/executable
		if not is_exe(superdic[key]['location']):
			print ("----------------------------------------------------------")
			print ("(EE) Program "+superdic[key]['location']+" does not exist or is not executable. Ignoring VMmanager "+key+".")
			print ("----------------------------------------------------------")
			continue


		# Checking if the 'key' VMmanager needs special treatment
		if superdic[key]['parseFolder'] != '':
			# Merging the result of getConfigFromFiles and current vmMAC
			vmMac.update(getConfigFromFiles(superdic[key], key))

		# If no special treatment needed defaulting to normal behaviour
		else:
			tempVmMac=dict()
			# Regex compilation
			try:
				regexList = str(superdic[key]['regexList'])
				rList=re.compile(regexList)
			except re.error as strError:
				print ("----------------------------------------------------------")
				print ("(EE) In "+key+" regexList field ->  regex error :")
				print ("(EE) ", strError)
				print ("(EE) Ignoring VMManager: "+key)
				print ("----------------------------------------------------------")
				continue

			try:
				regexMAC = str(superdic[key]['regexMAC'])
				rMAC=re.compile(regexMAC)
			except re.error as strError:
				print ("----------------------------------------------------------")
				print ("(EE) In "+key+" regexMACfield ->  regex error :")
				print ("(EE) ", strError)
				print ("(EE) Ignoring VMManager: "+key)
				print ("----------------------------------------------------------")
				continue

			# Getting list of VM & associated MAC

				# Get the list of vm available in VMmanager "key"
			cmd=superdic[key]["list"]
			try:
				answer=subprocess.check_output(cmd, shell = True, universal_newlines=True).split('\n')
				answer.remove('')
			except subprocess.CalledProcessError as pError:
				print ("----------------------------------------------------------")
				print ("(EE) In "+key+":")
				print ("(EE) ", pError)
				print ("(EE) Ignoring VMManager: "+key)
				print ("----------------------------------------------------------")
				continue

				# Filling in tempVmMac with the names of detected VMs & associated VMmanager:
				# tempVmMAC[vm]=[VMmanager, MAC]
			numGroup=superdic[key]['listGroup']
			for line in answer:
				res = rList.search(line)
				try:
					tempVmMac[res.group(numGroup)]=[key]
				except AttributeError:
					pass

				# Getting vm's associated MACs and storing them in tempVmMac
			numGroup=superdic[key]['macGroup']
			cmd=str(superdic[key]["mac"])+' '
			for vm in tempVmMac.keys():
				try:
					answer=subprocess.check_output(cmd+vm, shell = True, universal_newlines=True)
				except subprocess.CalledProcessError as pError:
					print ("----------------------------------------------------------")
					print ("(EE) In "+key+":")
					print ("(EE) ", pError)
					print ("(EE) Ignoring VMManager: "+key)
					print ("----------------------------------------------------------")
					continue

				res = rMAC.search(answer)
				try:
					tempVmMac[vm]+=[formatMac(res.group(numGroup))]
				except AttributeError:
					pass
			# Storing the content of tempVmMac in vmMac
			vmMac.update(tempVmMac)
	print (vmMac)
	return vmMac

# Must receive the the superDic field corresponding to the VMmanager being configure and the name of this VMmanager
def getConfigFromFiles(superDicField, VMmanager):
	tempVmMac=dict()

	# Get the name of the folder to work in
	configDir=superDicField['parseFolder']

	# Trying to compile the list RegEx
	try:
		regexList=str(superDicField['regexList'])
		rList=re.compile(regexList)
	except re.error as strError:
		print ("----------------------------------------------------------")
		print ("(EE) In "+VMmanager+" regexList field ->  regex error :")
		print ("(EE) ", strError)
		print ("(EE) Ignoring VMManager: "+VMmanager)
		print ("----------------------------------------------------------")
		return []

	# Trying to compile the mac RegEx
	try:
		regexMAC=str(superDicField['regexMAC'])
		rMAC=re.compile(regexMAC)
	except re.error as strError:
		print ("----------------------------------------------------------")
		print ("(EE) In "+VMmanager+" regexMAC field ->  regex error :")
		print ("(EE) ", strError)
		print ("(EE) Ignoring VMManager: "+VMmanager)
		print ("----------------------------------------------------------")
		return []

	# Getting names from files in configDir
	# if we don't want recursive parsing
	if not superDicField['recursive']:
		try:
			tempFiles=os.listdir(configDir)
		except OSError as oserr:
			print ("----------------------------------------------------------")
			print ("(EE) In "+VMmanager+" the folder to be parsed can not be opened.")
			print (oserr)
			print ("(EE) Aborting configuration of "+VMmanager)
			print ("----------------------------------------------------------")
			return []
	# if we want recursive parsing
	else:
		# Check if the provided file is realy a folder
		if not os.path.isdir(configDir):
			print ("----------------------------------------------------------")
			print ("(EE) In "+VMmanager+" the folder to be parsed can not be opened.")
			print (oserr)
			print ("(EE) Aborting configuration of "+VMmanager)
			print ("----------------------------------------------------------")
			return []
		tempFiles=[]
		for root, dirs, files in os.walk(configDir):
			for fil in files:
				tempFiles+=[os.path.join(root, fil)]


	# Sorting the list of files we have just received. We only keep those who are 
	# matching the regex.
	useLessFiles=[]
	for tempFile in tempFiles:
		result=rList.search(tempFile)
		# If the file name doesn't match the regex we store it.
		if not result:
			useLessFiles+=[tempFile]

	for useLessFile in useLessFiles:
		tempFiles.remove(useLessFile)


	#Looking for MACs in files
	for tempFile in tempFiles:
		# Getting the string before '.' if any, the all string else
		# This string will be considered to be the name of the VM
		name=os.path.basename(os.path.normpath(tempFile)).partition('.')[0]

		# Appending the name of the files found in configDir, at the end of 
		# configDir.
		# This is done in order to obtain the absolute path to the files to parse.
		#tempFile=configDir+tempFile
		tempFile=os.path.join(configDir,tempFile)

		# Looking for the MAC in tempFile
		try:
			vmFile=open(tempFile)
		except IOError:
			print ("(II) "+tempFile+" is not a file or can't be opened." )
			continue

		for line in vmFile:
			mac=rMAC.search(line)
			try:
				tempVmMac[name]=[VMmanager,formatMac(mac.group(superDicField['macGroup']))]
				break
			except AttributeError:
				pass
			except IndexError:
				pass
		vmFile.close()
		# If no MAC was found in the file
		if name not in tempVmMac:
			print ("(II) No mac found in file : "+tempFile)

	return tempVmMac


def writeVMList(superdic, vmMAC, fileToWrite):
	try:
		f=open(fileToWrite, 'w')
	except IOError as ioErr:
		print ("----------------------------------------------------------")
		print ("(FF) Error occured while writing configuration:")
		print ("(FF) ",ioErr)
		print ("----------------------------------------------------------")
		sys.exit(-1)
	#TODO si on a un nom mais pas de mac!!!!!!
	for key in vmMAC:
		try:
			f.write(vmMAC[key][1]+','+superdic[vmMAC[key][0]]['launchVM']+' '+key+'\n')
		except IndexError as Ierr:
			print ("----------------------------------------------------------")
			print ("(EE) In "+key+" we weren't able to retrieve the MAC of one of the VM")
			print ("(EE) One of the reason is that you 'list regex' didn't match the entire name of the VM")
			print (Ierr)
			print ("----------------------------------------------------------")
	f.close()


def argError(scriptName="wolvm.py"):
	print (scriptName, ": argument error")
	print ("Usage: \twolvm.py configure [-s SOURCE_CONFIG_FILE] [-d NOYAU_CONFIG_FILE]")
	print ("\twolvm.py start [-f DAEMON_CONFIG_FILE] [-l LOG_FILE] [-p PATH_TO_KERNEL]")
	print ("\twolvm.py stop [-p PATH_TO_KERNEL]")
	print ("\twolvm.py ( -h | --help | help )")
	print ("For help see wolvm.man")


def getPathToKernelFromXML(xmlFile):
	doc = openXML(xmlFile)
	field=doc.getElementsByTagName('WolVM')[0]
	path=xmlGetElement(field, 'kernelPath')
	return path
	


##################################################################################################
#					END OF DECLARATIONS					 #
##################################################################################################

##################################################################################################
#						HMI						 #
##################################################################################################
argv		= sys.argv
argc 		= len(argv)
configFileNoyau	= "vm.list"
configFileEnv	= "wolvm_configure.xml"	
configuring	= True
#pathToMan	= "wolvm.man"
pathToKernel	= "../../noyau/daemon/daemon"   #TODO CHANGE
# For Windows only
serviceName	= "wolvm"

# Processing args
if argc > 1:
	if argv[1] == "configure":
		if(argc > 2):
			currentIndex=2
			while currentIndex < argc:
				if argv[currentIndex]=='-s':
					configFileEnv=argv[currentIndex+1]
				elif argv[currentIndex]=='-d':
					configFileNoyau=argv[currentIndex+1]
				else:
					argError(argv[0])
					configuring=False
				currentIndex+=2

		# Beginning configuration
		if configuring:
			superdic = parseXML(configFileEnv)
			vmAndMac = getVMAndMac(superdic)
			writeVMList(superdic, vmAndMac, configFileNoyau)
		# End of configuration
	elif argv[1] == "start" or argv[1] == "stop":
		# If we are running on an UNIX environment do:
		if 'Linux' in operatingSystem:
			if argc > 2:
				if argc < 4 and argv[2] != '-p':
					argError(argv[0])
					sys.exit(-1)
				else:
					pathToKernel = argv[3]
			else:
				pathToKernel=getPathToKernelFromXML(configFileEnv)
				if not is_exe(pathToKernel):
					print ("----------------------------------------------------------")
					print ("(FF) Specified Path to Kernel non existent or non executable")
					print ("(FF) If you have not specified any, then the path in the wolvm")
					print ("(FF) configuration file must be changed.")
					print ("----------------------------------------------------------")
					sys.exit(-1)
				cmd=pathToKernel+' '+argv[1]
				print (cmd)
				try:
					answer=subprocess.check_output(cmd, shell = True)
					print (answer)
				except subprocess.CalledProcessError as pError:
					print ("----------------------------------------------------------")
					print ("(FF) Error while calling kernel.")
					print ("(FF) ", pError)
					print ("(FF) Specified path must be incorrect (if none, the path in")
					print ("(FF) wolvm config file must be incorrect)")
					print ("----------------------------------------------------------")
					sys.exit(-1)

		# If we are running on a Windows environment do:
		if 'Windows' in operatingSystem:
			cmd = "sc "+argv[1]+' '+serviceName
			try:
				answer=subprocess.check_output(cmd, shell = True)
				print (answer)
			except subprocess.CalledProcessError as pError:	
				print ("----------------------------------------------------------")
				print ("(FF) Error while calling the Service Manager.")
				print ("(FF) ", pError)
				print ("(FF) Please make sure that you are running this script with")
				print ("(FF) administrator privileges and that the name you registered")
				print ("(FF) for the WOLVM service is 'WOLVM'")
				print ("----------------------------------------------------------")
				sys.exit(-1)




	elif argv[1] == "help" or argv[1] == "--help" or argv[1] == '-h':
		argError(argv[0]) 
	else:
		argError(argv[0])
else:
	argError()

##################################################################################################
#						EOF						 #
##################################################################################################
