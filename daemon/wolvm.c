/* WOLVM, a Wake On Lan extension for virtual machines.
 * Below is the WOLVM kernel source code.
 *
 * File		: wolvm_windows.c
 *
 * Description	: Source code of the WLOVM kernel.
 * 		  The kernel's job is to detect the magic packets and to wake
 * 		  up the Virtual Machines which MAC address is in the magick packet.
 * 		  Of course this is if there is a VM with the corresponding MAC on the host 
 * 		  system.
 *
 * Last Modif	: 06/24/2012
 *
 * Authors	: MERLINI Adrien - <adrien.merlini@telecom-bretagne.eu>
 * 		  ZHANG Chi 	 - <chi.zhang@telecom-bretagne.eu>
 *
 * Contact	: BEGLIN   Marianne - <marianne.beglin@telecom-bretagne.eu>
 *                MERLINI  Adrien   - <adrien.merlini@telecom-bretagne.eu>
 *                NGUYEN   Olivier  - <olivier.nguyen@telecom-bretagne.eu>
 *                Zhang    Chi      - <chi.zhang@telecom-bretagne.eu>
 *
 * Requires	: You must have installed WinPcap (drivers + DLLs) - http://www.winpcap.org/install/default.htm
 * 		  To compile this code you also need to download and set the Winpcap Developer Resources - http://www.winpcap.org/devel.htm
 *
 * Compile	: Use your favorite IDE, but don't forget to link the compiler to the WinPcap libs
 * 		  and to place the Winpcap headers where your compiler needs you to. 
 * */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <windows.h>

#undef ERROR
#include "wolvm_config.h"

/* Path to the log file */
#define LOG_FILE        "C:\\Windows\\Temp\\WOLVM.log"
/* Path to the KERNEL_CONFIG_FILE, this file is refered to as vm.list in the WOLVM 
 * configuring script*/
#define KERNEL_CONFIG_FILE      "vm.list"
/* Max size of log messages */
#define LOG_MAX_SIZE    100
/* Max size of the Mac addresses returned by pcap. 16 should be enough but... */
#define MAC_LEN 20
/* Max size of the commands extracted from vm.list */
#define CMD_LEN 100
/* Max number of the packets bites to be read */
#define MAXBYTES2CAPTURE 2048

/* Seems to be defined in windows.h, undefining it to */
#undef ERROR


/*--------------------------------------------------------------------------------------------------*/
/*----------------------------------------------HEADERS---------------------------------------------*/
/*--------------------------------------------------------------------------------------------------*/

/* Windows' service related varibles and functions */
SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

void ServiceMain(int argc, char** argv);
void ControlHandler(DWORD request);
int  InitService();

/* WOLVM functions */
int  log_message(char *message, LOGLVL logLevel);
void formatMac(char *mac);
void launchVM(char *mac);
void processPacket(const struct pcap_pkthdr* pkthdr, const u_char * packet);


/*--------------------------------------------------------------------------------------------------*/
/*-----------------------------------------GLOBAL VARIABLES-----------------------------------------*/
/*--------------------------------------------------------------------------------------------------*/

int verbosity;


/*--------------------------------------------------------------------------------------------------*/
/*----------------------------------------------SOURCES---------------------------------------------*/
/*--------------------------------------------------------------------------------------------------*/

int main()
{
	/* Main just connect the program to the Windows Service Manager */
	SERVICE_TABLE_ENTRY ServiceTable[2];

	ServiceTable[0].lpServiceName = "WOLVM";
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

	ServiceTable[1].lpServiceName = NULL;
	ServiceTable[1].lpServiceProc = NULL;
	// Start the control dispatcher thread for our service
	if(!StartServiceCtrlDispatcher(ServiceTable))
	{
		/* If you see this message appear in your log file, you probably attempting to 
		 * launch the program directly.
		 * You must use the Service Manager to do so. 
		 * See README.txt.
		 * */
		log_message("The system is preveting service WOLVM from starting, see service.msc", FATAL);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}


/*--------------------------------------------------------------------------------------------------*/

void ServiceMain(int argc, char** argv)
{
	/* This function would be the 'real' main() if there were no need to communicate 
	 * with the service manager.
	 * */


	/* Windows Service specific code */
	int error;
	char *progName=argv[0];

	pcap_t *descr = NULL;
	char errbuf[PCAP_ERRBUF_SIZE], *device=NULL;
	char message[50];
	memset(errbuf,0,PCAP_ERRBUF_SIZE);
	struct pcap_pkthdr pkt_header;
	struct pcap_pkthdr * ppkt_header = &pkt_header;
	const u_char *pkt_data;


	ServiceStatus.dwServiceType        = SERVICE_WIN32;
	ServiceStatus.dwCurrentState       = SERVICE_START_PENDING;
	ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwWin32ExitCode      = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint         = 0;
	ServiceStatus.dwWaitHint           = 0;

	hStatus = RegisterServiceCtrlHandler(
		"WOLVM",
		(LPHANDLER_FUNCTION)ControlHandler);
	if (hStatus == (SERVICE_STATUS_HANDLE)0)
	{
		// Registering Control Handler failed
		log_message("Registering control handler failed, aborting.", FATAL);
		return;
	}
	// Initialize Service
	error = InitService();
	if (error)
	{
		// Initialization failed
		log_message("Service initialisation failed, aborting.", FATAL);
		ServiceStatus.dwCurrentState       = SERVICE_STOPPED;
		ServiceStatus.dwWin32ExitCode      = -1;
		SetServiceStatus(hStatus, &ServiceStatus);
		return;
	}
	// We report the running status to SCM.
	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus (hStatus, &ServiceStatus);
	/* END OF Windows Service specific code */

	/* Loading config file information */
	readConf(opts);

	/* Parsing arguments (k & R method) */
	if(argc == 2)
	{
		if(strcmp(*++argv,"-v") == 0){
			setOption("verbosity", "1", opts);
		}else{
			setOption("iface", *argv, opts);
		}
	}

	else if(argc == 3){
		if(strcmp(*++argv,"-v") == 0){
			setOption("verbosity", "1", opts);
		}else{
			badUsage(progName);	
		}
		setOption("iface", *++argv, opts);
	}

	/* Starting proper work with correct options */
	verbosity = atoi(getOptValue("verbosity", opts));

	device = getOptValue("iface", opts);

	
	/* pcap starts working with the network */
	if(strncmp(device, "auto", 5) == 0)		 /* Get the name of the first device suitable for capture */
	{
		if ((device = pcap_lookupdev(errbuf)) == NULL)
		{
			log_message(errbuf, FATAL);
			exit(EXIT_FAILURE);
		}
	}

	sprintf(message, "Opening device %s", device);
	log_message(message, INFORMATION);

	/* Open device in promiscuous mode */
	if ((descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL)
	{
		log_message(errbuf, FATAL);
		exit(EXIT_FAILURE);
	}

	// The worker loop of a service
	while (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
	{
		if(pcap_next_ex(descr, &ppkt_header, &pkt_data)!=-1){
			processPacket(ppkt_header, pkt_data);
		}   
	}


	return;
}


/*--------------------------------------------------------------------------------------------------*/

void badUsage(char *progName)
{
	char message[100];
	sprintf(message, "Usage: %s [-v] [iface]\n", progName);
	log_message(message, FATAL);
	exit(EXIT_FAILURE);
}


/*--------------------------------------------------------------------------------------------------*/


// Service initialization
int InitService()
{
	return log_message("Monitoring started.", INFORMATION);
}


/*--------------------------------------------------------------------------------------------------*/

// Control handler function
void ControlHandler(DWORD request)
{
	switch(request)
	{
		case SERVICE_CONTROL_STOP:
			log_message("Monitoring stopped.", INFORMATION);

			ServiceStatus.dwWin32ExitCode = 0;
			ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
			SetServiceStatus (hStatus, &ServiceStatus);
			return;

		case SERVICE_CONTROL_SHUTDOWN:
			log_message("Monitoring stopped.", INFORMATION);

			ServiceStatus.dwWin32ExitCode = 0;
			ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
			SetServiceStatus (hStatus, &ServiceStatus);
			return;

		default:
			break;
	}

	// Report current status
	SetServiceStatus (hStatus,  &ServiceStatus);

	return;
}


/*--------------------------------------------------------------------------------------------------*/

int log_message(char *message, LOGLVL logLevel)
{
	/* Logging function with different loglevels */
	FILE *logfile	= NULL;
	time_t now	= time(NULL);
	char logMsg[LOG_MAX_SIZE]={'\0'};

	strcat(logMsg, ctime(&now));
	/* Suppressing the '\n' in the string returned by cdate */
	logMsg[24] = ' ';

	switch(logLevel)
	{
		case DEBUG:
			if(!verbosity) return 0;
			strcat(logMsg, "(DD) ");
			strncat(logMsg, message, LOG_MAX_SIZE - 6);
			break;
		case INFORMATION:
			strcat(logMsg, "(II) ");
			strncat(logMsg, message, LOG_MAX_SIZE - 6);
			break;
		case WARNING:
			strcat(logMsg, "(WW) ");
			strncat(logMsg, message, LOG_MAX_SIZE - 6);
			break;
		case ERROR:
			strcat(logMsg, "(EE) ");
			strncat(logMsg, message, LOG_MAX_SIZE - 6);
			break;
		case FATAL:
			strcat(logMsg, "(FF) ");
			strncat(logMsg, message, LOG_MAX_SIZE - 6);
			break;
		default:
			break;
	}

	logfile=fopen(LOG_FILE, "a");
	if(!logfile) return -1;
	fprintf(logfile,"%s\n",logMsg);
	fclose(logfile);

	return 0;
}


/*--------------------------------------------------------------------------------------------------*/

// processPacket(): Callback function called by pcap_loop() everytime a packet
// arrives to the network card.
// This function determines wether a packet is a magic packet or not.
// If it is, launches the appropriate treatment.

void processPacket(const struct pcap_pkthdr* pkthdr, const u_char * packet)
{

	unsigned int i = 0, backUpI = 0, j, k, pktLen = pkthdr->len;
	int syncro, consecutif;
	u_char mac[6];
	char macToLog[50], macToLaunch[17];

	while(backUpI + 96 <= pktLen)
	{
		syncro = 0;
		consecutif = 1;
		i = backUpI - 1;
		while(++i<pktLen && syncro<6)
		{
			if(packet[i] == 0xff && consecutif)
			{
				syncro++;
			}
			else if(packet[i] == 0xff && !consecutif)
			{
				syncro = 1;
				consecutif = 1;
			}
			else if(consecutif)
			{
				consecutif = 0;
			}
		}
		backUpI=i;
		if(syncro == 6 && i + 96 == pktLen)
		{
			for(j = 0; j < 6; j++)
			{
				mac[j] = packet[i + j];
			}
			i += 6;
			j = -1;
			consecutif = 1;
			while(++j < 15 && consecutif)
			{
				for(k = 0; k < 6; k++)
				{
					if(packet[i + k] != mac[k])
						consecutif = 0;
				}
				i += 6;
			}

			/* If the algo has recognized a magic packet */
			if(consecutif)
			{
				sprintf(macToLaunch,"%2x%2x%2x%2x%2x%2x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
				launchVM(macToLaunch);
				sprintf(macToLog,"Received Magic Paquet destined to: %x:%x:%x:%x:%x:%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
				log_message(macToLog, DEBUG);
			}
		}
	}
	return;
}


/*--------------------------------------------------------------------------------------------------*/

void launchVM(char *mac){
	/* function called when a magick packet is received. It parses vm.list 
	 * and if there is a matching mac ask the system to launch the corresponding VM.
	 * */

	FILE *vmlist;
	char temp[CMD_LEN+MAC_LEN];
	char *tempToken;

	formatMac(mac);
	/*Opening KERNEL_CONFIG_FILE*/
	if(!(vmlist = fopen(KERNEL_CONFIG_FILE,"r"))){
		log_message("Fail to find the KERNEL_CONFIG_FILE.\nExiting.", FATAL);
		exit(EXIT_FAILURE);
	}

	while(fgets(temp,CMD_LEN+MAC_LEN,vmlist)){
		tempToken=strtok(temp, ",");
		if(!strncmp(tempToken, mac, MAC_LEN)){
			tempToken = strtok(NULL, ",");
			tempToken ? system(tempToken) : log_message("KERNEL_CONFIG_FILE contains a non well-formated line", WARNING);
			break;
		}
	}
	fclose(vmlist);
}


/*--------------------------------------------------------------------------------------------------*/

/* Function used to make sure that the mac has no ' '. This format MUST be coherent with the format
 * used in vm.list.
 * */
void formatMac(char *mac)
{
	while(*mac){
		if(*mac == ' '){
			*mac = '0';
		}
		++mac;
	}
}

	
/*--------------------------------------------------------------------------------------------------*/

/* EOF */
