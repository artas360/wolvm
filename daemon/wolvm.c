/* WOLVM, a Wake On Lan extension for virtual machines.
 * Below is the WOLVM kernel source code.
 *
 * File		: wolvm_unix.c
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
 * Requires	: You must have the libpcap-dev packet installed on your system.
 *
 * Compile	: gcc -lpcap -o wolvm wolvm_unix.c wolvm_config.c
 * */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <pcap.h>
#include <libconfig.h>

/* Defines the directory in whitch the daemon will be running */
#define RUNNING_DIR 		"/tmp/"
/* Name of the lock file */
#define LOCK_FILE   		"WOLVM.lock"
/* Path to the log file */
#define LOG_FILE    		"/tmp/WOLVM.log"
/* Path to the KERNEL_CONFIG_FILE, this file is refered to as vm.list in the WOLVM 
 * configuration script*/
#define KERNEL_CONFIG_FILE      "/etc/wolvm/vm.list"
/* Max size of log messages */
#define LOG_MAX_SIZE 		100
/* Max size of the Mac addresses returned by pcap. 16 should be enough but... */
#define MAC_LEN			20
/* Max size of the commands extracted from vm.list */
#define CMD_LEN 		100
/* Max number of the packets bites to be read */
#define MAXBYTES2CAPTURE 	2048

/*--------------------------------------------------------------------------------------------------*/
/*----------------------------------------------HEADERS---------------------------------------------*/
/*--------------------------------------------------------------------------------------------------*/

void launchVM(char *mac);
void formatMac(char *mac);
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet);
void badUsage(const char *progName);
void run(const char *iface);
void signal_handler(int sig);
void daemonize();
void start(const char *iface);
void stop();

typedef enum LOGLVL LOGLVL;
enum LOGLVL
{
	DEBUG,
	INFORMATION,
	WARNING,
	ERROR,
	FATAL
};
/*--------------------------------------------------------------------------------------------------*/
/*-----------------------------------------GLOBAL VARIABLES-----------------------------------------*/
/*--------------------------------------------------------------------------------------------------*/

int verbosity;


/*--------------------------------------------------------------------------------------------------*/
/*----------------------------------------------SOURCES---------------------------------------------*/
/*--------------------------------------------------------------------------------------------------*/

int main(int argc, char **argv)
{
	int starting = 0, stopping = 0; /* boolean */
	const char *progName = argv[0], *iface;
	config_t cfg;

	if(argc > 4 || argc < 2)
	{
		badUsage(progName);
	}

	/* Reading configuration file */

	config_init(&cfg);
	if(config_read_file(&cfg, "wolvm.conf") != CONFIG_TRUE) {
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
		config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return(EXIT_FAILURE);
	}
	
	if(!(config_lookup_string(&cfg, "iface", &iface))){
		fprintf(stderr, "Info : no device specified, defaulting.");
	}
	config_lookup_int(&cfg, "verbosity", &verbosity);


	/* Parsing arguments  (K & R method) */
	/* Arguments have priority compared to the conf file */
	while(--argc)
	{
		if(strcmp(*++argv,"-v") == 0){
			verbosity = 1;
			printf("Starting in debbug mode.\n");
		}

		else if(strcmp(*argv, "start") == 0){
			if(argc == 1)
				starting = 1;
			else{
				iface = *++argv;
				starting = 1;
				--argc;
			}
		}

		else if (strcmp(*argv, "stop")  == 0)
			stopping = 1;
		else    
			badUsage(progName);
	}

	/* Launching wolvm with the right options */
	
	if(starting)
		start(iface);
	else if(stopping)
		stop();
	
	return EXIT_SUCCESS;
}


/*--------------------------------------------------------------------------------------------------*/

void badUsage(const char *progName)
{
	fprintf(stderr, "Usage: %s [-v] {start|stop} [iface]\n", progName);
	exit(EXIT_FAILURE);
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

void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet)
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

/* Main function. Opens network interface and calls pcap_loop() */
void run(const char *iface)
{
	int count = 0;
	pcap_t *descr = NULL;
	char errbuf[PCAP_ERRBUF_SIZE], *device=NULL;
	char message[50];
	memset(errbuf,0,PCAP_ERRBUF_SIZE);

	if(strncmp(iface, "auto", 5) != 0)								  /* If user supplied interface name, use it. */
	{
		device = iface;
	}

	else										  /* Get the name of the first device suitable for capture */
	{
		if((device = pcap_lookupdev(errbuf)) == NULL)
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

	/* Loop forever & call processPacket() for every received packet*/
	if(pcap_loop(descr, -1, processPacket, (u_char*)&count ) == -1)
	{
		log_message(pcap_geterr(descr), FATAL);
		exit(EXIT_FAILURE);
	}
}


/*--------------------------------------------------------------------------------------------------*/

void signal_handler(int sig)
{
	switch(sig)
	{
		case SIGHUP:
			log_message("hangup signal catched", INFORMATION);
			break;
		case SIGTERM:
			log_message("terminate signal catched", INFORMATION);
			exit(EXIT_SUCCESS);
			break;
	}
}


/*--------------------------------------------------------------------------------------------------*/

/* Function used to fork the calling process into a daemon.
 * Closes all parent's file descriptors, changes the running dir... To obtain a 'clean' UNIX daemon.
 * */
void daemonize()
{
	int i,lfp;
	char str[10];
	if(getppid()==1) return;					  /* already a daemon */
	i=fork();
	if (i<0){							  /* fork error */
		log_message("Can not fork the process, aborting.\n", FATAL);
		exit(EXIT_FAILURE);
	}		
	if (i>0) exit(EXIT_SUCCESS);					  /* parent exits */
	/* child (daemon) continues */
	setsid();							  /* obtain a new process group */
	/* close all descriptors */
	for (i=getdtablesize();i>=0;--i) close(i);
	/* handle standart I/O */
	i=open("/dev/null",O_RDWR); dup(i); dup(i);
	umask(027);							  /* set newly created file permissions */
	chdir(RUNNING_DIR);						  /* change running directory */
	lfp=open(LOCK_FILE,O_RDWR|O_CREAT,0644);
	if (lfp<0){							  /* can not open */
		log_message("Can not open lock file, aborting.", FATAL);
		exit(EXIT_FAILURE);
	}
	/* can not lock */
	if (lockf(lfp,F_TLOCK,0)<0){ 
		log_message("Can not lock lock file, aborting.", FATAL);
		exit(EXIT_FAILURE);
	}
	/* first instance continues */
	sprintf(str,"%d\n",getpid());
	write(lfp,str,strlen(str));					  /* record pid to lockfile */
	signal(SIGCHLD,SIG_IGN);					  /* ignore child */
	signal(SIGTSTP,SIG_IGN);					  /* ignore tty signals */
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	/* catch hangup signal */
	signal(SIGHUP,signal_handler);
	/* catch kill signal */
	signal(SIGTERM,signal_handler);
}


/*--------------------------------------------------------------------------------------------------*/

void start(const char *iface)
{
	/* This function makes sure that no other instance of WOLVM is running, by checking the lock
	 * on LOCK_FILE. Aborts the execution if another WOLVM daemon instance is already running.
	 * */
	int lfp;
	char a[50]={0};
	strcat(a, RUNNING_DIR);
	strcat(a, LOCK_FILE);
	fprintf(stdout, "Starting service WOLVM:");
	lfp=open(a,O_RDWR);
	if (lfp>0)
	{
		if(lockf(lfp,F_TLOCK,0)<0)
		{
			/* can not lock */
			fprintf(stderr,"Service WOLVM already running.\n");
			close(lfp);
			exit(EXIT_FAILURE);
		}
	}
	fprintf(stdout, "...Done\n");
	close(lfp);

	log_message("Starting service WOLVM.", INFORMATION);

	daemonize();
	run(iface);
}


/*--------------------------------------------------------------------------------------------------*/

void stop()
{
	/* This function ask the running instance of the WOLVM daemon to stop (if any).
	 * Ends the program if no instance is running.
	 * */
	int lfp;
	FILE *file;
	char a[50]={0};
	char pid[10]={0};
	strcat(a, RUNNING_DIR);
	strcat(a, LOCK_FILE);
	fprintf(stdout, "Stopping service WOLVM: ");
	lfp=open(a,O_RDWR);
	if (lfp<0)
	{
		fprintf(stdout, "No instance to stop.\n");
		close(lfp);
		exit(EXIT_FAILURE);
	}
	if (lockf(lfp,F_TLOCK,0)>=0)				  /* can lock */
	{
		fprintf(stdout,"No instance to stop.\n");
		exit(EXIT_FAILURE);
	}

	else
	{
		fgets(pid, 9, file=fopen(a, "r"));
		fclose(file);
		kill(atoi(pid), SIGTERM);
		fprintf(stdout, "...Done.\n");
		log_message("Stoping service WOLVM.\n\n\n", INFORMATION);
	}

	close(lfp);
}


/*--------------------------------------------------------------------------------------------------*/

/* EOF */
