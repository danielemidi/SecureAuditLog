#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "protocol.h"
#include "logentrytypes.h"

#define CMD_LENGTH    255
#define PARAM_LENGTH  255

void createlog(char *fname);
void addentry(char *entry);
void closelog();
void verifyentry(int entryindex);
void verifyallentries(char *logfile, char *outfile);

char *get_line (char *s, size_t n, FILE *f);


int main() {
    int  number;
    char currcmd[CMD_LENGTH];
    char param1[PARAM_LENGTH];
	char param2[PARAM_LENGTH];
	int  param1n;
		
	init_crypto();
    
	fflush(stdout);
	
    while(1) {
        printf("> ");
    	fflush(stdout);
        get_line (currcmd, CMD_LENGTH, stdin);
        
		if (strcmp(currcmd, "quit")==0 || strcmp(currcmd, "exit")==0) {
			break;
		} 
		else if (strncmp(currcmd, "createlog ", strlen("createlog "))==0 && sscanf(currcmd, "createlog %s", param1 ) == 1) {
			createlog(param1);
		} 
		else if (strncmp(currcmd, "add ", strlen("add "))==0 && sscanf(currcmd, "add %s", param1 ) == 1) {
			addentry(currcmd + strlen("add "));
		} 
		else if (strcmp(currcmd, "closelog")==0) {
			closelog();
		} 
		else if (strncmp(currcmd, "verifyall ", strlen("verifyall "))==0 && sscanf(currcmd, "verifyall %s %s", param1, param2 ) == 2) {
			verifyallentries(param1, param2);
		} 
		else if (strncmp(currcmd, "verify ", strlen("verify "))==0 && sscanf(currcmd, "verify %d", &param1n ) == 1) {
			verifyentry(param1n);
		} 
		else {
			printf("Invalid command.\r\n");
		}
    	fflush(stdout);
    }

	uninit_crypto();
	
    return 0;
}




/******************************/
/* PUBLIC COMMANDS FUNCTIONS  */

void createlog(char *logname) {
	printf("Creating log %s... ", logname);
    fflush(stdout);
	
    initlog_U(logname);
	
	printf("Log %s created successfully.\r\n", logname);
    fflush(stdout);
}


void addentry(char *entry) {
	FILE *fp;
	
	printf("Adding log entry %s... ", entry);
    fflush(stdout);
	
	int newentryindex = buildandstoreentry(NORMALENTRYTYPE, entry, strlen(entry));
	
	printf("Added log entry number %d.\r\n", newentryindex);
    fflush(stdout);
}


void closelog() {
	FILE *fp;
	
	printf("Closing log... ");
    fflush(stdout);
	
	closelog_U();
	
	printf("Log closed.\r\n");
    fflush(stdout);
}


void verifyentry(int entryindex) {
	FILE *fp;
	
	printf("Verifying entry %d... ", entryindex);
    fflush(stdout);
	
	char *result = verifyentry_V(entryindex);
    if(result == NULL)
        printf("Failed verification.\r\n");
    else
        printf("%s\r\n", result);
    free(result);
    fflush(stdout);
}


void verifyallentries(char *logname, char *outfile) {
	FILE *fpout;
	char outfilename[255];
	
	printf("Verifying all entries of log %s to file %s...\r\n", logname, outfile);
    fflush(stdout);
	
    verifyallentries_T(logname, outfile);
	
	printf("All entries of log %s verified into file %s...\r\n", logname, outfile);
    fflush(stdout);
}



/******************************/
/* INTERNAL SUPPORT FUNCTIONS */

char *get_line(char *s, size_t n, FILE *f)
{
  char *p = fgets (s, n, f);

  if (p != NULL) {
    size_t last = strlen (s) - 1;

    if (s[last] == '\n') s[last] = '\0';
  }
  return p;
}

