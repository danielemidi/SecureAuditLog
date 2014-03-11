Secure Audit Log
Author: Daniele MIDI (dmidi@purdue.edu)

--------
OVERVIEW
--------
Very often, sensitive information have to be kept in log files on untrusted machines.
In the event that an attacker captures this machine, we would like to guarantee that he will gain little or no information from the log files, and to limit his ability to corrupt the log files.
The protocol implemented in this Secure Audit Log system is described in the paper "Secure Audit Logs to Support Computer Forensics", by Bruce Schneier and John Kelsey, available at http://www.schneier.com/paper-auditlogs.html.


--------
MAKEFILE
--------
make
	this will compile all the necessary files into "main".
make clean
	will delete all the binary files, plus all the log/output files (extension *.log) in the current directory.
make deepclean
	will delete all the binary files, plus all the log/output files (extension *.log), plus all the keys and 
    certificates (extension *.pem) in the current directory.


--------------
KEY GENERATION
--------------
The script gen_keys.sh will clear all possible previous key files in the current directory (extension *.pem).
Then it will generate private RSA keys (2048 bit) and self-signed public key certificates for both U and T.
The script will generate the following files:
  - keyT.pem : T's private key
  - pub-keyT.pem : T's self-signed public key certificate
  - keyU.pem : U's private key
  - pub-keyU.pem : U's self-signed public key certificate


----------------------
HOW TO RUN THE PROGRAM
----------------------
Execute the following commands:
    ./gen_keys.sh
    make clean
    make
    ./main
    
(See section "Sample execution" below in this document for an example of expected execution and output.)


------------------
AVAILABLE COMMANDS
------------------
EXIT
    This closes the program.

CREATELOG logname
    This creates a logfile called "<logname>.log" in the current directory.

ADD msg
    This adds a new entry with content "msg" to the currently open log.
    msg can be 255 characters long at most.
    In case of success, the index of the new entry is displayed.

CLOSELOG
    This closes the current log, adding the closing entry.

VERIFY entryindex
    This verifies the entry at index entryindex. If the verification succeeds, the entry content is displayed.

VERIFYALL logfile outputfile
    This read a logfile called "<logname>.log" from the current directory.
    It verifies all the entries and decrypts them all into a file called "<outputfile>.log" from the current directory.


----------------
SAMPLE EXECUTION
----------------
> createlog log7
Log log7 created successfully.
> add Primo
Adding log entry Primo... Added log entry number 2.
> add Secondo
Adding log entry Secondo... Added log entry number 3.
> add Contorno
Adding log entry Contorno... Added log entry number 4.
> add Dolce
Adding log entry Dolce... Added log entry number 5.
> add Ammazzacaffe
Adding log entry Ammazzacaffe... Added log entry number 6.
> closelog
Closing log... Log closed.
> verify 4
Verifying entry 4... Contorno
> verifyall log7 a7
Verifying all entries of log log7 to file a7...
All entries of log log7 verified into file a7...
> exit