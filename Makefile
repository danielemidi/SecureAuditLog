CC=gcc
CFLAGS=

all: main

main:
	$(CC) $(CFLAGS) *.c -o main -lssl

clean:
	rm -rf *o *.log main
    
deepclean:
	rm -rf *o *.log *.pem main