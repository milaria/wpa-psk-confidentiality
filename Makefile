CC = cc -g $(CFLAGS)
CFLAGS = -Wall -Wextra -lpcap -lcrypto

DIR = NetSec/

all: ns_project

ns_project: ns_project.o enc_functions.o util_functions.o
	$(CC) -o ns_project ns_project.o enc_functions.o util_functions.o $(CFLAGS)

ns_project.o: $(DIR)main.c enc_functions.o util_functions.o
	$(CC) -c $(DIR)main.c -o ns_project.o

enc_functions.o: $(DIR)enc_functions.c $(DIR)enc_functions.h
	$(CC) -c $(DIR)enc_functions.c -o enc_functions.o

util_functions.o: $(DIR)util_functions.c $(DIR)util_functions.h
	$(CC) -c $(DIR)util_functions.c -o util_functions.o

clean:
	rm -rf *.o *.dSYM ns_project
