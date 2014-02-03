/*
* Holly Brice
*/
#ifndef UOENC_H_
#define UOENC_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <gcrypt.h>
#include <sys/socket.h>	//needed for socket connections
#include <netinet/in.h> //needed for socket connections
#include <sys/types.h>

/*sends file to specified IP address*/
int sendToIP(long hostname, unsigned short int port);

/* prompt user for password and store in p */
void promptForPassword();

/* Generate salt and key for encryption*/
void getkey();

/*This is for creating the.uo encrypted file*/
void writeToFile(char *buffer);

/* opens the encryption process */
void encryptfile();

/* Function for calling other functions for encrypting a file*/
void uoenc();

/* read in a file*/
int readInFile(FILE *fp, char* filename, int c);

#endif