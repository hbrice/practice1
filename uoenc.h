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

#define BUF_SIZE	1024
#define MAX_FILE_SIZE 1024
#define SALT_LENGTH	64
#define KEY_LENGTH	32 
#define BLOCK_LEN 16
#define DEFAULT_ITERATIONS 1024 //2048 //16*128


/* Buffer for storing key */
char key[KEY_LENGTH];

/* For password */
char buf[BUF_SIZE]; //buffer for read in password
char *p;		// pointer for password input

/* Buffer for storing salt */
unsigned char salt[SALT_LENGTH];
unsigned char *iv;

/* Handlers for encryption */
gcry_cipher_hd_t handler;
gcry_md_hd_t handler2;

char *outputFile; //create hello.txt.uo

/* FIle pointers for reading files */
FILE *fp = NULL;	//file pointer for readInFile
FILE *fpout;	//file pointer for writeToFile


/* prompt user for password and store in p */
void promptForPassword();

/* Generate salt and key for encryption*/
void getkey();

/* generate new iv each message */
void setIV();

/* Takes in input file and returns hello.txt.uo */
void createOutputFile(char *filename);

/*Takes in encrypted file and appends hmac*/ 
void append_hmac(char *buffer);

/*This is for creating the.uo encrypted file*/
void writeToFile(char *buffer);

/* opens the encryption process */
void encryptfile(char *buffer);

/* Function for calling other functions for encrypting a file*/
void uoenc();

/* read in a file*/
int readInFile(FILE *fp, char* filename, int c);

/* check ther version and setup gcrypt */
void checkVersion_setup();

#endif