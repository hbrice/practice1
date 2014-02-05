/*
* Holly Brice
* Cis 433: Network Security
* 1/30/14
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <gcrypt.h>
#include "uoenc.h"

gcry_cipher_hd_t handler;
char key[KEY_LENGTH];
unsigned char salt[SALT_LENGTH];
char decryptedtext[16] = {0};
FILE *fpin;
char *inFile;

void promptForPassword(){
	/* prompt user for password and store in p */
	printf("Please enter the password: ");
	fflush (stdout);
	p = fgets (buf, 80, stdin);
	printf("You entered: %s\n", p);
}

void getkey(){
	/* Get key for decryption*/
	printf("SALT: %s\n", salt);
	gcry_kdf_derive(p, (strlen(p)-1), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, SALT_LENGTH, DEFAULT_ITERATIONS, KEY_LENGTH, key);
	printf("Derive is done.\n");
	printf("The Key is: %s\n", key);
//	setIV();
}



void setIV(){
	/* generate new iv each message */
	printf("Setting the iv.\n");
	iv = gcry_random_bytes_secure(BLOCK_LEN, GCRY_STRONG_RANDOM); 
	printf("Iv is set to: %s\n", iv);
}

void writeOtherFile(char *buffer){
	/*This is for creating the.uo encrypted file*/
	fpin = fopen("answer.txt", "a");
	printf("Output File created.\n");
	if (fpin == NULL){
		printf("Error opening file.\n");
		//fpin = fopen("output.txt", "w");
	}
	fputs(buffer, fpin);
	printf("buffer inserted is: %s\n",buffer);
	fclose(fpin);
}

void decryptFile(char *buffer){
	/* Read 16 bits at a time and decrypt*/
	gcry_cipher_open(&handler, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	gcry_cipher_setkey(handler, (void*)key, KEY_LENGTH);
	gcry_cipher_setiv(handler, (void*)salt, SALT_LENGTH);
	gcry_cipher_decrypt(handler, decryptedtext, 16, buffer, 16);
	writeOtherFile(decryptedtext);
}

int readEncFile(FILE *fp, int c){
	/* read in a file*/
	int bufSize = 16;
	char line[bufSize];
	fp = fopen(inFile, "r");
	printf("inFile %s\n", inFile);
	int n=0; //count up to 1 - 16
	int m; // used to hold char value
	char r; // used to cast char value
	if (fp == NULL) { //error handling
		perror("Error opening File.");
		return (-1);
	}else{
		printf("No error while reading input.\n");
	}
	while((m = fgetc(fp)) != EOF){	//fill line with 16 bits
		if(n==bufSize){
			decryptFile(line);
			int j;
			for (j = 0; j <bufSize; j++){	//nulled out line
				line[j] = '\0';
			}
			n=0;
		}
		r = (char)m;
		printf("r is: %c\n", r);
		line[n] = r;
		n++;
	}	//reached end of file
	printf("END OF FILE.\n");
	int v;
	v = (int)line[0]; //v is a new line
	if(v == 10){
		printf("No need to pad\n");
	}else{
		/*do padding*/
		while(n < bufSize){
			line[n] = 0x0;
			n++;
			printf("line %s\n", line);
		}
		decryptFile(line);
	}
	printf("finished writing\n");

	fclose(fp);
	return(0);
}

void uodec(){
	/*Test function to see if encryption is correct*/
	printf("Lets decrypt some shizzzz:\n");
	promptForPassword();
	getkey();
	readEncFile(fpin, MAX_FILE_SIZE);
/*	char *outputFile = "answer.txt"; //create hello.txt.uo
	fpin = fopen(outputFile, "w");
	printf("Output File created.\n");
	if (fpin == NULL){
		printf("Error opening file.\n");
		exit(1);
	}
	fputs(decryptedtext, fpin);
	fclose(fpin);
	//print text */
	fprintf(fpin, "The encrypted text has been decryypted. %s\n", decryptedtext);
}

int main (int argc, char *argv[]){
	char *inputFile;
	int i;
	
	//For encryption.. make secure memory...
	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	printf("Done.\n");

	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	printf("Done.\n");

	//Prints each arg on the command line:
	for (i = 0; i < argc; i++){
		printf("arg %d: %s\n", i, argv[i] );
	}
	
	//input: uodec.c hello.txt.uo 
	/* Parsing of command line */
	
	if(argv[1] == '\0'){
		//then no file name
		perror("Sorry, No Input File Entered.");
		exit(1);
	}else if(argv[1] == "-l"){
		// run local
		if(argv[2] == '\0'){
			perror("Sorry you forgot the input file");
			exit(1);
		}
		inFile = argv[2];	
		printf("InputFile:%s\n", inFile);
	}
	inFile = argv[1];	
	printf("InputFile:%s\n", inFile);

	uodec();
	//printf("THE PASSWORD IS STILL%s\n", p);
	//printf("Size of password: %zd\n", strlen(p));
	exit(0);
}
