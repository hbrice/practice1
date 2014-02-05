/*
* Holly Brice
* Cis 433: Network Security
* 1/24/14
* gcc -o uoenc uoenc.c -lgcrypt to run
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <gcrypt.h>
#include "uoenc.h"

//hardcode salt

//char hmacbuf[1024];

char *inFile; // File name "hello.txt" stored from argv[1]
char plaintext[MAX_FILE_SIZE];	//buffer to hold inFile text
char *uo = ".uo";
char *outputFile; //create hello.txt.uo

char ciphertext[BLOCK_LEN] = {0}; //originally 48
//char *temp;
//char decryptedtext[48] = {0};

gcry_error_t err = 0;	//for error handling

/*Save to heap*/

void promptForPassword(){
	/* prompt user for password and store in p */
	printf("Please enter the password: ");
	fflush (stdout);
	p = fgets (buf, 80, stdin);
	printf("You entered: %s\n", p);
}

void getkey(){
	/* Generate salt and key for encryption*/
	gcry_randomize(salt, SALT_LENGTH, GCRY_STRONG_RANDOM);
	printf("SALT: %s\n", salt);
	gcry_kdf_derive(p, (strlen(p)-1), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, SALT_LENGTH, DEFAULT_ITERATIONS, KEY_LENGTH, key);
	printf("Derive is done.\n");
	printf("The Key is: %s\n", key);
	setIV();
}

void setIV(){
	/* generate new iv each message */
	printf("Setting the iv.\n");
	iv = gcry_random_bytes_secure(BLOCK_LEN, GCRY_STRONG_RANDOM); 
	printf("Iv is set to: %s\n", iv);
}

void createOutputFile(char *filename){
	/* Takes in input file and returns hello.txt.uo */
	outputFile = filename;
	strcat(outputFile, uo);
	printf("outputFile: %s\n",outputFile);
}

void append_hmac(char *buffer){
	/*Takes in encrypted file and appends hmac*/ 
	gcry_md_open(&handler2, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(handler2, key, KEY_LENGTH);
//	gcry_md_write(handler2, hmacbuf, BUF_SIZE);_
	gcry_md_close(handler2);
	printf("The HMAC is appended to the key.\n");
}

void writeToFile(char *buffer){
	/*This is for creating the.uo encrypted file*/
	createOutputFile(inFile);
	fpout = fopen(outputFile, "a");
	printf("Output File created.\n");
	if (fpout == NULL){
		printf("Error opening file.\n");
	//	fpout = fopen("output.txt", "w");
	}
	fputs(buffer, fpout);
	fclose(fpout);
}

void encryptfile(char *buffer){
	printf("buffer passed to encrypt %s\n", buffer);
	/* opens the encryption process */
	err = gcry_cipher_open(&handler, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	gcry_cipher_setkey(handler, (void*)key, KEY_LENGTH);
	gcry_cipher_setiv(handler, &iv, BLOCK_LEN);
	gcry_cipher_encrypt(handler, ciphertext, sizeof(plaintext), buffer, BLOCK_LEN);
	writeToFile(ciphertext);
	gcry_cipher_close(handler);
	//printf("Done. Here is the ciphertext: %s\n", ciphertext);
}

void uoenc(){
	/* Function for calling other functions for encrypting a file*/
	printf("Lets encrypt some shizzzz:\n");
	promptForPassword();	//asks user for password
	getkey();
	printf("Encryption is beginning.\n");
	readInFile(fp, inFile, MAX_FILE_SIZE);
	printf("Encryption is done.\n");
}

int readInFile(FILE *fp, char* filename, int c){
	/* read in a file*/
	int bufSize = 16;
	char line[bufSize];
	printf("Filename inside readInFile: %s\n", filename);
	fp = fopen(filename, "r");
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
			encryptfile(line);	//ready to encrypt
			//writeToFile(line);
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
	v = (int)line[0]; //v is a new line character
	if(v == 10){
		printf("No need to pad\n");
	}else{
		/*do padding*/
		while(n < bufSize){
			line[n] = 0x0; //0x0
			n++;
			printf("line %s\n", line);
		}
		encryptfile(line);
		//writeToFile(line);
	}
	printf("finished writing\n");

	fclose(fp);
	return(0);
}

void doPadding(char *buffer, int count){
	/* pad the text to be 16 bits */
	
}


void checkVersion_setup(){
	/* check ther version and setup gcrypt */
	if(!gcry_check_version("1.5.0")){
		printf("Starting gcrypt failed.\n");
	}else{
		printf("You are starting gcrpyt.\n");
	}
	//For encryption.. make secure memory...
	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	printf("Done.\n");

	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	printf("Initialization is Done.\n");
}

int main (int argc, char *argv[]){
	char *ipaddress;
	int i;
	
	checkVersion_setup();
	/* Parse the command line */
	//Prints each arg on the command line: take out later***
	for (i = 0; i < argc; i++){
		printf("arg %d: %s\n", i, argv[i] );
	}	
	//input: uoenc.c hello.txt -d ipaddress -l
	/* Parsing of command line */
	
	if(argv[1] == '\0'){
		//then no file name
		perror("Sorry, No Input File Entered.");
		exit(1);
	}else {
		inFile = argv[1];	
		printf("InputFile:%s\n", argv[1]);
	}
	if(argv[2] != '\0'){
		if(argv[2] == "-d"){
			//send to ip address
			ipaddress = argv[3]; //holds the ipadress
			printf("IPAddress:%s\n", ipaddress);
		}else if(argv[2] == "-l"){
			printf("You are encrypting locally.\n");
			//run in local mode and just encrypt a file
		}
		// encrypt file and dump in output file of same name
	}else if(argv[2] == '\0'){ //run in local mode
		printf("You didn't add flags, default is to run locally.\n");
		
	}
	uoenc();

	exit(0);
}
