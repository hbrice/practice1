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

//hardcode salt

//char hmacbuf[1024];

char *inFile; // File name "hello.txt" stored from argv[1]
//char plaintext[MAX_FILE_SIZE];	//buffer to hold inFile text
char *uo = ".uo";

char ciphertext[BLOCK_LEN] = {0}; //originally 48
//gcry_error_t err = 0;	//for error handling
FILE *pepper = NULL; //used for sending salt

int z =0;
/*Save to heap*/

void promptForPassword(){
	/* prompt user for password and store in p */
	printf("Please enter the password: ");
	fflush (stdout);
	p = fgets (buf, 80, stdin);
	printf("You entered: %s\n", p);
}

void createOutputFile(char *filename){
	/* Takes in input file and returns hello.txt.uo */
	outputFile = filename;
	strcat(outputFile, uo);
	printf("outputFile: %s\n",outputFile);
}

void setIV(){
	/* generate new iv each message */
	printf("Setting the iv.\n");
	iv = gcry_random_bytes_secure(BLOCK_LEN, GCRY_STRONG_RANDOM); 
	printf("Iv is set to: %s\n", iv);

	/* attach to text file */
	pepper = fopen(outputFile, "a");
	printf("outputfile: %s\n", outputFile);
	fputs(iv, pepper);
	fclose(pepper);	
}

void getkey(){
	/* Generate salt and key for encryption*/
	gcry_randomize(salt, (SALT_LENGTH + strlen(p)), GCRY_STRONG_RANDOM);

	printf("SALT: %s\n", salt);
	createOutputFile(inFile);
	pepper = fopen(outputFile, "w");
	printf("outputfile: %s\n", outputFile);
	fputs(salt, pepper);
	fclose(pepper);	
	
	int result = gcry_kdf_derive(p, (strlen(p)-1), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, SALT_LENGTH, DEFAULT_ITERATIONS, KEY_LENGTH, key);
	if(result != 0){
		printf("ERROR getting password!\n");
	}
	printf("Derive is done.\n");
	printf("The Key is: %s\n", key);

	setIV();
}

void append_hmac(char *buffer){
	/*Takes in encrypted file and appends hmac*/ 
//	gcry_md_open(&handler2, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
//	gcry_md_setkey(handler2, key, KEY_LENGTH);
//	gcry_md_write(handler2, hmacbuf, BUF_SIZE);_
//	gcry_md_close(handler2);
	printf("The HMAC is appended to the key.\n");
}

void writeToFile(char *buffer){
	/*This is for creating the.uo encrypted file*/
	fpout = fopen(outputFile, "a");
	printf("this text is writting: %s\n", buffer);

//	printf("Output File created.\n");
	if (fpout == NULL){
		printf("Error opening file.\n");
	//	fpout = fopen("output.txt", "w");
	}
	printf("THIS IS THE [%d] TIME THROUGH WRITETOFILE.\n", z);
	fputs(buffer, fpout);
	fclose(fpout);
	z++;
}

void encryptfile(char *buffer2, unsigned int length){
	/* opens the encryption process */
	gcry_error_t err = 0;
	err = gcry_cipher_open(&handler, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
	if(err){
		printf("ERROR OPEN!!!\n");
		//exit(0);
	}
	err = gcry_cipher_setkey(handler, (void*)key, KEY_LENGTH);
	if(err){
		printf("ERROR SETKEY!!!\n");
		//exit(0);
	}
	err = gcry_cipher_setiv(handler, &iv, BLOCK_LEN);
	if(err){
		printf("ERROR SETIV!!!\n");
		//exit(0);
	}
	err = gcry_cipher_encrypt(handler, buffer2, length, NULL, 0); //changed from buffer, buf len
	if(err){
		printf("ERROR ENCRYPT!!!\n");
		//exit(0);
	}

	writeToFile(buffer2);

	gcry_cipher_close(handler);
	//printf("Done. Here is the ciphertext: %s\n", ciphertext);
}

void uoenc(){
	/* Function for calling other functions for encrypting a file*/
	printf("Lets encrypt some shizzzz:\n");
	promptForPassword();	//asks user for password
	getkey();
	printf("Encryption is beginning.\n");
	readInFile(inFile);
	printf("Encryption is done.\n");
}

void doPadding(char *buffer, int count){
	/* pad the text to be 16 bits */
	int diff;
	char *tempBuffer = NULL;
	while(count < BLOCK_LEN){
		buffer[count] = 0x0; //0x0
		count++;
	}
	int i;
	for(i=0; i < BLOCK_LEN; i++){
		if(buffer[i] == '\0'){
			diff = BLOCK_LEN - i;
			tempBuffer = malloc(diff + 1);
			gcry_create_nonce(tempBuffer, diff);

			memcpy(buffer + i, tempBuffer, diff + 1);
		}
	}
	//encryptfile(buffer);
}

int readInFile(char *filename){
	/* read in a file in 16 bits */
	/**
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
	//	printf("r is: %c\n", r);
		line[n] = r;
		n++;
	}	//reached end of file
	printf("END OF FILE.\n");
	int v;
	v = (int)line[0]; //v is a new line character
	if(v == 10){
		printf("No need to pad\n");
	}else{
		///*do padding
		doPadding(line, n);
	}
	printf("finished writing\n");
*/
	int bytes = '\0';
	char *encBuffer = NULL;
	char *newBuffer = NULL;
	int size = 16;
	encBuffer = malloc(BLOCK_LEN);
//	printf("inFile: %s\n", filename);

	//FILE NAME IS MESSED UP
	fp = fopen("hello.txt", "r");
	while (!feof(fp)){
		bytes = fread(encBuffer,1,size,fp);
		if(!bytes){
			break;
		}
		while(bytes<size){
			encBuffer[bytes++] = 0x0;
		}
		int i;
		int diff;
		printf("encBuffer before encryption:  %s\n", encBuffer);
		for(i=0; i<size; i++){
			if(encBuffer[i] == '\0'){
				diff = size - i;
				newBuffer = malloc(diff + 1);
				gcry_create_nonce(newBuffer, diff);

				memcpy(encBuffer + i, newBuffer, diff + 1);
				break;
			}
		}
		printf("encbuffer sending to encryption: %s\n", encBuffer);
		encryptfile(encBuffer, size);
	//	writeToFile(encBuffer);
	}
	fclose(fp);
	return(0);
}

void checkVersion_setup(){
	/* check ther version and setup gcrypt */
	if(!gcry_check_version("1.5.0")){
		printf("Starting gcrypt failed.\n");
	}else{
		printf("You are starting gcrpyt.\n");
	}
	//For encryption.. make secure memory...
/*	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	printf("Done.\n");
*/
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	printf("Initialization is Done.\n");
}

int main (int argc, char *argv[]){
	char *ipaddress;
	int i;
	char *fileToRead = NULL;
	
//	checkVersion_setup();
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
