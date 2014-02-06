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
#include <unistd.h>
//#include "uodec.h"

#define SALT_LENGTH	64
#define BLOCK_LEN 16
#define BUF_SIZE	1024
#define MAX_FILE_SIZE 1024
#define KEY_LENGTH	32 
#define DEFAULT_ITERATIONS 1024 //2048 //16*128

/* FIle pointers for reading files */
FILE *fp = NULL;	//file pointer for readInFile
FILE *fpout;	//file pointer for writeToFile
FILE *readSalt;

/* Buffer for storing key */
char key[KEY_LENGTH];

/* For password */
char buf[BUF_SIZE]; //buffer for read in password
char *p;		// pointer for password input

/* Buffer for storing salt */

unsigned char salt[SALT_LENGTH];
unsigned char iv[BLOCK_LEN];

/* Handlers for encryption */
gcry_cipher_hd_t handler;
gcry_md_hd_t handler2;

char *outputFile; //create hello.txt.uo
char *decryptBuf = NULL;
char decryptedtext[16] = {0};
FILE *fpin = NULL; //file pointer for readEncFile
char *inFile;

void promptForPassword(){
	/* prompt user for password and store in p */
	printf("Please enter the password: ");
	fflush (stdout);
	p = fgets (buf, 80, stdin);
	printf("You entered: %s\n", p);
}

void getkey(){
	gcry_error_t err = 0;
	/* Get key for decryption*/
//	printf("SALT: %s\n", salt);			//changed SHA256
	err = gcry_kdf_derive(p, (strlen(p)-1), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, SALT_LENGTH, DEFAULT_ITERATIONS, KEY_LENGTH, key);
	
	if(err){
		printf("ERROR!!! Error getting key.\n");
		//exit(0);
	}
	printf("Derive is done.\n");
//	printf("The Key is: %s\n", key);
}

void writeOtherFile(char *buffer3){
	/*This is for creating the.uo encrypted file*/
	fpin = fopen("answer.txt", "a");
	if (fpin == NULL){
		printf("Error opening file.\n");
		//fpin = fopen("output.txt", "w");
	}
	fputs(buffer3, fpin);
	printf("This is decrypted: %s\n", buffer3);
	fclose(fpin);
}

void decryptFile(char *bufferr, unsigned int length){
	/* Read 16 bits at a time and decrypt*/
	gcry_error_t err = 0;
	err = gcry_cipher_open(&handler, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	if(err){
		printf("ERROR OPEN!!!\n");
		//exit(0);
	}
	err = gcry_cipher_setkey(handler, key, KEY_LENGTH);
	if(err){
		printf("ERROR SETKEY!!!\n");
		//exit(0);
	}
	err = gcry_cipher_setiv(handler, &iv, BLOCK_LEN);
	if(err){
		printf("ERROR SETIV!!!\n");
		//exit(0);
	}
	err = gcry_cipher_decrypt(handler, bufferr, (size_t)length, NULL, 0);
	if (err != 0){
		printf("ERROR DECRYPTING!!!\n");
	}
	gcry_cipher_close(handler);
	

	writeOtherFile(bufferr);
	//writeOtherFile(buffer);
}

//store all of file into array. then start loop at 80

int readEncFile(){
	/* read in a file*/

	int bufSize = 16;
	char line[bufSize];
	fp = fopen("hello.txt.uo", "r");

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
			decryptFile(line, bufSize);
			n=0;
		}
		r = (char)m;
		line[n] = r;
		n++;
	}	//reached end of file
	printf("END OF FILE.\n");

//	decryptFile(line);
	printf("finished writing\n");
	fclose(fp);
	return(0);

}

void uodec(){
	/* function to see if encryption is correct*/

	printf("Lets decrypt some shizzzz:\n");
	int size = 16;
//	printf("salt is: %s\n", salt);
//	printf("iv is: %s\n", iv);
//	promptForPassword();
//	getkey();
//	readEncFile(fpin, MAX_FILE_SIZE);
	/* read in salt and iv for variables  */
	int bytes = '\0';
	decryptBuf = malloc(BLOCK_LEN);
	promptForPassword();

	readSalt = fopen(inFile, "r");
	fread(salt, (64 + strlen(p)), 1, readSalt); //save salt to variable
	printf("salt is: %s\n", salt);

	fread(iv, 16, 1, readSalt); //save iv to variable
	printf("iv is: %s\n", iv);
	//checkVersion_setup();

	getkey();
	printf("key is: %s\n", key);
	
	while(!feof(readSalt)){
	//	printf("inside while loop.\n");
		bytes = fread(decryptBuf, 1, size, readSalt);
		if(!bytes){
			printf("We are finished decrypted.\n");
			break;
		}
		printf("sending this to be decrypted: %s\n", decryptBuf);
		decryptFile(decryptBuf, size);
		//printf("This is decrypted: %s\n", decryptBuf);
		//writeOtherFile(decryptBuf);
	}

	fclose(readSalt);

	/* close functions */
	//fprintf(fpin, "The encrypted text has been decryypted. %s\n", decryptedtext);
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
	char *inputFile;
	char *port;
	int i;

	checkVersion_setup();

	//input: uodec.c hello.txt.uo 
	/* Parsing of command line */
	
	int dflag = 0;
	int lflag = 0;
	char *cvalue = NULL;
	int index;
	int c;

	inFile = argv[1];
	argv[1] = argv[0];
	argv++;
	argc--;

	while((c = getopt (argc, argv, "l")) != -1){
		switch(c){
			case 'd':
				cvalue = optarg;
				port = cvalue;
				break;
			case 'l':
				lflag = 1;
				break;
			case '?':
				fprintf(stderr, "Unknown input\n");
				exit(1);
		}
	}
	printf("dflag = %d, lflag = %d, cvalue = %s\n", dflag, lflag, cvalue);
	for(index = optind; index < argc; index++){
		printf("Non-option argument %s\n", argv[index]);
		return 0;
	}

	uodec();
	exit(0);
}
