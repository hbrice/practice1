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
#include <sys/socket.h>	//needed for socket connections
#include <netinet/in.h> //needed for socket connections
#include <sys/types.h>

#define BUF_SIZE	1024
#define SALT_LENGTH	64
#define KEY_LENGTH	32 
//#define	HASH_FUNCTION = 'SHA256'; //SHA256??
#define DEFAULT_ITERATIONS 1024 //2048 //16*128
#define ALGO = 'GCRY_KDF_PBKDF2';


char buf[BUF_SIZE]; //buffer for read in password
char hmacbuf[1024];
char plaintext[1024];	//buffer to hold inFile text
char *p;		// pointer for password input
//unsigned char *key = '\0'; 		//the key from hashing with password
char key[KEY_LENGTH];
//char *salt;
unsigned char salt[SALT_LENGTH];
gcry_cipher_hd_t handler;
gcry_md_hd_t handler2;
char ciphertext[48] = {0};
char *temp;
char decryptedtext[48] = {0};
int key_length = 128;
char *inFile;
FILE *fp = NULL;
FILE *fpout;
FILE *fpin;
gcry_error_t err = 0;	//for error handling
int lenOfIn;

//stuff for socket
struct hostent *hp;	//host info
struct sockaddr_in serv_addr;	//server address
char sendBuff[1025];
char *uo = ".uo";
char *outputFile; //create hello.txt.uo
/*Save to heap*/
//read in file to array. iterate through 16 bits, save that bit to a temp array
//encrypt the temp array


void promptForPassword(){
	/* prompt user for password and store in p */
	printf("Please enter the password: ");
	fflush (stdout);
	p = fgets (buf, 80, stdin);
	//printf("You entered: %s\n", p);
}

void getkey(){
	/* Generate salt and key for encryption*/
	gcry_randomize(salt, SALT_LENGTH, GCRY_STRONG_RANDOM);
	printf("SALT: %s\n", salt);
	gcry_kdf_derive(p, (strlen(p)-1), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, SALT_LENGTH, DEFAULT_ITERATIONS, key_length, key);
	printf("Derive is done.\n");
	printf("The Key is: %s\n", key);
}


void append_hmac(char *buffer){
	/*Takes in encrypted file and appends hmac*/ 
	//err = 0;
	gcry_md_open(&handler2, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(handler2, key, KEY_LENGTH);
//	gcry_md_write(handler2, hmacbuf, BUF_SIZE);_
	gcry_md_close(handler2);
	printf("The HMAC is appended to the key.\n");
}


void writeToFile(char *buffer){
	/*This is for creating the.uo encrypted file*/
	fpout = fopen("output.txt", "a");
	printf("Output File created.\n");
	if (fpout == NULL){
		printf("Error opening file.\n");
	//	fpout = fopen("output.txt", "w");
	}
	fputs(buffer, fpout);
	fclose(fpout);
	//print text
	//fprintf(fpout, "The encrypted text has been added. %s\n", ciphertext);
}

void encryptfile(char *buffer){
	printf("buffer passed to encrypt %s\n", buffer);
	/* opens the encryption process */
	gcry_cipher_open(&handler, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	gcry_cipher_setkey(handler, (void*)key, KEY_LENGTH);
	gcry_cipher_setiv(handler, (void*)salt, SALT_LENGTH);
	//printf("sizeof(ciphertext): %zd\n", sizeof(ciphertext));
	gcry_cipher_encrypt(handler, ciphertext, sizeof(plaintext), buffer, 16);
	writeToFile(ciphertext);
	gcry_cipher_close(handler);
	printf("Done. Here is the ciphertext: %s\n", ciphertext);
}

void uoenc(){
	/* Function for calling other functions for encrypting a file*/
	printf("Lets encrypt some shizzzz:\n");
	promptForPassword();	//asks user for password
	getkey();
	printf("Encryption is beginning.\n");
	readInFile(fp, inFile, 1024);
	//encryptfile();
	printf("Encryption is done.\n");
}

void uodec(){
	/*Test function to see if encryption is correct*/
	promptForPassword();
	
	gcry_cipher_open(&handler, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	gcry_cipher_setkey(handler, (void*)key, KEY_LENGTH);
	gcry_cipher_setiv(handler, (void*)salt, SALT_LENGTH);
	gcry_cipher_decrypt(handler, decryptedtext, sizeof(ciphertext), ciphertext, 16);
	char *outputFile = "answer.txt"; //create hello.txt.uo
	fpin = fopen(outputFile, "w");
	printf("Output File created.\n");
	if (fpin == NULL){
		printf("Error opening file.\n");
		exit(1);
	}
	fputs(decryptedtext, fpin);
	fclose(fpin);
	//print text
	fprintf(fpin, "The encrypted text has been decryypted. %s\n", decryptedtext);


//	readInFile(fpin, "hello.txt.uo", 100);
	//prompt user for password
	//open a encrypted file
	// decrypt
	//print output

}

int readInFile(FILE *fp, char* filename, int c){
	/* read in a file*/
	int bytes = '\0';
	int bufSize = 16;
	char *encBuffer = NULL;
	char *newBuffer = NULL;
	encBuffer = malloc(bufSize);
	printf("Filename inside readInFile: %s\n", filename);
	fp = fopen(filename, "r");
	if (fp == NULL) { //error handling
		perror("Error opening File.");
		return (-1);
	}else{
		printf("No error while reading input.\n");
	}
	while(!feof(fp)){
		bytes = fread(encBuffer, 1, bufSize, fp);
		if(!bytes){
			break;
		}
		while(bytes < bufSize){
			encBuffer[bytes++] = 0x0;
			printf("encBuffer %s\n", encBuffer);
		}
		int i;
		int diff;
		for(i=0; i<16; i++){
			if(encBuffer[i] == '\0'){
				diff = bufSize - i;
				newBuffer = malloc(diff + 1);
				gcry_create_nonce(newBuffer, diff);
				printf("encBuffer: %s\n", encBuffer);
				printf("newBuffer: %s\n", newBuffer);

				memcpy(encBuffer + i, newBuffer, diff + 1);
				printf("encBuffer after cpy: %s\n", encBuffer);
				break;
			}
		}

		printf("EncBuffer: %s\n", encBuffer);
	//	checkPadding(encBuffer);
		encryptfile(encBuffer);
		//writeToFile(ciphertext);
//		ciphertext = strcat(ciphertext, temp);
		int m;
		for(m=0; m<strlen(ciphertext); m++){	//clear out ciphertext
			ciphertext[m] = '\0';
		}
		//ciphertext = '\0';

	}
	fclose(fp);
	return(0);
}

int main (int argc, char *argv[]){
	char *ipaddress;
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
	
	//input: uoenc.c hello.txt -d ipaddress -l
	/* Parsing of command line */
	
	if(argv[1] == '\0'){
		//then no file name
		perror("Sorry, No Input File Entered.");
		exit(1);
	}else {
		inFile = argv[1];	
		//outputFile = argv[1];
		//outputFile = strcat(outputFile,argv[1]);
		//strcat(outputFile, uo);
		printf("Outputfile: %s\n", outputFile);
	//	lenOfIn = strlen(inFile);
		//printf("lenOfIn %d\n", lenOfIn);
		printf("InputFile:%s\n", argv[1]);
	//	readInFile(fp, argv[1], 100);
	}

	if(argv[2] != '\0'){
		if(argv[2] == "-d"){
			//send to ip address
			ipaddress = argv[3]; //holds the ipadress
			long host = (long)ipaddress;
			//sendToIP(host, )
			printf("IPAddress:%s\n", ipaddress);
		}else if(argv[2] == "-l"){
			//run in local mode and just encrypt a file
		}
		// encrypt file and dump in output file of same name
	}else if(argv[2] == '\0'){
		//run in local mode
	//	perror("You did not enter a third argument. Would you like to send over IP? add -d and IP address. If you would like to encrypt a local file, enter -l.");
	//	exit(1);
	}

	//call uoenc:
	uoenc();
	//uodec();
	//printf("THE PASSWORD IS STILL%s\n", p);
	//printf("Size of password: %zd\n", strlen(p));
	exit(0);
}