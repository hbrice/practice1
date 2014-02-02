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
char plaintext[100];	//buffer to hold inFile text
char *p;		// pointer for password input
//unsigned char *key = '\0'; 		//the key from hashing with password
char key[KEY_LENGTH];
//char *salt;
unsigned char salt[SALT_LENGTH];
gcry_cipher_hd_t handler;
char ciphertext[48] = {0};
int key_length = 128;
char *inFile;
FILE *fp = NULL;
FILE *fpout;
gcry_error_t err = 0;	//for error handling
int lenOfIn;

//stuff for socket
struct hostent *hp;	//host info
struct sockaddr_in serv_addr;	//server address
char sendBuff[1025];

/*Save to heap*/
//encyptedBuff = calloc(sizeof(plaintext));


int sendToIP(long hostname, unsigned short int port){
	/*sends file to specified IP address*/
	int fd = 0;	//file descriptor
	//create the socket
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0){
		perror("socket");
		exit (EXIT_FAILURE);
	}

	//give socket a name
	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = htonl(hostname);
/*
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(sendBuff, '0', sizeof(sendBuff));
*/
	if (bind(fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
		perror("bind");
		return 0;
	}

	return fd;

	listen(fd, 10);
	printf("Ready to serve..\n");
/*
	while(1){
		connfd = accept(fd, (struct sockaddr*)NULL, NULL);
		write(connfd, sendBuff, strlen(sendBuff));
		close(connfd);
	}*/
}

void promptForPassword(){
	/* prompt user for password and store in p */
	printf("Please enter the password: ");
	fflush (stdout);
	p = fgets (buf, 80, stdin);
	//printf("You entered: %s\n", p);
}

void getkey(){
	//key = calloc(key_length, sizeof(unsigned char*));
	gcry_randomize(salt, SALT_LENGTH, GCRY_STRONG_RANDOM);
	printf("SALT: %s\n", salt);
	//printf("PASSWORD: %s\n", p);
	//printf("LENGTH OF PASSWORD: %zd\n", strlen(p)-1);
	gcry_kdf_derive(p, (strlen(p)-1), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, SALT_LENGTH, DEFAULT_ITERATIONS, key_length, key);
	printf("Derive is done.\n");
	printf("The Key is: %s\n", key);
}


//void append_hmac(char *buffer){
	/*Takes in key and appends hmac*/ 
//	err = 0;
//	err = gcry_md_open(&handler, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
//	printf("The HMAC is appended to the key.\n");
//}


void writeToFile(char *buffer){
	/*This is for creating the.uo encrypted file*/
	char *uo = ".uo";
	char *outputFile = (strcat(inFile, uo)); //create hello.txt.uo
	fpout = fopen(outputFile, "w");
	printf("Output File created.\n");
	if (fpout == NULL){
		printf("Error opening file.\n");
		exit(1);
	}
	fputs(buffer, fpout);
	fclose(fpout);
	//print text
	fprintf(fpout, "The encrypted text has been added. %s\n", ciphertext);
}

void encryptfile(){
	/* opens the encryption process */
	char *encryptMe = NULL;
	int i;
	gcry_cipher_open(&handler, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	gcry_cipher_setkey(handler, (void*)key, KEY_LENGTH);
	gcry_cipher_setiv(handler, (void*)salt, SALT_LENGTH);
	//for (i = 0; i < 16; i++){
	printf("sizeof(ciphertext): %zd\n", sizeof(ciphertext));
	//}

	gcry_cipher_encrypt(handler, ciphertext, sizeof(plaintext), plaintext, 16);
	printf("Before seg fault.\n");
	writeToFile(ciphertext);
	printf("After seg fault.\n");
//	while(fgets(plaintext, 16, fp)){ //this gets seg faulat
		/*This will read 16 bits at a time of a file*/
		//while not end of file
		//read 16 bits -> save to a buffer
		//encrypt that buffer
		//save to a file
		//encrypt next 16 its
		//add padding
	
//	}


	/*if (err){ //ERROR HANDLING
		printf("ENCRYPTION FAILED! %s/%s\n",
		gcry_strsource(err),	//this can be used to output diagnostic message to the user.
		gcry_strerror (err));
	}else{
		printf("Encryption succeeded.\n");
	}*/
	gcry_cipher_close(handler);
	printf("Done. Here is the ciphertext: %s\n", ciphertext);
}




void uoenc(){
	/* Function for encrypting a file*/
	printf("Lets encrypt some shizzzz:\n");
	promptForPassword();	//asks user for password
	getkey();
	printf("Encryption is beginning:\n");
	encryptfile();
	printf("Encryption is done.\n");
	
}

bool doesFileExist(){
	/*Checks to see if file exsists, if it does:
	* Abort program
	*/
	return true;
}


int readInFile(FILE *fp, char* filename, int c){
	/* read in a file*/
	//FILE *fp;
	printf("Filename inside readInFile: %s\n", filename);
	fp = fopen(filename, "r");
	if (fp == NULL) { //error handling
		perror("Error opening File.");
		return (-1);
	}else{
		printf("No error while reading input.\n");
	}
	if( fgets (plaintext, c, fp) != NULL){
		printf("Plaintext: %s\n", plaintext);
	}else{
		printf("Plaintext is Null.\n");
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
	//Parsing of command line
	
	if(argv[1] == '\0'){
		//then no file name
		perror("Sorry, No Input File Entered.");
		exit(1);
	}else {
		inFile = argv[1];	//i don't know if i use this anymore
		lenOfIn = strlen(inFile);
		//printf("lenOfIn %d\n", lenOfIn);
		printf("InputFile:%s\n", argv[1]);
		readInFile(fp, argv[1], 100);
	}

	if(argv[2] == '\0'){
		// no -d comment
		// encrypt file and dump in output file of same name
	}else{

		ipaddress = argv[3]; //holds the ipadress
		long host = (long)ipaddress;
		//sendToIP(host, )
		printf("IPAddress:%s\n", ipaddress);
		
	}

	
	//call uoenc:
	uoenc();
	//printf("THE PASSWORD IS STILL%s\n", p);
	//printf("Size of password: %zd\n", strlen(p));
	exit(0);
}