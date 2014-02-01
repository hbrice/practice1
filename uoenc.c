/*
* Holly Brice
* Cis 433: Network Security
* 1/24/14
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <gcrypt.h>
#include <sys/socket.h>
#include <netinet/in.h>

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
//gcryp_error_t = 0;

//stuff for socket
int listenfd = 0;
int connfd = 0;
struct sockaddr_in serv_addr;

char sendBuff[1025];

int sentToIP(char *hostname, unsigned short int port){
	/*sends file to specified IP address*/
	int sock = 0;
	//create the socket
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0){
		perror("socket");
		exit (EXIT_FAILURE);
	}

	//give socket a name
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = hton1(hostname);
/*
	listenfd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&serv_add, '0', sizeof(serv_addr));
	memset(sendBuff, '0', sizeof(sendBuff));
*/
	if (bind(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
		perror("bind");
		exit(EXIT_FAILURE);
	}

	return sock;

	listen(listenfd, 10);
	printf("Ready to serve..\n");

	while(1){
		connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
		write(connfd, sendBuff, strlen(sendBuff));
		close(connfd);
	}
}


//Make room on the heap

void promptForPassword(){
	//prompt user for password and store in p
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

	gcry_kdf_derive((void*)p, (strlen(p)-1), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, (void*)salt, SALT_LENGTH, DEFAULT_ITERATIONS, key_length, (void*) key);
	printf("Derive is done.\n");
	printf("The Key is: %s\n", key);
	/*int i;
	for(i = 0; i < key_length; i++){
		printf("%d\n", key[i]);
	}*/
}

void append_hmac(char *buffer){
	/*Takes in key and appends hmac*/ 
	//gcry_md_open(handler, GCRY_HMAC_SHA_256, GCRY_MD_FLAG_HMAC);
	printf("The HMAC is appended to the key.\n");
}

void encryptfile(){
	//opens the encryption process
	//fp = fopen("inFile", "r+");
	//fpout = fopen("out", "w+");
	gcry_cipher_open(&handler, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	//gcry_cipher_setkey(handler, (void*)key, KEY_LENGTH);
	//gcry_cipher_setiv(handler, (void*)salt, SALT_LENGTH);
	//err = gcry_cipher_encrypt(handler, (unsigned char*)ciphertext, plaintext, 48);
	if (err){
		printf("ENCRYPTION FAILED! %s/%s\n",
		gcry_strsource(err),	//this can be used to output diagnostic message to the user.
		gcry_strerror (err));
	}else{
		printf("Encryption succeeded.\n");
	}
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






void uodec(){
/*Function for decrypting file and verifying the HMAC */
//	promptForPassword();
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
		printf("InputFile:%s\n", argv[1]);
		readInFile(fp, argv[1], 100);

	}

	if(argv[2] == '\0'){
		// no -d comment
		// encrypt file and dump in output file of same name
	}else{
		ipaddress = argv[3]; //holds the ipadress
		printf("IPAddress:%s\n", ipaddress);
		
	}

	
	//call uoenc:
	uoenc();
	//printf("THE PASSWORD IS STILL%s\n", p);
	//printf("Size of password: %zd\n", strlen(p));
	exit(0);
}