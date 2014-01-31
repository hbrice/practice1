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

#define BUF_SIZE	80
#define SALT_LENGTH	16 //128	//maybe 16?
#define KEY_LENGTH	32 
#define	HASH_FUNCTION = 'AES256'; //SHA256??
#define DEFAULT_ITERATIONS 2048 //16*128
#define ALGO = 'GCRY_KDF_PBKDF2';


char buf[BUF_SIZE]; //buffer for read in password
char *p;		// pointer for password input
//unsigned char *key = '\0'; 		//the key from hashing with password
char key[32];
//char *salt;
unsigned char salt[32];
int key_length = 128;
//gcryp_error_t = 0;

void promptForPassword(){
	//prompt user for password and store in p
	printf("Please enter the password: ");
	fflush (stdout);
	p = fgets (buf, 80, stdin);
	//printf("You entered: %s\n", p);
}

void getkey(){
	//key = calloc(key_length, sizeof(unsigned char*));
	gcry_randomize(salt, 32, GCRY_STRONG_RANDOM);
	printf("SALT: %s\n", salt);
	printf("PASSWORD: %s\n", p);
	printf("LENGTH OF PASSWORD: %zd\n", strlen(p)-1);

	gcry_kdf_derive((void*)p, (strlen(p)-1), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, (void*)salt, SALT_LENGTH, DEFAULT_ITERATIONS, key_length, (void*) key);
	printf("The Key is: %s\n", key);
	/*int i;
	for(i = 0; i < key_length; i++){
		printf("%d\n", key[i]);
	}*/
	
}


void uoenc(){
	/* Function for encrypting a file*/
	printf("Lets encrypt some shizzzz:\n");
	//call password prompt:
	promptForPassword();	//asks user for password
	getkey();
	
}


/*
void append_hmac(char password){
	// Taskes in user password and returns key by using PBDKF2 function 
	salt = CryptGen
}
*/

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


int main (int argc, char *argv[]){
	char *inFile;
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
		inFile = argv[1];
		printf("InputFile:%s\n", inFile);
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