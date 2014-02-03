/*
* Holly Brice
* Cis 433: Network Security
* 1/30/14
*/

#include <uoenc.c>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <gcrypt.h>

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
	//	lenOfIn = strlen(inFile);
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