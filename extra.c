//extra code functions
#include <sys/socket.h>	//needed for socket connections
#include <netinet/in.h> //needed for socket connections
#include <sys/types.h>



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