/*
* Holly Brice
*/
#ifndef UOENC_H_
#define UOENC_H_

int sendToIP(long hostname, unsigned short int port);
void promptForPassword();
void getkey();
void writeToFile(char *buffer);
void encryptfile();
void uoenc();
int readInFile(FILE *fp, char* filename, int c);
