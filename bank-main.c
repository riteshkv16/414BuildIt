#include "bank.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>

// Default port and ip address are defined here

int main(int argc, char** argv){
	int FAILURE = 255;
	unsigned short DEFAULT_PORT = 3000;
	char* DEFAULT_IP = "127.0.0.1";
	char* DEFAULT_AUTH_FILE = "bank.auth";

	unsigned short port = 0;
	char* auth_file = NULL;
	char *ip = NULL;

	//Might be wrong max args
	if(argc > 6){
		return FAILURE;
	}

	//Section: parse command line input 
	int cflag;
	regex_t valid_numbers;
	regex_t valid_filenames;

	//Compile Regex patterns
	regcomp(&valid_numbers, "^(0|[1-9][0-9]*)$", REG_EXTENDED);
	regcomp(&valid_filenames, "^([0-9a-z._\\-]*)$", REG_EXTENDED); 
	
	while ((cflag = getopt(argc, argv, "p:s:")) != -1) {
		switch(cflag){
			case 'p':
				if(port == 0){
					port = atoi(optarg); //does this become unsigned short?
				} else {
					return FAILURE; // duplicate
				}
				//port # did not match regex
				if(regexec(&valid_numbers, optarg, 0, NULL, 0) == 0 && port >= 1024 && port <= 65535){
					break;
				} else {
					return FAILURE;
				}

				break;
			case 's':
				if(auth_file == NULL){
					auth_file = optarg;
				} else {
					return FAILURE;
				}
				//file NOT match regex
				//ERR here
				
				if(regexec(&valid_filenames, auth_file, 0, NULL, 0) != 0){
					return FAILURE;
				}
				
				size_t file_len = strlen(auth_file);
				if(file_len < 1 || file_len > 127){
					return FAILURE;
				}
				//strcmp returns 0 if match
				if(strcmp(auth_file, ".") == 0 || strcmp(auth_file, "..") == 0){
					return FAILURE;
				}
				break;
			case '?':
				return FAILURE;
		}

	}

	

	if(auth_file == NULL){
		auth_file = DEFAULT_AUTH_FILE;
	}
	if(port == 0){
		port = DEFAULT_PORT;
	}
	if(ip == NULL){
		ip = DEFAULT_IP;
	}

	printf("Auth file: %s\n", auth_file);
	printf("Port: %d\n", port);
	
	Bank *b = bank_create(auth_file, ip, port);
	
	for(;;) {

		unsigned int len = sizeof(b->remote_addr);
		b->clientfd = accept(b->sockfd, (struct sockaddr*)&b->remote_addr, &len);
		if (b->clientfd < 0) {
			perror("error on accept call");
			exit(255);
		}

		/* okay, connected to bank/atm. Send/recv messages to/from the bank/atm. */
		int MAX_MSG_SIZE = 5000;
		char data[MAX_MSG_SIZE];

		ssize_t res =  bank_recv(b, data, sizeof(data));
		if(res >= 0){
			printf("bank received:  %s\n", data);
			bank_process_remote_command(b, data, sizeof(data));
		} 

		/*strcpy(buffer, "money money money");
		bank_send(b, buffer, strlen(buffer)+1);*/



		/* when finished processing commands ...*/
		/*close(b->clientfd);
		b->clientfd = -1;*/
	}
	
	
	// Implement how atm protocol will work: sanitizing inputs and using different modes of operations

	return EXIT_SUCCESS;
}
