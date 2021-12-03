#include "atm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <unistd.h>

// Default port and ip address are defined here
#define FAILURE 255   
#define DEFAULT_AUTH_FILE "bank.auth"
#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 3000   


int main(int argc, char** argv){
  	unsigned short port = 0;
	char *auth_file = NULL;
	char *ipAddr = NULL;
	char *card = NULL;
	char *account = NULL;
	char mode = '\0';
	size_t file_len;
	int amount;
	
	//Might be wrong max args
	if(argc > 13){
		return FAILURE;
	}

	//Section: parse command line input 
	int cflag;
	regex_t valid_account;
	regex_t valid_numbers;
	regex_t valid_filenames;
	regex_t valid_ip;
	regex_t valid_card;
	//Compile Regex patterns
	regcomp(&valid_account, "^[a-zA-Z0-9_-]*$", REG_EXTENDED);
	regcomp(&valid_numbers, "^(0|[1-9][0-9]*)$", REG_EXTENDED);
	regcomp(&valid_filenames, "^([a-zA-Z0-9._\\-]*)$", REG_EXTENDED); 
	regcomp(&valid_ip, "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", REG_EXTENDED);
	regcomp(&valid_card, "^([a-zA-Z0-9._\\-]*).card$", REG_EXTENDED);
	while ((cflag = getopt(argc, argv, "p:s:i:a:c:n:d:w:g::")) != -1) {
		switch(cflag){
			case 'a':
				if(account == NULL){
					account = optarg;
				} else {
					return FAILURE;
				}
				//file NOT match regex
				//ERR here
				
				if(regexec(&valid_account, account, 0, NULL, 0) != 0){
					return FAILURE;
				}
				break;

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

			case 'i':
				if(ipAddr == NULL){
					ipAddr = optarg;
				} else {
					return FAILURE;
				}
				//file NOT match regex
				//ERR here
				
				if(regexec(&valid_ip, ipAddr, 0, NULL, 0) != 0){
					return FAILURE;
				}
				
				file_len = strlen(ipAddr);
				if(file_len < 1 || file_len > 127){
					return FAILURE;
				}
				//strcmp returns 0 if match
				if(strcmp(ipAddr, ".") == 0 || strcmp(ipAddr, "..") == 0){
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
				
				file_len = strlen(auth_file);
				if(file_len < 1 || file_len > 127){
					return FAILURE;
				}
				//strcmp returns 0 if match
				if(strcmp(auth_file, ".") == 0 || strcmp(auth_file, "..") == 0){
					return FAILURE;
				}
				break;
			case 'c':
				if(card == NULL){
					card = optarg;
				} else {
					return FAILURE;
				}
				//file NOT match regex
				//ERR here
				
				if(regexec(&valid_card, card, 0, NULL, 0) != 0){
					return FAILURE;
				}
				
				file_len = strlen(card);
				if(file_len < 1 || file_len > 127){
					return FAILURE;
				}
				//strcmp returns 0 if match
				if(strcmp(card, ".") == 0 || strcmp(card, "..") == 0){
					return FAILURE;
				}
				break;
			case 'n':
				if(!mode){
					mode = 'n';
					amount = atoi(optarg);
				} else {
					return FAILURE;
				}
				break;
			case 'd':
				if(!mode){
					mode = 'd';
					amount = atoi(optarg);
				} else {
					return FAILURE;
				}
				break;
			case 'w':
				if(!mode){
					mode = 'w';
					amount = atoi(optarg);
				} else {
					return FAILURE;
				}
				break;
			case 'g':
				if(!mode){
					mode = 'g';
					printf("optarg: %s\n", optarg);
				} else {
					return FAILURE;
				}
				break;
			case '?':
				return FAILURE;
		}

	}	
	if(account == NULL){
		return FAILURE;
	}
	if(auth_file == NULL){
		auth_file = DEFAULT_AUTH_FILE;
	}
	if(port == 0){
		port = DEFAULT_PORT;
	}
	if(ipAddr == NULL){
		ipAddr = DEFAULT_IP;
	}
	if(card == NULL){
		card = malloc(strlen(account));
		strcpy(card, account); 
		strcat(card, ".card"); 
	}
	if(!mode){
		return FAILURE; 
	}
	printf("Account: %s\n", account);
	printf("Auth file: %s\n", auth_file);
	printf("IP: %s\n", ipAddr);
	printf("Port: %d\n", port);
	printf("Card: %s\n", card);
	printf("Mode: %c\n", mode);
	switch (mode) {
		case 'n':
			printf("Amount: %d\n", amount);
			break;
		case 'd':
			printf("Amount: %d\n", amount);
			break;
		case 'w':
			printf("Amount: %d\n", amount);
			break;
	}
	ATM *atm = atm_create(ipAddr, port);

	/* send messages */

	char buffer[] = "Hello I am the atm and I would like to have money please";
	int msg_size = sizeof(account) + sizeof(auth_file) + sizeof(ipAddr) + sizeof(card) + 1;
	char *msg = malloc(msg_size);
	int j = snprintf(msg, msg_size, "%s%s%s%s%c", account, auth_file, ipAddr, card, mode);
	printf("msg %s\n", msg);
	atm_send(atm, msg, j);
	//atm_send(atm, buffer, sizeof(buffer));
	atm_recv(atm, buffer, sizeof(buffer));
	printf("atm received %s\n", buffer);
	
	atm_free(atm);
	

	// Implement how atm protocol will work: sanitizing inputs and using different modes of operations

	return EXIT_SUCCESS;
}
