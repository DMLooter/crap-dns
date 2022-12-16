#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <pthread.h>
#include <semaphore.h>

#include "dns.h"
#include "storage.h"

#define DNS_ADDRESS "127.0.0.53"
#define DNS_PORT 53

//Number of slots in our buffer.
#define BUFFER_SIZE 10

typedef struct dns_message{
	bool used;
	struct sockaddr *sa;
	size_t message_length;
	char message[512];
} dns_message_t;

sem_t empty;
sem_t full;
int emptySlots = BUFFER_SIZE;
int fullSlots = 0;

pthread_mutex_t messages_lock;
pthread_mutex_t requests_lock;
//incoming messages that havent been categorized
dns_message_t message_buffer[BUFFER_SIZE];
//requests that have been parsed and are waiting for a response.
dns_message_t request_buffer[BUFFER_SIZE];


int sd;

struct sockaddr_in dns_addr;
int dns_struct_length;

/**
Method taken from https://opensource.apple.com/source/postfix/postfix-197/postfix/src/util/sock_addr.c
Used to compare IP addresses in IPv4 and IPv6.
*/
int cmp_addr(const struct sockaddr *a, const struct sockaddr *b){
	if(a->sa_family != b->sa_family){
		return a->sa_family - b->sa_family;
	}
	if(a->sa_family == AF_INET) {
		return ((struct sockaddr_in *)a)->sin_addr.s_addr - ((struct sockaddr_in *)b)->sin_addr.s_addr;
	}else if(a->sa_family == AF_INET6){
		return memcmp((char *) &(((struct sockaddr_in6 *)a)->sin6_addr.s6_addr),
						(char *) &(((struct sockaddr_in6 *)b)->sin6_addr.s6_addr),
						sizeof(((struct sockaddr_in6 *)a)->sin6_addr.s6_addr));
	}
	return 0;
}

void *listener_thread(void *arg){
	//Offset used so we dont check the buffer for free spaces starting at the same point every time.
	int buffer_offset = 0;

	char buf[512];
	while(1){

		struct sockaddr_in *client_addr = malloc(sizeof(struct sockaddr_in));
		unsigned int client_addr_len = sizeof(&client_addr);
		size_t bytes = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr *)client_addr, &client_addr_len);
		if(bytes < 0){
			printf("Failed to receive\n");
			return NULL;
		}

//		printf("Received message from IP: %s and port: %i\n", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
		print_packet(parse_packet(buf,bytes));
		
		//now we poll semaphore
		sem_wait(&empty);
		pthread_mutex_lock(&messages_lock);
		
		for(int i = 0; i < BUFFER_SIZE; i ++){
			int off = (buffer_offset + i) % BUFFER_SIZE;
			if(message_buffer[off].used == false){
				buffer_offset = off + 1;// next time start at next one.
				message_buffer[off].used = true;
				message_buffer[off].sa = (struct sockaddr *)client_addr;//to be freed later;
				message_buffer[off].message_length = bytes;
				memcpy(message_buffer[off].message, buf, bytes);
				break;
			}
		}
		pthread_mutex_unlock(&messages_lock);
		sem_post(&full);

	}
}

void *resolver_thread(void *arg){
	int buffer_offset = 0; // mimics offset in listener so we can chase them.
	while(1){

		sem_wait(&full);
		pthread_mutex_lock(&messages_lock);

		//only do one message per loop.
		for(int i = 0; i < BUFFER_SIZE; i ++){
			int off = (buffer_offset + i) % BUFFER_SIZE;
			if(message_buffer[off].used == true){
				buffer_offset = off + 1;// next time start at next one.

				// if it comes from our resolver we need to use it to respond to a message
				if(cmp_addr(message_buffer[off].sa, (struct sockaddr *)&dns_addr) == 0){
					dns_packet_t *response = parse_packet(message_buffer[off].message, message_buffer[off].message_length);
					cache_all(response);

					pthread_mutex_lock(&requests_lock);
					for(int j = 0; j < BUFFER_SIZE; j++){
						if(request_buffer[j].used == true){
							//check each request for the valid QID.
							dns_packet_t *request = parse_packet(request_buffer[j].message, request_buffer[j].message_length);
							if(request->header.QID == response->header.QID){
								size_t sent_bytes = sendto(sd,
												message_buffer[off].message,
												message_buffer[off].message_length,
												0, request_buffer[j].sa, // send to requester.
												sizeof(*request_buffer[j].sa));
								if(sent_bytes < 0){
									printf("Failed to send\n");
									return NULL;
							    }
								//clear used bit in request
								//and free both sa pointers.
								request_buffer[j].used = false;
								free(request_buffer[j].sa);
								free(message_buffer[off].sa);
								
								break;
							}
						}
					}
					pthread_mutex_unlock(&requests_lock);
				} else { // if it comes from anyone else its a query
					pthread_mutex_lock(&requests_lock);
					//TODO right now this loop will discard any request if there are 10 pending.
					for(int j = 0; j < BUFFER_SIZE; j ++){
						if(request_buffer[j].used == false){
							// TODO can this be one copy?
							request_buffer[j].used = true;
							request_buffer[j].sa = message_buffer[off].sa;
							request_buffer[j].message_length = message_buffer[off].message_length;
							memcpy(request_buffer[j].message, message_buffer[off].message, message_buffer[off].message_length);

							//FOrward query to resolver
							size_t sent_bytes = sendto(sd,
											message_buffer[off].message,
											message_buffer[off].message_length,
											0, (struct sockaddr *)&dns_addr,
											sizeof(dns_addr));
							if(sent_bytes < 0){
								printf("Failed to send\n");
								return NULL;
							}

							break;
						}
					}
					pthread_mutex_unlock(&requests_lock);
				}
				//clear used bit since we've either moved it or used it to respond
				message_buffer[off].used = false;
				break;
			}
		}
		pthread_mutex_unlock(&messages_lock);
		sem_post(&empty);
	}
}

int main(int argc, char **argv){
	init_cache();

	// 0 out our buffer.
	memset(request_buffer,0,BUFFER_SIZE * sizeof(dns_message_t));
	sem_init(&empty, 0, BUFFER_SIZE);
	sem_init(&full, 0, 0);
	pthread_mutex_init(&messages_lock, NULL);
	pthread_mutex_init(&requests_lock, NULL);

	struct sockaddr_in server_addr;
	char buf[512];

	memset(buf, 0, 512);

	//Create Socket
	sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if(sd < 0){
		printf("error creating socket: %d\n", sd);
		return -1;
	}

	// This lets us re-use the addr already in use by the local dns resolver
	int optval = 1;
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

	//Setup the server to listen on 53, any addr.
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(DNS_PORT);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	//Bind
	if(bind(sd, (struct sockaddr *)&server_addr, sizeof(server_addr))){
		perror(NULL);
		printf("failed to bind\n");
		close(sd);
		return -1;
	}

	//setup the dns_server address.
	dns_addr.sin_family = AF_INET;
	dns_addr.sin_port = htons(DNS_PORT);
	inet_pton(AF_INET, DNS_ADDRESS, &(dns_addr.sin_addr));
	dns_struct_length = sizeof(dns_addr);

	//listen

	pthread_t resolver, listener;

	pthread_create(&resolver, NULL, &resolver_thread, NULL);
	pthread_create(&listener, NULL, &listener_thread, NULL);
	pthread_join(resolver, NULL);

	close(sd);
	return 0;
}

/*
Goal is one thread that listens to incoming packets and tosses them in a buffer.
Another thread waits for data and then parses the data
If its a question packet from a client, store ID and client and forward to dns server
If its an answer packet from the dns server, sned it back to corresponding client

*/
