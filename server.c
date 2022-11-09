#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "dns.h"

#define DNS_PORT 53

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

int try(const struct sockaddr *source_addr, int source_addr_len, char *buf, int length){
	struct sockaddr_in client_addr;
	unsigned int client_addr_len = sizeof(client_addr);



	size_t sent_bytes = sendto(sd, buf, length, 0, (struct sockaddr*)&dns_addr, dns_struct_length);
	if(sent_bytes < 0){
		printf("Failed to send\n");
		return -1;
    }

	char resp[512];

	while(1){
		size_t bytes = recvfrom(sd, resp, sizeof(resp), 0, (struct sockaddr *)&client_addr, &client_addr_len);
		if(bytes < 0){
			printf("Failed to receive\n");
			return -1;
		}

		//wait for dns response
		if(cmp_addr((struct sockaddr *)&client_addr, (struct sockaddr *)&dns_addr) == 0){
			printf("Response message from IP: %s and port: %i\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
			print_packet(parse_packet(resp,bytes));
			size_t sent_bytes = sendto(sd, resp, bytes, 0, source_addr, source_addr_len);
			printf("Sent %d bytes\n", sent_bytes);
			perror(NULL);
			if(sent_bytes < 0){
				printf("Failed to send\n");
				return -1;
		    }
			break;
		}
	}
	return 0;
}

int main(int argc, char **argv){
	struct sockaddr_in server_addr, client_addr;
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
	inet_pton(AF_INET, "127.0.0.53", &(dns_addr.sin_addr));
	dns_struct_length = sizeof(dns_addr);

	//listen
	while(1){
		unsigned int client_addr_len = sizeof(client_addr);
		size_t bytes = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &client_addr_len);
		if(bytes < 0){
			printf("Failed to receive\n");
			return -1;
		}

		printf("Received message from IP: %s and port: %i\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		printf("IP Family: %hu / %hu\n", client_addr.sin_family, AF_INET);
		print_packet(parse_packet(buf,bytes));
	
		try((struct sockaddr *)&client_addr, client_addr_len, buf, bytes);
	}
	close(sd);
	return 0;
}

