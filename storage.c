#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "storage.h"

#define CACHE_SIZE 1000

dns_domain_t *create_domain(dns_domain_t *, char *);
void print_all(dns_domain_t *);

// The super root is the root of the cache
// It is one level below the root domain '.' to make tree traversal based on a string easier.
dns_domain_t *super_root;

/**
 initializes the DNS cache with root node. if fails, returns -1.
*/
int init_cache(){
	super_root = malloc(sizeof(dns_domain_t));
	strcpy(super_root->label, "super_root");
	super_root->domain_no = 1;
	super_root->domains = malloc(sizeof(dns_domain_t *));

	dns_domain_t *root;
	root = malloc(sizeof(dns_domain_t));
	if(root == NULL){
		return -1;
	}

	root->label[0] = '\0';
	root->ns_record_no = 13;
	root->ns_records = malloc(13*sizeof(dns_domain_t *));
	if(root->ns_records == NULL){
		return -1;
	}
	for(int i = 0; i < 13; i ++){
		root->ns_records[i] = malloc(sizeof(dns_resource_record_t));
		if(root->ns_records[i] == NULL){
			return -1;
		}
		root->ns_records[i]->Name[0] = '\0';
		root->ns_records[i]->Class = C_IN;
		root->ns_records[i]->Type = T_NS;
		root->ns_records[i]->RDLength = 20;
		root->ns_records[i]->RData = malloc(20*sizeof(char));
		strncpy(root->ns_records[i]->RData, "\x01" "a" "\x0c" "root-servers" "\x03" "net" "\x00", 20);
		((char *)root->ns_records[i]->RData)[1] +=i;
	}
	root->domain_no = 0;
	super_root->domains[0] = root;
//	print_domain(root);
	return 0;
}

/**
 * Caches all of the RR in a particular packet.
*/
void cache_all(dns_packet_t *packet){
	//TODO make this better, group domains before insertion.
	for(int i = 0; i < packet->header.ANCount; i++){
		insert_record(packet->answers[i]);
	}
	for(int i = 0; i < packet->header.NSCount; i++){
		insert_record(packet->authorities[i]);
	}
	for(int i = 0; i < packet->header.ARCount; i++){
		if(packet->additional[i]->Type == T_OPT){
			continue; // dont cache OPT pseudo records.
		}
		insert_record(packet->additional[i]);
	}
}
int insert_record(dns_resource_record_t *rr){
	printf("NAME: %s\n", rr->Name);
	dns_domain_t *current = super_root;
	
	char label[64];

	int start = strlen(rr->Name);
	int end = start;
	while(start >= 0){
		while(rr->Name[start] != '.' && start >= 0){
			start--;
		}
		strncpy(label, rr->Name+start+1, end-start);
		label[end-start-1] = '\0';
		printf("%s\n", label);
		end = start;
		start--;

		bool found = false;
		for(int i = 0; i < current->domain_no; i++){
			if(strcmp(current->domains[i]->label, label) == 0){
				current = current->domains[i];
				found = true;
				break;
			}
		}
		if(!found){
			current = create_domain(current, label);
			if(current == NULL){
				return -1; //failed to make the domain, cant go any further.
			}
		}
	}
	if(rr->Type == T_NS){
		current->ns_record_no += 1;
		current->ns_records = realloc(current->ns_records, current->ns_record_no*sizeof(dns_resource_record_t *));
		//TODO check if this fails.

		//TODO Make this a deep copy
		current->ns_records[current->record_no-1] = rr;
	}else{
		current->record_no += 1;
		current->records = realloc(current->records, current->record_no*sizeof(dns_resource_record_t *));
		//TODO check if this fails.

		//TODO Make this a deep copy
		current->records[current->record_no-1] = rr;
	}
	//print_all(super_root);
	return 0;
}

/**
 Attempts to add a new subdomain with the given label to the parent domain.
 returns NULL on failure, otherwise returns a pointer to the new domain
  */
dns_domain_t *create_domain(dns_domain_t *parent, char *label){

	dns_domain_t *domain;
	domain = malloc(sizeof(dns_domain_t));
	if(domain == NULL){
		return NULL;
	}

	strncpy(domain->label, label, 64);
	domain->ns_record_no = 0;
	domain->ns_records = NULL;
	domain->record_no = 0;
	domain->records = NULL;
	domain->domain_no = 0;
	domain->domains = NULL;

	parent->domain_no += 1;
	parent->domains = realloc(parent->domains, parent->domain_no*sizeof(dns_domain_t *));
	//TODO check if this fails.
	parent->domains[parent->domain_no-1] = domain;

	return domain;
}



/*
Attempts to find a domain in the cache with the specified domain name.
Returns NULL if the domain is not cached.
*/
dns_domain_t *find_domain(char *domainname){
	printf("NAME: %s\n", domainname);
	dns_domain_t *current = super_root;
	
	char label[64];

	int start = strlen(domainname);
	int end = start;
	while(start >= 0){
		while(domainname[start] != '.' && start >= 0){
			start--;
		}
		strncpy(label, domainname+start+1, end-start);
		label[end-start-1] = '\0';
		end = start;
		start--;

		bool found = false;
		for(int i = 0; i < current->domain_no; i++){
			if(strcmp(current->domains[i]->label, label) == 0){
				current = current->domains[i];
				found = true;
				break;
			}
		}
		if(!found){
			return NULL;
		}
	}

	return current;
}

void print_domain(dns_domain_t *domain){
	printf("DOMAIN:\n");
	printf("Label: .%s\n", domain->label);
	printf("Name servers: %d\n", domain->ns_record_no);
	/*for(int i = 0; i < domain->ns_record_no; i ++){
		print_rr(domain->ns_records[i]);
	}*/
	printf("Records: %d\n", domain->record_no);
	printf("Subdomains: %d\n", domain->domain_no);
	for(int i = 0; i < domain->domain_no; i ++){
		printf("%s ", domain->domains[i]->label);
	}
	printf("\n");
}

void print_all(dns_domain_t *domain){
	print_domain(domain);
	for(int i = 0; i < domain->domain_no; i ++){
		print_all(domain->domains[i]);
	}
	printf("\n");
}
