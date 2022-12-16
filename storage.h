#ifndef STORAGE_H
#define STORAGE_H

#include "dns.h"

// dns cache is a tree of domains.
// At the base is the root domain ""
// Which has children like "com","org","uk","fm", etc.
// Each domain 
typedef struct dns_domain{
	char label[64];
	int ns_record_no;
	dns_resource_record_t** ns_records; // NS records for this domain, for easy access
	int record_no;
	dns_resource_record_t** records;
	int domain_no;
	struct dns_domain** domains;
} dns_domain_t;

int init_cache();
void cache_all(dns_packet_t *);
int insert_record(dns_resource_record_t *);
dns_domain_t *find_domain(char *);
void print_domain(dns_domain_t *);

#endif
