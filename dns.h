#include <stdint.h>
#include <stddef.h>

enum TYPE {
		T_A=1, T_NS=2, T_MD=3, T_MF=4, T_CNAME=5, T_SOA=6,
			T_MB=7, T_MG=8, T_MR=9, T_NULL=10, T_WKS=11,
			T_PTR=12, T_HINFO=13, T_MINFO=14, T_MX=15, T_TXT=16
};

enum QTYPE {
		QT_A=1, QT_NS=2, QT_MD=3, QT_MF=4, QT_CNAME=5, QT_SOA=6,
			QT_MB=7, QT_MG=8, QT_MR=9, QT_NULL=10, QT_WKS=11,
			QT_PTR=12, QT_HINFO=13, QT_MINFO=14, QT_MX=15, QT_TXT=16,

			QT_AXFR=252, QT_MAILB=253, QT_MAILA=254, QT_ALL=255
};

enum CLASS {
		C_IN=1, C_CS=2, C_CH=3, C_HS=4
};

enum QCLASS {
		QC_IN=1, QC_CS=2, QC_CH=3, QC_HS=4,
		QC_ALL=255
};

typedef struct dns_question{
	char QName[256];
	uint16_t QType;
	uint16_t QClass;
}dns_question_t;

typedef struct dns_answer{
	char Name[256];
	uint16_t Type;
	uint16_t Class;
	uint32_t TTL;
	uint16_t RDLength;
	void* RData;
} dns_answer_t;

typedef struct dns_header{
	uint16_t QID;
	unsigned short QR :1;
	unsigned short OpCode :4;
	unsigned short AA :1;
	unsigned short TC :1;
	unsigned short RD :1;
	unsigned short RA :1;
	unsigned short Z :3;
	unsigned short RCode :4;
	uint16_t QDCount;
	uint16_t ANCount;
	uint16_t NSCount;
	uint16_t ARCount;
} dns_header_t;

typedef struct dns_packet{
	dns_header_t header;
	dns_question_t **questions;
	dns_answer_t **answers;
	dns_answer_t **authorities;
	dns_answer_t **additional;
} dns_packet_t;

int parse_question(void *,int, dns_question_t *);
int parse_answer(void *, int, dns_answer_t *);
dns_packet_t *parse_packet(void *data, int n);

char *domainname_ptr_to_string(void *packet_start, int ptr);
int domainname_to_string(void *packet_start, int offset, char *output);

