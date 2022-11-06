#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "dns.h"

/**
Parses the data from a packet that is n bytes long
*/
dns_packet_t *parse_packet(void *data, int n){
	if(n < 12){ // Header is 12 bytes minimum
		return NULL;
	}
	dns_packet_t *packet = malloc(sizeof(dns_packet_t));

	packet->header.QID = ntohs(((uint16_t *)data)[0]);
	//TODO short circuit if not valid
	
	packet->header.QR = (((char *)data)[2] & 0x80) >> 7;
	packet->header.OpCode = (((char *)data)[2] & 0x78) >> 3;
	packet->header.AA = (((char *)data)[2] & 0x04) >> 2;
	packet->header.TC = (((char *)data)[2] & 0x02) >> 1;
	packet->header.RD = (((char *)data)[2] & 0x01);
	packet->header.RA = (((char *)data)[3] & 0x80) >> 7;
	packet->header.Z = (((char *)data)[3] & 0x70) >> 4;
	// TODO shortcircuit if not zero
	packet->header.RCode = (((char *)data)[3] & 0x0F);

	packet->header.QDCount = ntohs(((uint16_t *)data)[2]);
	packet->header.ANCount = ntohs(((uint16_t *)data)[3]);
	packet->header.NSCount = ntohs(((uint16_t *)data)[4]);
	packet->header.ARCount = ntohs(((uint16_t *)data)[5]);
	
	packet->questions = malloc(packet->header.QDCount * sizeof(dns_question_t));

	int read_bytes = 12;
	for(int i = 0; i < packet->header.QDCount; i ++){
		dns_question_t *question =  parse_question(data + read_bytes);
		packet->questions[i] = question;
		read_bytes += length_of_question(question);
	}

	packet->answers = malloc(packet->header.ANCount * sizeof(dns_answer_t));

	for(int i = 0; i < packet->header.ANCount; i ++){
		dns_answer_t *answer =  parse_answer(data + read_bytes);
		packet->answers[i] = answer;
		read_bytes += length_of_answer(answer);
	}

	return packet;
}

/**
 Converts a dns message character string to a cstring (null terminated)
 the returned pointer will be heap allocated and must be freed
 If there are any null characters in the dns string, the method returns null
*/
char *characterstring_to_cstring(void *string){
	short length = ((char *)string)[0]; // first byte is length.
	
	char *out = malloc((length+1) * sizeof(char));
	strncpy(out, string+1, length);
	out[length] = '\0';

	// Make sure that there is no null character in the middle of the string that will mess us up
	if(strlen(out) != length){
		free(out);
		return NULL;
	}
	return out;
}

/**
 Converts a domain-name (series of labels) into a string with . separated labels
*/
char *domainname_to_string(void *name){
	int offset = 0;
	char *out = malloc(256 * sizeof(char)); //TODO I think this is maximal? including dots.
	char *nextout = out;

	while(offset < 255){ // names can by 255 bytes or less
		//check that we dont have a pointer
		if(((char *)name)[offset] > 63){
			free(out);
			return NULL; // todo, have this check for pointers and not fail.
		}
		
		char *label = characterstring_to_cstring(name+offset);
		if(label == NULL){
			free(out);
			return NULL; // invalid null char in string.
		}
		int length = strlen(label);
		if(length == 0){
			free(label);
			break; // 0-length label at the end
		}

		nextout = stpncpy(nextout, label, length);
		nextout[0] = '.';
		nextout++;

		offset += length+1; // skip to next string.
		//TODO check if over 255 and return error?
		free(label);
	}
	nextout[-1] = '\0'; //override last dot with NULL
	return out;

	//length of each label in dns is len +1 for length
	//so total length is sum[len +1] plus the 1 for 0 length
	//length in string is len +1 for the dot except the last one.
	//so total length is sum[len +1] minus the last dot.
	//so length of c string is length of data - 2
	//size: data can be 255, cstring is 255-2 +1 == 254 max.
}

/**
 parses out a DNS question that starts at data.
 question is malloced.
*/
dns_question_t *parse_question(void *data){
	dns_question_t *question = malloc(sizeof(dns_question_t));

	char *domainname = domainname_to_string(data);
	int length = strlen(domainname) + 2;
	strncpy(question->QName, domainname, 256);
	free(domainname);

	question->QType = ntohs(((uint16_t *)(data + length))[0]);
	question->QClass = ntohs(((uint16_t *)(data + length))[1]);
	return question;
}

size_t length_of_question(dns_question_t *question){
	return strlen(question->QName) + 6;
}

/**
 parses out a DNS answer that starts at data.
 answer and data are both malloced.
*/
dns_answer_t *parse_answer(void *data){
	dns_answer_t *answer = malloc(sizeof(dns_answer_t));

	char *domainname = domainname_to_string(data);
	int length = strlen(domainname) + 2;
	strncpy(answer->Name, domainname, 256);
	free(domainname);

	answer->Type = ntohs(((uint16_t *)(data + length))[0]);
	answer->Class = ntohs(((uint16_t *)(data + length))[1]);
	answer->TTL = ntohl(((uint32_t *)(data + length))[1]);
	answer->RDLength = ntohs(((uint16_t *)(data + length))[4]);
	answer->RData = malloc(sizeof(char) * answer->RDLength);
	//TODO check malloc
	memcpy(answer->RData, data+length+10, answer->RDLength);
	return question;
}

size_t length_of_answer(dns_answer_t *answer){
	return strlen(answer->Name) + 10 + answer->RDLength;
}

char *data="\x01\x02\x58\x8a\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
char *real="\xc4\x6b\x01\x00\x00\x01" \
"\x00\x00\x00\x00\x00\x00\x03\x64\x6e\x73\x06\x67\x6f\x6f\x67\x6c" \
"\x65\x00\x00\x01\x00\x01";

int main(){
	parse_packet(real, 28);
	return 0;
}