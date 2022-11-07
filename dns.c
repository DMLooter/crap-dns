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
		dns_question_t *question = malloc(sizeof(dns_question_t));
		read_bytes += parse_question(data, read_bytes, question);//TODO check return
		packet->questions[i] = question;
	}

	packet->answers = malloc(packet->header.ANCount * sizeof(dns_answer_t));

	for(int i = 0; i < packet->header.ANCount; i ++){
		dns_answer_t *answer = malloc(sizeof(dns_answer_t));
		read_bytes += parse_answer(data, read_bytes, answer);//TODO check return
		packet->answers[i] = answer;
	}

	return packet;
}

/**
 Converts a dns message character string to a cstring (null terminated)
 the returned pointer will be heap allocated and must be freed
 If there are any null characters in the dns string, the method returns null
 
 The resulting string will be exactly the same length in total bytes,
 same number of characters and replace the length byte with the null byte
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
char *domainname_ptr_to_string(void *packet_start, int ptr){
	void *name = packet_start+ptr;

	int offset = 0;
	char *out = malloc(256 * sizeof(char)); //TODO I think this is maximal? including dots.
	char *nextout = out;

	while(offset < 255){ // names can by 255 bytes or less
		//check that we dont have a pointer
		if(((char *)name)[offset] > 63){
			uint16_t ptr = ntohs(((uint16_t*)(((char *)name + offset)))[0]) & 0x3FFF;
				
			char *labels = domainname_ptr_to_string(packet_start, ptr);
			if(labels == NULL){
				free(out);
				return NULL; //todo figure out what error this should be
			}
			strncpy(nextout, labels, strlen(labels)+1); //TODO make this bounds check
			free(labels);

			return out; // todo, have this check for pointers and not fail.
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

		//TODO add bounds checking, min length/remaining chars?
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
  parses a domain name into a '.' separated cstring of labels.
  packet_start should point to the start of the DNS packet (for Compression purposes)
  offset should be the number of bytes from packet_start to the start of the domain name
  output should point to a malloced 256 character string (TODO make sure thats the right length, TODO maybe have this allocate it and make output a double pointer?)

  The method returns the number of bytes in this domain name (needs to be calculated since pointers mess up string length.
  */
int domainname_to_string(void *packet_start, int offset, char *output){
	if(output == NULL){
		return -1; // TODO crash
	}

	int len = 0;
	//char *out = malloc(256 * sizeof(char)); //TODO I think this is maximal? including dots.
	char *nextout = output;

	while(len < 255){ // names can by 255 bytes or less
		//check that we dont have a pointer
		if(((char *)packet_start)[offset+len] > 63){
			uint16_t ptr = ntohs(((uint16_t*)(((char *)packet_start + offset+len)))[0]) & 0x3FFF;
				
			char *labels = domainname_ptr_to_string(packet_start, ptr); //TODO this doesnt need to call out, could just change offset and continue. Would need to stop using len as an offset and jsut change offset every read.;
			if(labels == NULL){
				return -1; //todo figure out what error this should be
			}
			strncpy(nextout, labels, strlen(labels)+1); //TODO make this bounds check
			free(labels);
			len +=2;
			
			return len;
		}
		
		char *label = characterstring_to_cstring(packet_start+offset+len);
		if(label == NULL){
			return -1; // invalid null char in string.
		}
		int length = strlen(label);
		len += length + 1;

		if(length == 0){
			free(label);
			break; // 0-length label at the end
		}

		//TODO add bounds checking, min length/remaining chars?
		nextout = stpncpy(nextout, label, length);
		nextout[0] = '.';
		nextout++;

		//TODO check if over 255 and return error?
		free(label);
	}
	nextout[-1] = '\0'; //override last dot with NULL
	return len;

	//length of each label in dns is len +1 for length
	//so total length is sum[len +1] plus the 1 for 0 length
	//length in string is len +1 for the dot except the last one.
	//so total length is sum[len +1] minus the last dot.
	//so length of c string is length of data - 2
	//size: data can be 255, cstring is 255-2 +1 == 254 max.
}

/**
 parses out a DNS question that starts at data.
 The data is loaded into the question pointer passed in.

 returns the number of bytes read.
*/
int parse_question(void *packet_start, int offset, dns_question_t *question){
	if(question == NULL){
		return -1;//TODO failure mode
	}
	void *data = packet_start + offset;

	int length = domainname_to_string(packet_start, offset, question->QName);
//TODO Check return

	question->QType = ntohs(((uint16_t *)(data + length))[0]);
	question->QClass = ntohs(((uint16_t *)(data + length))[1]);
	return length+4;
}

/**
 parses out a DNS answer that starts at data.
 The data is loaded into the answer pointer passed in
 Answer data is malloced.

 returns the number of bytes read.
*/
int parse_answer(void *packet_start, int offset, dns_answer_t *answer){
	if(answer == NULL){
		return -1; // TODO failure mode
	}

	void *data = packet_start+offset;

	int length = domainname_to_string(packet_start, offset, answer->Name);
//TODO Check return
	answer->Type = ntohs(((uint16_t *)(data + length))[0]);
	answer->Class = ntohs(((uint16_t *)(data + length))[1]);
	answer->TTL = ntohl(((uint32_t *)(data + length))[1]);
	answer->RDLength = ntohs(((uint16_t *)(data + length))[4]);
	answer->RData = malloc(sizeof(char) * answer->RDLength);
	//TODO check malloc
	memcpy(answer->RData, data+length+10, answer->RDLength);
	return length + 10 + answer->RDLength;
}

char *data="\x01\x02\x58\x8a\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
char *real="\xc4\x6b\x01\x00\x00\x01" \
"\x00\x00\x00\x00\x00\x00\x03\x64\x6e\x73\x06\x67\x6f\x6f\x67\x6c" \
"\x65\x00\x00\x01\x00\x01";
char *test="\xb6\x36\x81\x80\x00\x01\x00\x04\x00\x00\x00\x00\x07\x70\x61\x67" \
"\x65\x61\x64\x32\x11\x67\x6f\x6f\x67\x6c\x65\x73\x79\x6e\x64\x69" \
"\x63\x61\x74\x69\x6f\x6e\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0" \
"\x0c\x00\x05\x00\x01\x00\x00\x01\x0f\x00\x1c\x08\x70\x61\x67\x65" \
"\x61\x64\x34\x36\x01\x6c\x0b\x64\x6f\x75\x62\x6c\x65\x63\x6c\x69" \
"\x63\x6b\x03\x6e\x65\x74\x00\xc0\x3b\x00\x01\x00\x01\x00\x00\x00" \
"\xd9\x00\x04\x4a\x7d\xe1\x2d\xc0\x3b\x00\x01\x00\x01\x00\x00\x00" \
"\xd9\x00\x04\x4a\x7d\xe1\x3a\xc0\x3b\x00\x01\x00\x01\x00\x00\x00" \
"\xd9\x00\x04\x4a\x7d\xe1\x39";

int main(){
	parse_packet(test, 135);
	return 0;
}
