#include "crypto.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <assert.h>
#include <stdio.h>

#define S(n, X)		(((X) << (n)) | ((X) >> ((32) - (n))))

static unsigned char *sha1pad(const unsigned char *msg, size_t msglen, size_t *rlen);

/* Only works if the bit length is below 2 ^ 32 */
unsigned char *sha1pad(const unsigned char *msg, size_t msglen, size_t *rlen)
{
	size_t len;
	unsigned char *val;
	uint32_t *end;

	len = msglen + 1;
	len += 8;
	len += 64 - len % 64;

	*rlen = len;

	val = calloc(1, len);
	memcpy(val, msg, msglen);
	val[msglen] = 0x80;

	end = (uint32_t *)(val + len - 4);
	*end = htonl(msglen * 8);
	
	return val;
}

unsigned char *sha1(const unsigned char *msg, size_t msglen, size_t *rlen)
{
	unsigned char *M;
	size_t Mlen;
	uint32_t *H;
	
	uint32_t A, B, C, D, E;
	uint32_t W[80];
	unsigned i;
	unsigned t;
	uint32_t TEMP;
	uint32_t f;
	uint32_t k;

	M = sha1pad(msg, msglen, &Mlen);
	H = calloc(5, sizeof(uint32_t));

	H[0] = 0x67452301;
	H[1] = 0xEFCDAB89;
	H[2] = 0x98BADCFE;
	H[3] = 0x10325476;
	H[4] = 0xC3D2E1F0;

	for(i = 0; i < Mlen; i += 64) {

		for(t = 0; t < 16; t++)
			W[t] = ntohl(*(uint32_t *)(M + i + t * 4));
		

		for(t = 16; t <= 79; t++)
			W[t] = S(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);

		A = H[0];
		B = H[1];
		C = H[2];
		D = H[3];
		E = H[4];

		for(t = 0; t <= 79; t++) {
			if(t <= 19) {
				f = (B & C) | ((~B) & D);
				k = 0x5A827999;
			} else
			if(t <= 39) {
				f = B ^ C ^ D;
				k = 0x6ED9EBA1;
			} else
			if(t <= 59) {
				f = (B & C) | (B & D) | (C & D);
				k = 0x8F1BBCDC;
			} else
			if(t <= 79) {
				f = B ^ C ^ D;
				k = 0xCA62C1D6;
			}

			TEMP = S(5, A) + f + E + k + W[t];
			E = D;
			D = C;
			C = S(30, B);
			B = A;
			A = TEMP;
		}

		H[0] = H[0] + A;
		H[1] = H[1] + B;
		H[2] = H[2] + C;
		H[3] = H[3] + D;
		H[4] = H[4] + E;
	}
	
	*rlen = 20;

	for(i = 0; i < 5; i++) {
		H[i] = htonl(H[i]);
	}

	free(M);
	
	return (unsigned char *)H;
}
