#include "../crypto.c"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const unsigned char expected[] = { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D };


int main(int argc, char *argv[])
{
	char *out;
	size_t len;
	const unsigned char *iter;
	int i;

	out = sha1("abc", strlen("abc"), &len);

	assert(len == sizeof(expected));

	assert(S(1, 0x80000000 ) == 1);

	for(iter = expected; ; iter = out) {
		for(i = 0; i < 20; i++) {
			printf("%.2hhX", iter[i]);
		}
		puts("");
		if(iter == out)
			break;
	}

	assert(memcmp(out, expected, len) == 0);
	
	exit(EXIT_SUCCESS);
}
