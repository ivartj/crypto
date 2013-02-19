#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
unsigned char *sha1(const unsigned char *msg, size_t msglen, size_t *rlen);

#endif CRYPTO_H
