#ifndef CURVE25519_DONNA_H
#define CURVE25519_DONNA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * curve25519_donna - compute shared secret or public key
 *
 * mypublic = curve25519(mysecret, basepoint)     — key generation
 * shared   = curve25519(mysecret, theirpublic)    — ECDH
 *
 * All arrays are 32 bytes. Returns 0 on success.
 */
int curve25519_donna(uint8_t *mypublic, const uint8_t *mysecret, const uint8_t *basepoint);

#ifdef __cplusplus
}
#endif

#endif /* CURVE25519_DONNA_H */
