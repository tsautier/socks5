#ifndef __SSLCOMPAT_H
#define __SSLCOMPAT_H

// OpenSSL 3.x compatibility layer.
//
// Two things changed between the OpenSSL this code was written against
// (0.9.x/1.0.x) and OpenSSL 3.x as shipped by Ubuntu 24.04:
//
//  1. Blowfish moved out of the default provider into the "legacy" provider.
//     The config-file encryption (blowcrypt) uses BF-CFB, so the legacy
//     provider has to be loaded explicitly or every EVP call for it fails.
//
//  2. The library no longer needs (or has) the manual init and locking
//     callbacks; those are no-ops kept only for source compatibility.
//
// crypto_init() must be called once at the top of main(), *before* the
// daemon chroots -- loading a provider dlopen()s a module out of
// /usr/lib/<arch>/ossl-modules, which is unreachable after chroot().

#include <string>
#include <openssl/opensslv.h>

// Initialise libcrypto/libssl and load the providers we need.
// Returns 1 on success. If the legacy provider cannot be loaded, returns 0
// and leaves a description in the string passed by reference.
int crypto_init(bool need_legacy, std::string &err);

// Release the providers loaded by crypto_init(). Safe to call unconditionally.
void crypto_cleanup(void);

// Renamed in OpenSSL 3.0; the old spelling is a deprecated macro.
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define SSL_get1_peer_certificate SSL_get_peer_certificate
#endif

#endif
