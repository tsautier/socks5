#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#include "sslcompat.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static OSSL_PROVIDER *prov_legacy = NULL;
static OSSL_PROVIDER *prov_default = NULL;
#endif

static std::string ssl_errors(void)
{
	std::stringstream ss;
	unsigned long e;
	while ((e = ERR_get_error()) != 0)
	{
		ss << " [" << ERR_error_string(e, NULL) << "]";
	}
	return ss.str();
}

int crypto_init(bool need_legacy, std::string &err)
{
	err = "";

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	// OPENSSL_init_ssl() replaces SSL_library_init() + SSL_load_error_strings()
	// + OpenSSL_add_all_digests(), all of which are no-ops since 1.1.0.
	if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
	                      OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL))
	{
		err = "OPENSSL_init_ssl failed:" + ssl_errors();
		return 0;
	}

	if (need_legacy)
	{
		// Blowfish (used for the encrypted config file) lives in the legacy
		// provider from 3.0 onwards. Loading any provider explicitly stops
		// the default one from being loaded implicitly, so load both.
		prov_legacy = OSSL_PROVIDER_load(NULL, "legacy");
		if (prov_legacy == NULL)
		{
			err = "could not load the OpenSSL 'legacy' provider, which is "
			      "required to read an encrypted config file. On Debian/Ubuntu "
			      "install the 'openssl' package (it ships "
			      "ossl-modules/legacy.so). Alternatively run with '-u' and a "
			      "plaintext config." + ssl_errors();
			return 0;
		}

		prov_default = OSSL_PROVIDER_load(NULL, "default");
		if (prov_default == NULL)
		{
			err = "could not load the OpenSSL 'default' provider:" + ssl_errors();
			OSSL_PROVIDER_unload(prov_legacy);
			prov_legacy = NULL;
			return 0;
		}
	}
#else
	(void)need_legacy;
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_digests();
#endif

	return 1;
}

void crypto_cleanup(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (prov_default != NULL)
	{
		OSSL_PROVIDER_unload(prov_default);
		prov_default = NULL;
	}
	if (prov_legacy != NULL)
	{
		OSSL_PROVIDER_unload(prov_legacy);
		prov_legacy = NULL;
	}
#endif
}
