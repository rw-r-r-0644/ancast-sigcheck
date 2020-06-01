#include "rsa.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>

int
verify_rsa2048_signature(void *sha1digest,
						 void *signature,
						 const char *pubkey)
{
	int res;
	RSA *rsa = NULL;

	/* load public key pem */
	BIO *keybio = BIO_new_mem_buf(pubkey, -1);
	if (!keybio) {
		printf("error: failed to create bio mem buf\n");
		return 0;
	}

	PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	if (!rsa) {
		printf("error: failed to create rsakey\n");
		return 0;
	}

	/* verify signature using openssl */
	res = RSA_verify(NID_sha1,
					 sha1digest,
					 0x14,
					 signature,
					 0x100,
					 rsa);

	/* cleanup */
	RSA_free(rsa);
	BIO_free(keybio);

	return res;
}
