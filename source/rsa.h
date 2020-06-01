#pragma once

int
verify_rsa2048_signature(void *sha1digest,
						 void *signature,
						 const char *pubkey);

