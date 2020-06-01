#include <openssl/sha.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "ancast.h"
#include "endian.h"
#include "rsa.h"
#include "signatures.h"

FILE *
f_ancast;

AncastHeader
header;

AncastHeaderSignatureBlock
sigblock;

AncastHeaderInfoBlock
infoblock;

off_t
bodyoffs;

void
usage()
{
	puts(
		"ancast-sigcheck v1 by rw-r-r-0644\n\n"
		"usage: ancast-sigcheck <ancast_image>\n"
	);
}

int
load_ancast_image(char *path)
{
	f_ancast = fopen(path, "rb");
	if (!f_ancast) {
		printf("error: failed to open %s\n", path);
		return -1;
	}

	/* read ancast header */
	if (fread(&header, sizeof(AncastHeader), 1, f_ancast) != 1) {
		printf("error: failed to read ancast header\n");
		return -2;
	}

	/* check ancast magic */
	if (rbe32(&header.magic) != ANCAST_MAGIC) {
		printf("error: invalid ancast magic\n");
		return -3;
	}

	/* read signature block */
	fseek(f_ancast, rbe32(&header.signatureBlockOffset), SEEK_SET);
	printf("info: ancast signature block at %08X\n", ftell(f_ancast));
	fread(&sigblock, sizeof(sigblock.type), 1, f_ancast);
	switch (rbe32(&sigblock.type)) {
		case 1:
			fread(&sigblock.type1, sizeof(sigblock.type1), 1, f_ancast);
			break;
		case 2:
			fread(&sigblock.type2, sizeof(sigblock.type2), 1, f_ancast);
			break;
		defult:
			printf("error: unknown signature type %u\n", rbe32(&sigblock.type));
			return -4;
	}

	/* read info block */
	printf("info: ancast info block at %08X\n", ftell(f_ancast));
	fread(&infoblock, sizeof(infoblock), 1, f_ancast);

	/* save ancast body offset */
	bodyoffs = ftell(f_ancast);
	printf("info: ancast body at %08X\n", bodyoffs);

	return 0;
}

void
unload_ancast_image()
{
	fclose(f_ancast);
}

int
verify_ancast_infoblock_nullpads()
{
	int i;

	/* verify all fields that must be set to zero */
	if (rbe32(&infoblock.nullpad0) != 0) {
		return -1;
	}
	if (infoblock.nullpad1 != 0) {
		return -2;
	}
	if (infoblock.nullpad2 != 0) {
		return -3;
	}
	for (i = 0; i < sizeof(infoblock.nullpad3); i++) {
		if (infoblock.nullpad3[i] != 0) {
			return -4;
		}
	}
	return 0;
}

int
verify_ancast_type1_signature()
{
	int i;
	AncastType1Signature *sigblock1 = &sigblock.type1;
	
	/* ensure the signature block null pad is empty */
	for (i = 0; i < sizeof(sigblock1->nullpad); i++) {
		if (sigblock1->nullpad[i] != 0) {
			printf("error: signature block pad is not empty\n");
			return -1;
		}
	}

	printf("warning: ancast type1 signature verification not implemented\n");
	return 0;
}

int
verify_ancast_type2_signature()
{
	int i;
	uint8_t infoblock_sha1[0x14];
	AncastType2Signature *sigblock2 = &sigblock.type2;

	/* ensure the signature block null pad is empty */
	for (i = 0; i < sizeof(sigblock2->nullpad); i++) {
		if (sigblock2->nullpad[i] != 0) {
			printf("error: signature block pad is not empty\n");
			return -1;
		}
	}

	/* compute information block sha1 */
	SHA1((unsigned char *)&infoblock,
		 sizeof(infoblock),
		 infoblock_sha1);

	/* check if it matches a known valid signature */
	for (i = 0; i < valid_signatures_count; i++) {
		/* valid signature */
		if (verify_rsa2048_signature(infoblock_sha1,
									 sigblock2->signature,
									 valid_signatures[i].pem)) {
			printf("info: validation successful using the %s\n",
				   valid_signatures[i].name);
			return 0;
		}
	}

	printf("error: invalid or unknown image signature\n");
	return -2;
}

int
verify_ancast_signature()
{
	uint32_t type = rbe32(&sigblock.type);
	printf("info: ancast signature type: %u\n", type);

	switch (type) {
		case 1:
			return verify_ancast_type1_signature();
		case 2:
			return verify_ancast_type2_signature();
	}

	return -1;
}

int
verify_ancast_body_checksum()
{
	uint32_t pos;
	uint32_t total;
	uint8_t block[0x40];
	uint8_t hash[0x14];
	SHA_CTX ctx;

	fseek(f_ancast, bodyoffs, SEEK_SET);

	/* get ancast body size */
	total = rbe32(&infoblock.bodySize);

	/* compute ancast body sha1 */
	SHA1_Init(&ctx);
	for (pos = 0; pos < total; pos += sizeof(block)) {
		fread(block, sizeof(block), 1, f_ancast);
		SHA1_Update(&ctx, block, sizeof(block));
	}
	fread(block, total - pos, 1, f_ancast);
	SHA1_Update(&ctx, block, total - pos);
	SHA1_Final(hash, &ctx);

	/* compare result with the info block */
	if (memcmp(infoblock.bodyHash, hash, sizeof(hash))) {
		printf("error: incorrect ancast image body sha1 checksum");
		return -1;
	}

	return 0;
}

int
main(int argc,
	 char **argv)
{
	if (argc != 2) {
		usage();
		return 0;
	}

	if (load_ancast_image(argv[1])) {
		printf(">> loading ancast image failed\n");
		return -1;
	} else {
		printf(">> loaded ancast image\n");
	}

	if (verify_ancast_infoblock_nullpads()) {
		printf(">> verifying ancast info block null fields failed\n");
		return -2;
	} else {
		printf(">> verified ancast info block null fields\n");
	}

	if (verify_ancast_signature()) {
		printf(">> verifying ancast signature failed\n");
		return -3;
	} else {
		printf(">> verified ancast signature\n");
	}

	if (verify_ancast_body_checksum()) {
		printf(">> verifying ancast body checksum failed\n");
		return -4;
	} else {
		printf(">> verified ancast body checksum\n");
	}

	printf(">> successfully verified ancast image!\n");
	return 0;
}
