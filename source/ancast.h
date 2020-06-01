#pragma once
#include <stdint.h>

#define ANCAST_MAGIC (0xEFA282D9l)
#define ANCAST_TARGET_IOP (0x02)
#define ANCAST_TARGET_PPC (0x01)

typedef struct AncastType1Signature AncastType1Signature;
typedef struct AncastType2Signature AncastType2Signature;
typedef struct AncastHeaderSignatureBlock AncastHeaderSignatureBlock;
typedef struct AncastHeaderInfoBlock AncastHeaderInfoBlock;
typedef struct AncastHeader AncastHeader;

#pragma pack(push)
#pragma pack(1)

struct AncastType1Signature
{
	uint8_t signature[0x38];
	uint8_t nullpad[0x44];
};

struct AncastType2Signature
{
	uint8_t signature[0x100];
	uint8_t nullpad[0x7C];
};

struct AncastHeaderSignatureBlock
{
	uint32_t type;
	union
	{
		AncastType1Signature type1;
		AncastType2Signature type2;
	};
};

struct AncastHeaderInfoBlock
{
	uint16_t nullpad0;
	uint8_t nullpad1;
	uint8_t nullpad2;
	uint32_t device;
	uint32_t type;
	uint32_t bodySize;
	uint8_t bodyHash[0x14];
	uint32_t version;
	uint8_t nullpad3[0x38];
};

struct AncastHeader
{
	uint32_t magic;
	uint8_t pad0[0x04];
	uint32_t signatureBlockOffset;
	uint8_t pad1[0x14];
};

#pragma pack(pop)
