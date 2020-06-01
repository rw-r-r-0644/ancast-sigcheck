#include "endian.h"

uint16_t
rbe16(void *p)
{
	uint8_t *b = (uint8_t *)p;
	return
		((uint16_t)b[0] << 8) |
		((uint16_t)b[1] << 0);
}

uint32_t
rbe32(void *p)
{
	uint8_t *b = (uint8_t *)p;
	return
		((uint32_t)b[0] << 24) |
		((uint32_t)b[1] << 16) |
		((uint32_t)b[2] << 8) |
		((uint32_t)b[3] << 0);
}

uint64_t
rbe64(void *p)
{
	uint8_t *b = (uint8_t *)p;
	return
		((uint64_t)b[0] << 56) |
		((uint64_t)b[1] << 48) |
		((uint64_t)b[2] << 40) |
		((uint64_t)b[3] << 32) |
		((uint64_t)b[4] << 24) |
		((uint64_t)b[5] << 16) |
		((uint64_t)b[6] << 8) |
		((uint64_t)b[7] << 0);
}
