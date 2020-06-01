#pragma once

typedef struct Signature Signature;

struct Signature
{
	const char *name;
	const char *pem;
};

extern const Signature valid_signatures[];
extern const unsigned valid_signatures_count;
