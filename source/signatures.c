#include "signatures.h"

const unsigned valid_signatures_count = 2;

const Signature valid_signatures[2] =
{
	{
		/* The retail signature used by boot0 to verify the boot1 image */
		.name = "retail boot1 signature",
		.pem = \
			"-----BEGIN PUBLIC KEY-----\n" \
			"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAniEJu+bXclIz2258bDGg\n" \
			"lzBP/OeL72yto8UsKEcw9EiGvNY8RZ6hyO7kUWUzuj1DqGkjfnknQmGAhhPVgyjl\n" \
			"rH+NnoqHfI+W0iqKaqjzl5AoHVcpMEkqjvHRj8xC9PWRJqLbVMmYhyb5GDCACWCC\n" \
			"Q8e7hCNoNmk2CyqAA21MBgZodZ83J408fCgMFOd6HcfXS3q3n6KSV0mhmP6LZ4iM\n" \
			"v+nLFdSc6Oo2sjx0f7yBrBniio08ABUSuOSNeZELBbIoBveyvY27HYadTxstxXRX\n" \
			"F3Q2tVGkZoEbx+63eVt/kF+rp9OW8xI4W5cXoB2DU0WA0WlEtzma5SzM8j041T33\n" \
			"+wIDAQAB\n" \
			"-----END PUBLIC KEY-----\n",
	},
	{
		/* The retail signature used by boot1 to verify the fw.img */
		.name = "retal firmware signature",
		.pem = \
			"-----BEGIN PUBLIC KEY-----\n" \
			"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApI2xAjgm/eWCnriOgYou\n" \
			"31Binf63x/D5y3AUDUxldCRNxQTzEK+fP3iFEcfhI1JLNtTjve7Nu8ISeFtW7fdt\n" \
			"ZWWc5haH6rSvN1kS09sTf9R9rY8rzv9Moi5eZ3hKxBqILCq6CQGPl4bvwz9IsuKK\n" \
			"C5suECOw+EZHJy1jMlwy7xNV+MHT3WIP96zy1O6TK+xB06oe6iACJRkyG8hj1c4+\n" \
			"QYhM/Iq9afjB0a05RSS7tB4ajDKMgBRA8YRbPd3KQu1Xe/TqHxIczkvy+Bqzxmch\n" \
			"31Qx8ic/4OaEKsLzB8IQwQgyTCs3cpwbzG1JHdAub3Wuo9DXbZkzEZcugHPGjCgJ\n" \
			"ZQIDAQAB\n" \
			"-----END PUBLIC KEY-----\n",
	},
};
