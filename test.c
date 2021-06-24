#include <stdio.h>
#include "80-bit PRESENT.h"

int main() {
	uint8_t plain[8]  = {0, 0, 0, 0, 0, 0, 0, 0};
	uint8_t key[10]   = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	uint8_t cipher[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	present_encrypt(plain, key, cipher);
	int i = 0;
	for(i = 0; i < 8; ++i)
		printf("%x ", cipher[i]);
	puts("");
	present_decrypt(cipher, key, plain);
	for(i = 0; i<8 ; ++i)
		printf("%x ",plain[i]);
	return 0;
}
