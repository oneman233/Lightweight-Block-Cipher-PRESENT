typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

uint8_t sbox[16] = {
	0x0C,0x05,0x06,0x0B,
	0x09,0x00,0x0A,0x0D,
	0x03,0x0E,0x0F,0x08,
	0x04,0x07,0x01,0x02
};

uint8_t reverse_sbox[16] = {
	0x05,0x0E,0x0F,0x08,
	0x0C,0x01,0x02,0x0D,
	0x0B,0x04,0x06,0x03,
	0x00,0x07,0x09,0x0A
};

void present_encrypt(const uint8_t *plain, const uint8_t *key, uint8_t *ans) {
	uint8_t state[8];
	uint8_t round_key[10];
	// round_key[0] = k79
	uint8_t buf[10];
	// for temporary storage 
	
	uint8_t round_counter = 1;
	
	/*
		round 1
	*/
	
	// addRoundKey
	state[0] = plain[0] ^ key[0];
	state[1] = plain[1] ^ key[1];
	state[2] = plain[2] ^ key[2];
	state[3] = plain[3] ^ key[3];
	state[4] = plain[4] ^ key[4];
	state[5] = plain[5] ^ key[5];
	state[6] = plain[6] ^ key[6];
	state[7] = plain[7] ^ key[7];
	
	// updateKey
	round_key[9] = key[6] << 5 | key[7] >> 3;
	round_key[8] = key[5] << 5 | key[6] >> 3;
	round_key[7] = key[4] << 5 | key[5] >> 3;
	round_key[6] = key[3] << 5 | key[4] >> 3;
	round_key[5] = key[2] << 5 | key[3] >> 3;
	round_key[4] = key[1] << 5 | key[2] >> 3;
	round_key[3] = key[0] << 5 | key[1] >> 3;
	round_key[2] = key[9] << 5 | key[0] >> 3;
	round_key[1] = key[8] << 5 | key[9] >> 3;
	round_key[0] = key[7] << 5 | key[8] >> 3;
	
	round_key[0] = (round_key[0] & 0x0F) | (sbox[round_key[0] >> 4] << 4);
	
	round_key[7] ^= round_counter >> 1;
	round_key[8] ^= round_counter << 7;
	
	// sBoxLayer
	state[0] = sbox[state[0] & 0x0F] | (sbox[state[0] >> 4] << 4);
	state[1] = sbox[state[1] & 0x0F] | (sbox[state[1] >> 4] << 4);
	state[2] = sbox[state[2] & 0x0F] | (sbox[state[2] >> 4] << 4);
	state[3] = sbox[state[3] & 0x0F] | (sbox[state[3] >> 4] << 4);
	state[4] = sbox[state[4] & 0x0F] | (sbox[state[4] >> 4] << 4);
	state[5] = sbox[state[5] & 0x0F] | (sbox[state[5] >> 4] << 4);
	state[6] = sbox[state[6] & 0x0F] | (sbox[state[6] >> 4] << 4);
	state[7] = sbox[state[7] & 0x0F] | (sbox[state[7] >> 4] << 4);
	
	// pLayer
	buf[0] = state[0];
	buf[1] = state[1];
	buf[2] = state[2];
	buf[3] = state[3];
	buf[4] = state[4];
	buf[5] = state[5];
	buf[6] = state[6];
	buf[7] = state[7];
	
	state[0] = (buf[7 - 63 / 8] >> (63 % 8) & 1) << 7 | // 63
			   (buf[7 - 59 / 8] >> (59 % 8) & 1) << 6 | // 62
			   (buf[7 - 55 / 8] >> (55 % 8) & 1) << 5 | // 61
			   (buf[7 - 51 / 8] >> (51 % 8) & 1) << 4 | // 60
			   (buf[7 - 47 / 8] >> (47 % 8) & 1) << 3 | // 59
			   (buf[7 - 43 / 8] >> (43 % 8) & 1) << 2 | // 58
			   (buf[7 - 39 / 8] >> (39 % 8) & 1) << 1 | // 57
			   (buf[7 - 35 / 8] >> (35 % 8) & 1);       // 56
		   		
	state[1] = (buf[7 - 31 / 8] >> (31 % 8) & 1) << 7 | // 55
			   (buf[7 - 27 / 8] >> (27 % 8) & 1) << 6 | // 54
			   (buf[7 - 23 / 8] >> (23 % 8) & 1) << 5 | // 53
			   (buf[7 - 19 / 8] >> (19 % 8) & 1) << 4 | // 52
			   (buf[7 - 15 / 8] >> (15 % 8) & 1) << 3 | // 51
			   (buf[7 - 11 / 8] >> (11 % 8) & 1) << 2 | // 50
			   (buf[7 - 7 / 8] >> (7 % 8) & 1) << 1   | // 49
			   (buf[7 - 3 / 8] >> (3 % 8) & 1);         // 48
			   
	state[2] = (buf[7 - 62 / 8] >> (62 % 8) & 1) << 7 | // 47
			   (buf[7 - 58 / 8] >> (58 % 8) & 1) << 6 | // 46
			   (buf[7 - 54 / 8] >> (54 % 8) & 1) << 5 | // 45
			   (buf[7 - 50 / 8] >> (50 % 8) & 1) << 4 | // 44
			   (buf[7 - 46 / 8] >> (46 % 8) & 1) << 3 | // 43
			   (buf[7 - 42 / 8] >> (42 % 8) & 1) << 2 | // 42
			   (buf[7 - 38 / 8] >> (38 % 8) & 1) << 1 | // 41
			   (buf[7 - 34 / 8] >> (34 % 8) & 1);       // 40
			   
	state[3] = (buf[7 - 30 / 8] >> (30 % 8) & 1) << 7 | // 39
			   (buf[7 - 26 / 8] >> (26 % 8) & 1) << 6 | // 38
			   (buf[7 - 22 / 8] >> (22 % 8) & 1) << 5 | // 37
			   (buf[7 - 18 / 8] >> (18 % 8) & 1) << 4 | // 36
			   (buf[7 - 14 / 8] >> (14 % 8) & 1) << 3 | // 35
			   (buf[7 - 10 / 8] >> (10 % 8) & 1) << 2 | // 34
			   (buf[7 - 6 / 8] >> (6 % 8) & 1) << 1   | // 33
			   (buf[7 - 2 / 8] >> (2 % 8) & 1);         // 32
			   
	state[4] = (buf[7 - 61 / 8] >> (61 % 8) & 1) << 7 | // 31
			   (buf[7 - 57 / 8] >> (57 % 8) & 1) << 6 | // 30
			   (buf[7 - 53 / 8] >> (53 % 8) & 1) << 5 | // 29
			   (buf[7 - 49 / 8] >> (49 % 8) & 1) << 4 | // 28
			   (buf[7 - 45 / 8] >> (45 % 8) & 1) << 3 | // 27
			   (buf[7 - 41 / 8] >> (41 % 8) & 1) << 2 | // 26
			   (buf[7 - 37 / 8] >> (37 % 8) & 1) << 1 | // 25
			   (buf[7 - 33 / 8] >> (33 % 8) & 1);       // 24
			   
	state[5] = (buf[7 - 29 / 8] >> (29 % 8) & 1) << 7 | // 23
			   (buf[7 - 25 / 8] >> (25 % 8) & 1) << 6 | // 22
			   (buf[7 - 21 / 8] >> (21 % 8) & 1) << 5 | // 21
			   (buf[7 - 17 / 8] >> (17 % 8) & 1) << 4 | // 20
			   (buf[7 - 13 / 8] >> (13 % 8) & 1) << 3 | // 19
			   (buf[7 - 9 / 8] >> (9 % 8) & 1) << 2   | // 18
			   (buf[7 - 5 / 8] >> (5 % 8) & 1) << 1   | // 17
			   (buf[7 - 1 / 8] >> (1 % 8) & 1);         // 16
			   
	state[6] = (buf[7 - 60 / 8] >> (60 % 8) & 1) << 7 | // 15
			   (buf[7 - 56 / 8] >> (56 % 8) & 1) << 6 | // 14
			   (buf[7 - 52 / 8] >> (52 % 8) & 1) << 5 | // 13
			   (buf[7 - 48 / 8] >> (48 % 8) & 1) << 4 | // 12
			   (buf[7 - 44 / 8] >> (44 % 8) & 1) << 3 | // 11
			   (buf[7 - 40 / 8] >> (40 % 8) & 1) << 2 | // 10
			   (buf[7 - 36 / 8] >> (36 % 8) & 1) << 1 | // 9
			   (buf[7 - 32 / 8] >> (32 % 8) & 1);       // 8
			   
	state[7] = (buf[7 - 28 / 8] >> (28 % 8) & 1) << 7 | // 7
			   (buf[7 - 24 / 8] >> (24 % 8) & 1) << 6 | // 6
			   (buf[7 - 20 / 8] >> (20 % 8) & 1) << 5 | // 5
			   (buf[7 - 16 / 8] >> (16 % 8) & 1) << 4 | // 4
			   (buf[7 - 12 / 8] >> (12 % 8) & 1) << 3 | // 3
			   (buf[7 - 8 / 8] >> (8 % 8) & 1) << 2   | // 2
			   (buf[7 - 4 / 8] >> (4 % 8) & 1) << 1   | // 1
			   (buf[7 - 0 / 8] >> (0 % 8) & 1);         // 0

	/*
		round 2 - round 31
	*/

	for(round_counter = 2; round_counter <= 31; ++round_counter) {
		// addRoundKey
		state[0] ^= round_key[0];
		state[1] ^= round_key[1];
		state[2] ^= round_key[2];
		state[3] ^= round_key[3];
		state[4] ^= round_key[4];
		state[5] ^= round_key[5];
		state[6] ^= round_key[6];
		state[7] ^= round_key[7];
		
		// updateKey
		buf[9] = round_key[9];
		buf[8] = round_key[8];
		buf[7] = round_key[7];
		buf[6] = round_key[6];
		buf[5] = round_key[5];
		buf[4] = round_key[4];
		buf[3] = round_key[3];
		buf[2] = round_key[2];
		buf[1] = round_key[1];
		buf[0] = round_key[0];
		
		round_key[9] = buf[6] << 5 | buf[7] >> 3;
		round_key[8] = buf[5] << 5 | buf[6] >> 3;
		round_key[7] = buf[4] << 5 | buf[5] >> 3;
		round_key[6] = buf[3] << 5 | buf[4] >> 3;
		round_key[5] = buf[2] << 5 | buf[3] >> 3;
		round_key[4] = buf[1] << 5 | buf[2] >> 3;
		round_key[3] = buf[0] << 5 | buf[1] >> 3;
		round_key[2] = buf[9] << 5 | buf[0] >> 3;
		round_key[1] = buf[8] << 5 | buf[9] >> 3;
		round_key[0] = buf[7] << 5 | buf[8] >> 3;
		
		round_key[0] = (round_key[0] & 0x0F) | (sbox[round_key[0] >> 4] << 4);
		
		round_key[7] ^= round_counter >> 1;
		round_key[8] ^= round_counter << 7;
		
		// sBoxLayer
		state[0] = sbox[state[0] & 0x0F] | (sbox[state[0] >> 4] << 4);
		state[1] = sbox[state[1] & 0x0F] | (sbox[state[1] >> 4] << 4);
		state[2] = sbox[state[2] & 0x0F] | (sbox[state[2] >> 4] << 4);
		state[3] = sbox[state[3] & 0x0F] | (sbox[state[3] >> 4] << 4);
		state[4] = sbox[state[4] & 0x0F] | (sbox[state[4] >> 4] << 4);
		state[5] = sbox[state[5] & 0x0F] | (sbox[state[5] >> 4] << 4);
		state[6] = sbox[state[6] & 0x0F] | (sbox[state[6] >> 4] << 4);
		state[7] = sbox[state[7] & 0x0F] | (sbox[state[7] >> 4] << 4);
		
		// pLayer
		buf[0] = state[0];
		buf[1] = state[1];
		buf[2] = state[2];
		buf[3] = state[3];
		buf[4] = state[4];
		buf[5] = state[5];
		buf[6] = state[6];
		buf[7] = state[7];
		
		state[0] = (buf[7 - 63 / 8] >> (63 % 8) & 1) << 7 | // 63
				   (buf[7 - 59 / 8] >> (59 % 8) & 1) << 6 | // 62
				   (buf[7 - 55 / 8] >> (55 % 8) & 1) << 5 | // 61
				   (buf[7 - 51 / 8] >> (51 % 8) & 1) << 4 | // 60
				   (buf[7 - 47 / 8] >> (47 % 8) & 1) << 3 | // 59
				   (buf[7 - 43 / 8] >> (43 % 8) & 1) << 2 | // 58
				   (buf[7 - 39 / 8] >> (39 % 8) & 1) << 1 | // 57
				   (buf[7 - 35 / 8] >> (35 % 8) & 1);       // 56
			   	   
		state[1] = (buf[7 - 31 / 8] >> (31 % 8) & 1) << 7 | // 55
				   (buf[7 - 27 / 8] >> (27 % 8) & 1) << 6 | // 54
				   (buf[7 - 23 / 8] >> (23 % 8) & 1) << 5 | // 53
				   (buf[7 - 19 / 8] >> (19 % 8) & 1) << 4 | // 52
				   (buf[7 - 15 / 8] >> (15 % 8) & 1) << 3 | // 51
				   (buf[7 - 11 / 8] >> (11 % 8) & 1) << 2 | // 50
				   (buf[7 - 7 / 8] >> (7 % 8) & 1) << 1   | // 49
				   (buf[7 - 3 / 8] >> (3 % 8) & 1);         // 48
				   
		state[2] = (buf[7 - 62 / 8] >> (62 % 8) & 1) << 7 | // 47
				   (buf[7 - 58 / 8] >> (58 % 8) & 1) << 6 | // 46
				   (buf[7 - 54 / 8] >> (54 % 8) & 1) << 5 | // 45
				   (buf[7 - 50 / 8] >> (50 % 8) & 1) << 4 | // 44
				   (buf[7 - 46 / 8] >> (46 % 8) & 1) << 3 | // 43
				   (buf[7 - 42 / 8] >> (42 % 8) & 1) << 2 | // 42
				   (buf[7 - 38 / 8] >> (38 % 8) & 1) << 1 | // 41
				   (buf[7 - 34 / 8] >> (34 % 8) & 1);       // 40
				   
		state[3] = (buf[7 - 30 / 8] >> (30 % 8) & 1) << 7 | // 39
				   (buf[7 - 26 / 8] >> (26 % 8) & 1) << 6 | // 38
				   (buf[7 - 22 / 8] >> (22 % 8) & 1) << 5 | // 37
				   (buf[7 - 18 / 8] >> (18 % 8) & 1) << 4 | // 36
				   (buf[7 - 14 / 8] >> (14 % 8) & 1) << 3 | // 35
				   (buf[7 - 10 / 8] >> (10 % 8) & 1) << 2 | // 34
				   (buf[7 - 6 / 8] >> (6 % 8) & 1) << 1   | // 33
				   (buf[7 - 2 / 8] >> (2 % 8) & 1);         // 32
				   
		state[4] = (buf[7 - 61 / 8] >> (61 % 8) & 1) << 7 | // 31
				   (buf[7 - 57 / 8] >> (57 % 8) & 1) << 6 | // 30
				   (buf[7 - 53 / 8] >> (53 % 8) & 1) << 5 | // 29
				   (buf[7 - 49 / 8] >> (49 % 8) & 1) << 4 | // 28
				   (buf[7 - 45 / 8] >> (45 % 8) & 1) << 3 | // 27
				   (buf[7 - 41 / 8] >> (41 % 8) & 1) << 2 | // 26
				   (buf[7 - 37 / 8] >> (37 % 8) & 1) << 1 | // 25
				   (buf[7 - 33 / 8] >> (33 % 8) & 1);       // 24
				   
		state[5] = (buf[7 - 29 / 8] >> (29 % 8) & 1) << 7 | // 23
				   (buf[7 - 25 / 8] >> (25 % 8) & 1) << 6 | // 22
				   (buf[7 - 21 / 8] >> (21 % 8) & 1) << 5 | // 21
				   (buf[7 - 17 / 8] >> (17 % 8) & 1) << 4 | // 20
				   (buf[7 - 13 / 8] >> (13 % 8) & 1) << 3 | // 19
				   (buf[7 - 9 / 8] >> (9 % 8) & 1) << 2   | // 18
				   (buf[7 - 5 / 8] >> (5 % 8) & 1) << 1   | // 17
				   (buf[7 - 1 / 8] >> (1 % 8) & 1);         // 16
				   
		state[6] = (buf[7 - 60 / 8] >> (60 % 8) & 1) << 7 | // 15
				   (buf[7 - 56 / 8] >> (56 % 8) & 1) << 6 | // 14
				   (buf[7 - 52 / 8] >> (52 % 8) & 1) << 5 | // 13
				   (buf[7 - 48 / 8] >> (48 % 8) & 1) << 4 | // 12
				   (buf[7 - 44 / 8] >> (44 % 8) & 1) << 3 | // 11
				   (buf[7 - 40 / 8] >> (40 % 8) & 1) << 2 | // 10
				   (buf[7 - 36 / 8] >> (36 % 8) & 1) << 1 | // 9
				   (buf[7 - 32 / 8] >> (32 % 8) & 1);       // 8
				   
		state[7] = (buf[7 - 28 / 8] >> (28 % 8) & 1) << 7 | // 7
				   (buf[7 - 24 / 8] >> (24 % 8) & 1) << 6 | // 6
				   (buf[7 - 20 / 8] >> (20 % 8) & 1) << 5 | // 5
				   (buf[7 - 16 / 8] >> (16 % 8) & 1) << 4 | // 4
				   (buf[7 - 12 / 8] >> (12 % 8) & 1) << 3 | // 3
				   (buf[7 - 8 / 8] >> (8 % 8) & 1) << 2   | // 2
				   (buf[7 - 4 / 8] >> (4 % 8) & 1) << 1   | // 1
				   (buf[7 - 0 / 8] >> (0 % 8) & 1);         // 0
	}
	// post-whitening
	state[0] ^= round_key[0];
	state[1] ^= round_key[1];
	state[2] ^= round_key[2];
	state[3] ^= round_key[3];
	state[4] ^= round_key[4];
	state[5] ^= round_key[5];
	state[6] ^= round_key[6];
	state[7] ^= round_key[7];
	
	// get result
	ans[0] = state[0];
	ans[1] = state[1];
	ans[2] = state[2];
	ans[3] = state[3];
	ans[4] = state[4];
	ans[5] = state[5];
	ans[6] = state[6];
	ans[7] = state[7];
}

void present_decrypt(const uint8_t *cipher, const uint8_t *key, uint8_t *ans) {
	uint8_t state[8];
	uint8_t round_key[32][10];
	/*
		round_key[i][0] = k79
		Pre-calculate all round_key
	*/
	uint8_t buf[10];
	// for temporary storage 
	
	uint8_t round_counter;
	
	round_key[0][9] = key[9];
	round_key[0][8] = key[8];
	round_key[0][7] = key[7];
	round_key[0][6] = key[6];
	round_key[0][5] = key[5];
	round_key[0][4] = key[4];
	round_key[0][3] = key[3];
	round_key[0][2] = key[2];
	round_key[0][1] = key[1];
	round_key[0][0] = key[0];
	
	for(round_counter = 1; round_counter <= 31; ++round_counter) {
		// updateKey	
		round_key[round_counter][9] =
			round_key[round_counter - 1][6] << 5 |
			round_key[round_counter - 1][7] >> 3;
		round_key[round_counter][8] =
			round_key[round_counter - 1][5] << 5 |
			round_key[round_counter - 1][6] >> 3;
		round_key[round_counter][7] =
			round_key[round_counter - 1][4] << 5 |
			round_key[round_counter - 1][5] >> 3;
		round_key[round_counter][6] =
			round_key[round_counter - 1][3] << 5 |
			round_key[round_counter - 1][4] >> 3;
		round_key[round_counter][5] =
			round_key[round_counter - 1][2] << 5 |
			round_key[round_counter - 1][3] >> 3;
		round_key[round_counter][4] =
			round_key[round_counter - 1][1] << 5 |
			round_key[round_counter - 1][2] >> 3;
		round_key[round_counter][3] =
			round_key[round_counter - 1][0] << 5 |
			round_key[round_counter - 1][1] >> 3;
		round_key[round_counter][2] =
			round_key[round_counter - 1][9] << 5 |
			round_key[round_counter - 1][0] >> 3;
		round_key[round_counter][1] =
			round_key[round_counter - 1][8] << 5 |
			round_key[round_counter - 1][9] >> 3;
		round_key[round_counter][0] =
			round_key[round_counter - 1][7] << 5 |
			round_key[round_counter - 1][8] >> 3;
		
		round_key[round_counter][0] =
			(round_key[round_counter][0] & 0x0F) |
			(sbox[round_key[round_counter][0] >> 4] << 4);
		
		round_key[round_counter][7] ^= round_counter >> 1;
		round_key[round_counter][8] ^= round_counter << 7;
	}
	
	/*
		post-whitening
	*/
	
	state[0] = cipher[0] ^ round_key[31][0];
	state[1] = cipher[1] ^ round_key[31][1];
	state[2] = cipher[2] ^ round_key[31][2];
	state[3] = cipher[3] ^ round_key[31][3];
	state[4] = cipher[4] ^ round_key[31][4];
	state[5] = cipher[5] ^ round_key[31][5];
	state[6] = cipher[6] ^ round_key[31][6];
	state[7] = cipher[7] ^ round_key[31][7];
	
	/*
		round 31 - round 1
	*/
	
	for(round_counter = 30; round_counter >= 1; --round_counter) {
		// pLayer
		buf[0] = state[0];
		buf[1] = state[1];
		buf[2] = state[2];
		buf[3] = state[3];
		buf[4] = state[4];
		buf[5] = state[5];
		buf[6] = state[6];
		buf[7] = state[7];
		
		state[0] = (buf[7 - 63 / 8] >> (63 % 8) & 1) << 7 | // 63
				   (buf[7 - 47 / 8] >> (47 % 8) & 1) << 6 | // 62
				   (buf[7 - 31 / 8] >> (31 % 8) & 1) << 5 | // 61
				   (buf[7 - 15 / 8] >> (15 % 8) & 1) << 4 | // 60
				   (buf[7 - 62 / 8] >> (62 % 8) & 1) << 3 | // 59
				   (buf[7 - 46 / 8] >> (46 % 8) & 1) << 2 | // 58
				   (buf[7 - 30 / 8] >> (30 % 8) & 1) << 1 | // 57
				   (buf[7 - 14 / 8] >> (14 % 8) & 1);       // 56
			   	   
		state[1] = (buf[7 - 61 / 8] >> (61 % 8) & 1) << 7 | // 55
				   (buf[7 - 45 / 8] >> (45 % 8) & 1) << 6 | // 54
				   (buf[7 - 29 / 8] >> (29 % 8) & 1) << 5 | // 53
				   (buf[7 - 13 / 8] >> (13 % 8) & 1) << 4 | // 52
				   (buf[7 - 60 / 8] >> (60 % 8) & 1) << 3 | // 51
				   (buf[7 - 44 / 8] >> (44 % 8) & 1) << 2 | // 50
				   (buf[7 - 28 / 8] >> (28 % 8) & 1) << 1 | // 49
				   (buf[7 - 12 / 8] >> (12 % 8) & 1);       // 48
				   
		state[2] = (buf[7 - 59 / 8] >> (59 % 8) & 1) << 7 | // 47
				   (buf[7 - 43 / 8] >> (43 % 8) & 1) << 6 | // 46
				   (buf[7 - 27 / 8] >> (27 % 8) & 1) << 5 | // 45
				   (buf[7 - 11 / 8] >> (11 % 8) & 1) << 4 | // 44
				   (buf[7 - 58 / 8] >> (58 % 8) & 1) << 3 | // 43
				   (buf[7 - 42 / 8] >> (42 % 8) & 1) << 2 | // 42
				   (buf[7 - 26 / 8] >> (26 % 8) & 1) << 1 | // 41
				   (buf[7 - 10 / 8] >> (10 % 8) & 1);       // 40
				   
		state[3] = (buf[7 - 57 / 8] >> (57 % 8) & 1) << 7 | // 39
				   (buf[7 - 41 / 8] >> (41 % 8) & 1) << 6 | // 38
				   (buf[7 - 25 / 8] >> (25 % 8) & 1) << 5 | // 37
				   (buf[7 - 9 / 8] >> (9 % 8) & 1) << 4   | // 36
				   (buf[7 - 56 / 8] >> (56 % 8) & 1) << 3 | // 35
				   (buf[7 - 40 / 8] >> (40 % 8) & 1) << 2 | // 34
				   (buf[7 - 24 / 8] >> (24 % 8) & 1) << 1 | // 33
				   (buf[7 - 8 / 8] >> (8 % 8) & 1);         // 32
				   
		state[4] = (buf[7 - 55 / 8] >> (55 % 8) & 1) << 7 | // 31
				   (buf[7 - 39 / 8] >> (39 % 8) & 1) << 6 | // 30
				   (buf[7 - 23 / 8] >> (23 % 8) & 1) << 5 | // 29
				   (buf[7 - 7 / 8] >> (7 % 8) & 1) << 4   | // 28
				   (buf[7 - 54 / 8] >> (54 % 8) & 1) << 3 | // 27
				   (buf[7 - 38 / 8] >> (38 % 8) & 1) << 2 | // 26
				   (buf[7 - 22 / 8] >> (22 % 8) & 1) << 1 | // 25
				   (buf[7 - 6 / 8] >> (6 % 8) & 1);         // 24
				   
		state[5] = (buf[7 - 53 / 8] >> (53 % 8) & 1) << 7 | // 23
				   (buf[7 - 37 / 8] >> (37 % 8) & 1) << 6 | // 22
				   (buf[7 - 21 / 8] >> (21 % 8) & 1) << 5 | // 21
				   (buf[7 - 5 / 8] >> (5 % 8) & 1) << 4   | // 20
				   (buf[7 - 52 / 8] >> (52 % 8) & 1) << 3 | // 19
				   (buf[7 - 36 / 8] >> (36 % 8) & 1) << 2 | // 18
				   (buf[7 - 20 / 8] >> (20 % 8) & 1) << 1 | // 17
				   (buf[7 - 4 / 8] >> (4 % 8) & 1);         // 16
				   
		state[6] = (buf[7 - 51 / 8] >> (51 % 8) & 1) << 7 | // 15
				   (buf[7 - 35 / 8] >> (35 % 8) & 1) << 6 | // 14
				   (buf[7 - 19 / 8] >> (19 % 8) & 1) << 5 | // 13
				   (buf[7 - 3 / 8] >> (3 % 8) & 1) << 4   | // 12
				   (buf[7 - 50 / 8] >> (50 % 8) & 1) << 3 | // 11
				   (buf[7 - 34 / 8] >> (34 % 8) & 1) << 2 | // 10
				   (buf[7 - 18 / 8] >> (18 % 8) & 1) << 1 | // 9
				   (buf[7 - 2 / 8] >> (2 % 8) & 1);         // 8
				   
		state[7] = (buf[7 - 49 / 8] >> (49 % 8) & 1) << 7 | // 7
				   (buf[7 - 33 / 8] >> (33 % 8) & 1) << 6 | // 6
				   (buf[7 - 17 / 8] >> (17 % 8) & 1) << 5 | // 5
				   (buf[7 - 1 / 8] >> (1 % 8) & 1) << 4   | // 4
				   (buf[7 - 48 / 8] >> (48 % 8) & 1) << 3 | // 3
				   (buf[7 - 32 / 8] >> (32 % 8) & 1) << 2 | // 2
				   (buf[7 - 16 / 8] >> (16 % 8) & 1) << 1 | // 1
				   (buf[7 - 0 / 8] >> (0 % 8) & 1);         // 0
		
		// sBoxLayer
		state[0] = reverse_sbox[state[0] & 0x0F] | (reverse_sbox[state[0] >> 4] << 4);
		state[1] = reverse_sbox[state[1] & 0x0F] | (reverse_sbox[state[1] >> 4] << 4);
		state[2] = reverse_sbox[state[2] & 0x0F] | (reverse_sbox[state[2] >> 4] << 4);
		state[3] = reverse_sbox[state[3] & 0x0F] | (reverse_sbox[state[3] >> 4] << 4);
		state[4] = reverse_sbox[state[4] & 0x0F] | (reverse_sbox[state[4] >> 4] << 4);
		state[5] = reverse_sbox[state[5] & 0x0F] | (reverse_sbox[state[5] >> 4] << 4);
		state[6] = reverse_sbox[state[6] & 0x0F] | (reverse_sbox[state[6] >> 4] << 4);
		state[7] = reverse_sbox[state[7] & 0x0F] | (reverse_sbox[state[7] >> 4] << 4);
		
		// addRoundKey
		state[0] ^= round_key[round_counter][0];
		state[1] ^= round_key[round_counter][1];
		state[2] ^= round_key[round_counter][2];
		state[3] ^= round_key[round_counter][3];
		state[4] ^= round_key[round_counter][4];
		state[5] ^= round_key[round_counter][5];
		state[6] ^= round_key[round_counter][6];
		state[7] ^= round_key[round_counter][7];
	}
	// pLayer
	buf[0] = state[0];
	buf[1] = state[1];
	buf[2] = state[2];
	buf[3] = state[3];
	buf[4] = state[4];
	buf[5] = state[5];
	buf[6] = state[6];
	buf[7] = state[7];
	
	state[0] = (buf[7 - 63 / 8] >> (63 % 8) & 1) << 7 | // 63
			   (buf[7 - 47 / 8] >> (47 % 8) & 1) << 6 | // 62
			   (buf[7 - 31 / 8] >> (31 % 8) & 1) << 5 | // 61
			   (buf[7 - 15 / 8] >> (15 % 8) & 1) << 4 | // 60
			   (buf[7 - 62 / 8] >> (62 % 8) & 1) << 3 | // 59
			   (buf[7 - 46 / 8] >> (46 % 8) & 1) << 2 | // 58
			   (buf[7 - 30 / 8] >> (30 % 8) & 1) << 1 | // 57
			   (buf[7 - 14 / 8] >> (14 % 8) & 1);       // 56
		   	   
	state[1] = (buf[7 - 61 / 8] >> (61 % 8) & 1) << 7 | // 55
			   (buf[7 - 45 / 8] >> (45 % 8) & 1) << 6 | // 54
			   (buf[7 - 29 / 8] >> (29 % 8) & 1) << 5 | // 53
			   (buf[7 - 13 / 8] >> (13 % 8) & 1) << 4 | // 52
			   (buf[7 - 60 / 8] >> (60 % 8) & 1) << 3 | // 51
			   (buf[7 - 44 / 8] >> (44 % 8) & 1) << 2 | // 50
			   (buf[7 - 28 / 8] >> (28 % 8) & 1) << 1 | // 49
			   (buf[7 - 12 / 8] >> (12 % 8) & 1);       // 48
			   
	state[2] = (buf[7 - 59 / 8] >> (59 % 8) & 1) << 7 | // 47
			   (buf[7 - 43 / 8] >> (43 % 8) & 1) << 6 | // 46
			   (buf[7 - 27 / 8] >> (27 % 8) & 1) << 5 | // 45
			   (buf[7 - 11 / 8] >> (11 % 8) & 1) << 4 | // 44
			   (buf[7 - 58 / 8] >> (58 % 8) & 1) << 3 | // 43
			   (buf[7 - 42 / 8] >> (42 % 8) & 1) << 2 | // 42
			   (buf[7 - 26 / 8] >> (26 % 8) & 1) << 1 | // 41
			   (buf[7 - 10 / 8] >> (10 % 8) & 1);       // 40
			   
	state[3] = (buf[7 - 57 / 8] >> (57 % 8) & 1) << 7 | // 39
			   (buf[7 - 41 / 8] >> (41 % 8) & 1) << 6 | // 38
			   (buf[7 - 25 / 8] >> (25 % 8) & 1) << 5 | // 37
			   (buf[7 - 9 / 8] >> (9 % 8) & 1) << 4   | // 36
			   (buf[7 - 56 / 8] >> (56 % 8) & 1) << 3 | // 35
			   (buf[7 - 40 / 8] >> (40 % 8) & 1) << 2 | // 34
			   (buf[7 - 24 / 8] >> (24 % 8) & 1) << 1 | // 33
			   (buf[7 - 8 / 8] >> (8 % 8) & 1);         // 32
			   
	state[4] = (buf[7 - 55 / 8] >> (55 % 8) & 1) << 7 | // 31
			   (buf[7 - 39 / 8] >> (39 % 8) & 1) << 6 | // 30
			   (buf[7 - 23 / 8] >> (23 % 8) & 1) << 5 | // 29
			   (buf[7 - 7 / 8] >> (7 % 8) & 1) << 4   | // 28
			   (buf[7 - 54 / 8] >> (54 % 8) & 1) << 3 | // 27
			   (buf[7 - 38 / 8] >> (38 % 8) & 1) << 2 | // 26
			   (buf[7 - 22 / 8] >> (22 % 8) & 1) << 1 | // 25
			   (buf[7 - 6 / 8] >> (6 % 8) & 1);         // 24
			   
	state[5] = (buf[7 - 53 / 8] >> (53 % 8) & 1) << 7 | // 23
			   (buf[7 - 37 / 8] >> (37 % 8) & 1) << 6 | // 22
			   (buf[7 - 21 / 8] >> (21 % 8) & 1) << 5 | // 21
			   (buf[7 - 5 / 8] >> (5 % 8) & 1) << 4   | // 20
			   (buf[7 - 52 / 8] >> (52 % 8) & 1) << 3 | // 19
			   (buf[7 - 36 / 8] >> (36 % 8) & 1) << 2 | // 18
			   (buf[7 - 20 / 8] >> (20 % 8) & 1) << 1 | // 17
			   (buf[7 - 4 / 8] >> (4 % 8) & 1);         // 16
			   
	state[6] = (buf[7 - 51 / 8] >> (51 % 8) & 1) << 7 | // 15
			   (buf[7 - 35 / 8] >> (35 % 8) & 1) << 6 | // 14
			   (buf[7 - 19 / 8] >> (19 % 8) & 1) << 5 | // 13
			   (buf[7 - 3 / 8] >> (3 % 8) & 1) << 4   | // 12
			   (buf[7 - 50 / 8] >> (50 % 8) & 1) << 3 | // 11
			   (buf[7 - 34 / 8] >> (34 % 8) & 1) << 2 | // 10
			   (buf[7 - 18 / 8] >> (18 % 8) & 1) << 1 | // 9
			   (buf[7 - 2 / 8] >> (2 % 8) & 1);         // 8
			   
	state[7] = (buf[7 - 49 / 8] >> (49 % 8) & 1) << 7 | // 7
			   (buf[7 - 33 / 8] >> (33 % 8) & 1) << 6 | // 6
			   (buf[7 - 17 / 8] >> (17 % 8) & 1) << 5 | // 5
			   (buf[7 - 1 / 8] >> (1 % 8) & 1) << 4   | // 4
			   (buf[7 - 48 / 8] >> (48 % 8) & 1) << 3 | // 3
			   (buf[7 - 32 / 8] >> (32 % 8) & 1) << 2 | // 2
			   (buf[7 - 16 / 8] >> (16 % 8) & 1) << 1 | // 1
			   (buf[7 - 0 / 8] >> (0 % 8) & 1);         // 0
	
	// sBoxLayer
	state[0] = reverse_sbox[state[0] & 0x0F] | (reverse_sbox[state[0] >> 4] << 4);
	state[1] = reverse_sbox[state[1] & 0x0F] | (reverse_sbox[state[1] >> 4] << 4);
	state[2] = reverse_sbox[state[2] & 0x0F] | (reverse_sbox[state[2] >> 4] << 4);
	state[3] = reverse_sbox[state[3] & 0x0F] | (reverse_sbox[state[3] >> 4] << 4);
	state[4] = reverse_sbox[state[4] & 0x0F] | (reverse_sbox[state[4] >> 4] << 4);
	state[5] = reverse_sbox[state[5] & 0x0F] | (reverse_sbox[state[5] >> 4] << 4);
	state[6] = reverse_sbox[state[6] & 0x0F] | (reverse_sbox[state[6] >> 4] << 4);
	state[7] = reverse_sbox[state[7] & 0x0F] | (reverse_sbox[state[7] >> 4] << 4);

	state[0] = state[0] ^ round_key[0][0];
	state[1] = state[1] ^ round_key[0][1];
	state[2] = state[2] ^ round_key[0][2];
	state[3] = state[3] ^ round_key[0][3];
	state[4] = state[4] ^ round_key[0][4];
	state[5] = state[5] ^ round_key[0][5];
	state[6] = state[6] ^ round_key[0][6];
	state[7] = state[7] ^ round_key[0][7];
	
	// get result
	ans[0] = state[0];
	ans[1] = state[1];
	ans[2] = state[2];
	ans[3] = state[3];
	ans[4] = state[4];
	ans[5] = state[5];
	ans[6] = state[6];
	ans[7] = state[7];
}

#include <stdio.h>

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
