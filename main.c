#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

unsigned char inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

void printMatrix(unsigned char * block) {
    int i;
    for (i = 0; i < 16; i++) {
        printf("%02x ", block[i]);
        if (i % 4 == 3) {
            printf("\n");
        }
    }
}

void printBinaryAsText(unsigned char * block) {
    int i;
    for (i = 0; i < 16; i++) {
        printf("%c", block[i]);
    }
    printf("\n\n");
}

void printBinaryAsHex(unsigned char * block) {
    int i;
    for (i = 0; i < 16; i++) {
        printf("%02x", block[i]);
    }
    printf("\n\n");
}

void printBinary(unsigned char n, int size) {
    int i;
    for (i = size-1; i >= 0; i--) {
        printf("%d", (n >> i) & 1);
    }
    printf("\n");
}

void printHexChunks(unsigned char * block) {
    int i;
    for (i = 0; i < 16; i++) {
        printf("%02x ", block[i]);
        if (i % 4 == 3) {
            printf("\n");
        }
    }
    printf("\n");
}

void shiftSubRows(unsigned char * block) {
    /*
        Shifts the subrows of the current block
        Row 0: No shift
        Row 1: 1 shift (left)
        Row 2: 2 shift (left)
        Row 3: 3 shift (left)
    */
    unsigned char temp[16];
    int i;

    // Copy block into temp
    for (i = 0; i < 16; i++) {
        temp[i] = block[i];
    }

    // Shift subrows of temp into block
    block[4] = temp[5];
    block[5] = temp[6];
    block[6] = temp[7];
    block[7] = temp[4];

    block[8] = temp[10];
    block[9] = temp[11];
    block[10] = temp[8];
    block[11] = temp[9];

    block[12] = temp[15];
    block[13] = temp[12];
    block[14] = temp[13];
    block[15] = temp[14];
}

void inverse_shiftSubRows(unsigned char * block) {
    /*
        Shifts the subrows of the current block
        Row 0: No shift
        Row 1: 1 shift (right)
        Row 2: 2 shift (right)
        Row 3: 3 shift (right)
    */
    unsigned char temp[16];
    int i;

    // Copy block into temp
    for (i = 0; i < 16; i++) {
        temp[i] = block[i];
    }

    // Shift subrows
    block[4] = temp[7];
    block[5] = temp[4];
    block[6] = temp[5];
    block[7] = temp[6];

    block[8] = temp[10];
    block[9] = temp[11];
    block[10] = temp[8];
    block[11] = temp[9];

    block[12] = temp[13];
    block[13] = temp[14];
    block[14] = temp[15];
    block[15] = temp[12];
}

void subBytes(unsigned char * block) {
    /*
        Substitutes each byte of the current block with
        the corresponding byte in the S-Box
    */
    int i;
    for (i = 0; i < 16; i++) {
        block[i] = sbox[block[i]];
    }
}

void inverse_subBytes(unsigned char * block) {
    /*
        Substitutes each byte of the current block with 
        the corresponding byte in the inverse S-Box
    */
    int i;
    for (i = 0; i < 16; i++) {
        block[i] = inv_sbox[block[i]];
    }
}

unsigned char g(unsigned char a) {
    /*
        Keeps number within Galois Field and applies a left shift to the number
    */

    // if the high bit (2^7) is set, xor with 0x1b to keep within GF
    if ((a & 0x80) == 0x80) {
        a = a ^ 0x1b;
    }

    // Apply left shift
    a = a << 1;

    return a;
}

void mixColumns(unsigned char * block) {
    unsigned char * new_block = malloc(16);
    int i, a, b, c, d;

    // Matrix Multiplication in GF(2^8)
    // 2 3 1 1
    // 1 2 3 1
    // 1 1 2 3
    // 3 1 1 2

    // * 1 == original
    // * 2 == << 1
    // * 3 == << 1 ^ original

    for (i = 0; i < 4; i++) {
        a = i;
        b = i + 4;
        c = i + 8;
        d = i + 12;

        // ~ = 2, 3, 1, 1
        new_block[a] = (unsigned char) (
            g(block[a])
            ^
            (g(block[b]) ^ block[b])
            ^
            (block[c])
            ^ 
            (block[d])
        );
        // ~ = 1, 2, 3, 1
        new_block[b] = (unsigned char) (
            (block[a])
            ^
            g(block[b])
            ^
            (g(block[c]) ^ block[c])
            ^
            (block[d])
        );
        // ~ = 1, 1, 2, 3
        new_block[c] = (unsigned char) (
            (block[a])
            ^
            (block[b])
            ^
            g(block[c])
            ^
            (g(block[d]) ^ block[d])
        );
        // ~ = 3, 1, 1, 2
        new_block[d] = (unsigned char) (
            (g(block[a]) ^ block[a])
            ^
            (block[b])
            ^
            (block[c])
            ^
            g(block[d])
        );
    }

    // replace block with new_block
    for (i = 0; i < 16; i++) {
        block[i] = new_block[i];
    }

    //Cleanup
    free(new_block);
}

void inverse_mixColumns(unsigned char * block) {
    unsigned char * new_block = malloc(16);
    int i, a, b, c, d;

    // Matrix Multiplication in GF(2^8)
    // 14 11 13 09
    // 09 14 11 13
    // 13 09 14 11
    // 11 13 09 14

    // Reference on how to multiply using shifts and XOR
    // * 9 == << 3 + original
    // * 11 == << 3 + << 1 + original
    // * 13 == << 3 + << 2 + original
    // * 14 == << 3 + << 2 + << 1

    for (i = 0; i < 4; i++) {
        a = i;
        b = i + 4;
        c = i + 8;
        d = i + 12;

        // ~ = 14, 11, 13, 9
        new_block[a] = (unsigned char) (
            (g(g(g(block[a]))) ^ g(g(block[a])) ^ g(block[a]))
            ^
            (g(g(g(block[b]))) ^ g(block[b]) ^ block[b])
            ^
            (g(g(g(block[c]))) ^ g(g(block[c])) ^ block[c])
            ^
            (g(g(g(block[d]))) ^ block[d])
        );
        // ~ = 9, 14, 11, 13
        new_block[b] = (unsigned char) (
            (g(g(g(block[a]))) ^ block[a])
            ^
            (g(g(g(block[b]))) ^ g(g(block[b])) ^ g(block[b]))
            ^
            (g(g(g(block[c]))) ^ g(block[c]) ^ block[c])
            ^
            (g(g(g(block[d]))) ^ g(g(block[d])) ^ block[d])
        );
        // ~ = 13, 9, 14, 11
        new_block[c] = (unsigned char) (
            (g(g(g(block[a]))) ^ g(g(block[a])) ^ block[a])
            ^
            (g(g(g(block[b]))) ^ block[b])
            ^
            (g(g(g(block[c]))) ^ g(g(block[c])) ^ g(block[c]))
            ^
            (g(g(g(block[d]))) ^ g(block[d]) ^ block[d])
        );
        // ~ = 11, 13, 9, 14
        new_block[d] = (unsigned char) (
            (g(g(g(block[a]))) ^ g(block[a]) ^ block[a])
            ^
            (g(g(g(block[b]))) ^ g(g(block[b])) ^ block[b])
            ^
            (g(g(g(block[c]))) ^ block[c])
            ^
            (g(g(g(block[d]))) ^ g(g(block[d])) ^ g(block[d]))
        );
    }

    // replace current block with updated block
    for (i = 0; i < 16; i++) {
        block[i] = new_block[i];
    }

    //Cleanup
    free(new_block);
}

void KeyExpansionHeart(unsigned char * block) {
    //Rotate left:
    unsigned char temp = block[0];
    block[0] = block[1];
    block[1] = block[2];
    block[2] = block[3];
    block[4] = temp;

    // S-box four bytes:
    block[0] = sbox[block[0]];
    block[1] = sbox[block[1]];
    block[2] = sbox[block[2]];
    block[3] = sbox[block[3]];
};

unsigned char rcon(unsigned char in) {
    unsigned char c = 1;
    if(in == 0) {
        return 0;
    }

    while(in != 1) {
        unsigned char b;
        b = c & 0x80;
        c <<= 1;

        if(b == 0x80) {
            c ^= 0x1b;
        }

        in--;
    }

    return c;
}

void KeyExpansion(unsigned char * key, unsigned char * expandKey) {
    //the first 16 bytes are the original key:
    for (int i = 0; i < 16; i++) {
        expandKey[i] = key[i];
    }

    int bytesGenerated = 16; //generate 16 bytes so far
    int i = 1; //iteration begins at 1
    unsigned char temp[4]; //temp storage

    while (bytesGenerated < 176) {
        //Read 4 bytes for the "temp" storage
        for (int j = 0; j < 4; j++) {
            temp[j] = expandKey[bytesGenerated - 4 + j];
        }

        //Perform the core once for each 16 byte key
        if (bytesGenerated % 16 == 0) {
            KeyExpansionHeart(temp);
            temp[0] = temp[0] ^ rcon(i);
            i++;
        }

        //XOR temp with [bytesGenerated-16], and store in expandKey
        for (int j = 0; j < 4; j++) {
            expandKey[bytesGenerated] = expandKey[bytesGenerated - 16] ^ temp[j];
            bytesGenerated++;
        }
    }
}

void addRoundKey(unsigned char * block, unsigned char * roundKey) {
    int i;
    for (i = 0; i < 16; i++) {
        block[i] ^= roundKey[i];
    }
}

void AES_Single_Block_Encrypt(unsigned char * message, unsigned char * key) {
    unsigned char * block = malloc(16);
    unsigned char * expandKey = malloc(176);
    int i;

    KeyExpansion(key, expandKey);

    for (i = 0; i < 16; i++) {
        block[i] = message[i];
    }

    addRoundKey(block, key);

    for (i = 0; i < 9; i++) {
        subBytes(block);
        shiftSubRows(block);
        mixColumns(block);
        addRoundKey(block, expandKey + (16 * (i + 1)));
    }

    subBytes(block);
    shiftSubRows(block);
    addRoundKey(block, expandKey + 160);

    // Copy the block back to the message
    for (i = 0; i < 16; i++) {
        message[i] = block[i];
    }

    // Cleanup
    free(block);
    free(expandKey);
}

void AES_Single_Block_Decrypt(unsigned char * message, unsigned char * key) {
    unsigned char * block = malloc(16);
    unsigned char * expandKey = malloc(176);
    int i;

    KeyExpansion(key, expandKey);

    for (i = 0; i < 16; i++) {
        block[i] = message[i];
    }

    addRoundKey(block, expandKey + 160);

    for (i = 8; i >= 0; i--) {
        inverse_shiftSubRows(block);
        inverse_subBytes(block);
        addRoundKey(block, expandKey + (16 * (i + 1)));
        inverse_mixColumns(block);
    }

    inverse_shiftSubRows(block);
    inverse_subBytes(block);
    addRoundKey(block, key);

    for (i = 0; i < 16; i++) {
        message[i] = block[i];
    }

    free(block);
    free(expandKey);
}

void AES_MultiBlock_Encrypt_ECB(unsigned char * message, int blocks, unsigned char * key) {
    int i;
    for (i = 0; i < blocks; i++) {
        AES_Single_Block_Encrypt(message + (i * 16), key);
    }
}

void AES_MultiBlock_Decrypt_ECB(unsigned char * message, int blocks, unsigned char * key) {
    int i;
    for (i = 0; i < blocks; i++) {
        AES_Single_Block_Decrypt(message + (i * 16), key);
    }
}

void AES_MultiBlock_Encrypt_CBC(unsigned char * message, int blocks, unsigned char * key, unsigned char * iv) {
    int i;
    unsigned char * temp = malloc(16); // temp acts as current block and previous block

    // first block is special
    for (i = 0; i < 16; i++) {
        temp[i] = message[i] ^ iv[i];
    }
    // encrypt current block
    AES_Single_Block_Encrypt(temp, key);
    // copy encrypted block to message
    memcpy(message, temp, 16);

    for (i = 1; i < blocks; i++) {
        // xor temp (previous block) with next block
        for (int j = 0; j < 16; j++) {
            temp[j] = message[(i * 16) + j] ^ temp[j];
        }

        //Encrypt
        AES_Single_Block_Encrypt(temp, key);

        //Copy current block back to message
        memcpy(message + (i * 16), temp, 16);
    }
    free(temp);
}

void AES_MultiBlock_Decrypt_CBC(unsigned char * message, int blocks, unsigned char * key, unsigned char * iv) {
    int i;
    unsigned char * temp = malloc(16);
    unsigned char * prev_block = malloc(16);

    // -- first block is special -- //
    // copy first block to prev_block
    memcpy(prev_block, message, 16);
    // copy current block to temp
    memcpy(temp, message, 16);
    // decrypt
    AES_Single_Block_Decrypt(temp, key);
    // xor with iv
    for (i = 0; i < 16; i++) {
        temp[i] ^= iv[i];
    }
    // copy decrypted block back to message
    memcpy(message, temp, 16);

    // the rest of the blocks
    for (i = 1; i < blocks; i++) {
        // copy current block to temp
        memcpy(temp, message + (i * 16), 16);

        //Decrypt
        AES_Single_Block_Decrypt(temp, key);

        // xor temp with previous block
        int j;
        for (j = 0; j < 16; j++) {
            temp[j] ^= prev_block[j];
        }

        //update prev_block to current block
        memcpy(prev_block, message + (i * 16), 16);

        //Copy current block (temp) back to message
        memcpy(message + (i * 16), temp, 16);
    }
    free(temp);
}

void test_AES_oneblock() {
    /*
        Test AES encryption and decryption
    */

    int i;
    int message_len = 16;
    unsigned char key[16] = "123456789abcdef";
    unsigned char message[16] = "pink_fluffy78453";

    printf(" Original message: ");
    for (i = 0; i < message_len; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");

    AES_Single_Block_Encrypt(message, key);

    printf("Encrypted message: ");
    for (i = 0; i < message_len; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");

    AES_Single_Block_Decrypt(message, key);

    printf("Decrypted message: ");
    for (i = 0; i < message_len; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");
}

void test_AES_multiblock_ECB() {
    /*
        Test AES encryption and decryption
    */

    int i;
    int message_len = 64; // 4 blocks
    int chunk_size = 16;
    int blocks = message_len / chunk_size;
    unsigned char key[16] = "123456789abcdefg";
    unsigned char message[64] = "123456789123456 123456789123456 123456789123456 123456789123456 ";

    printf("Key: ");
    for (i = 0; i < 16; i++) {
        printf("%c", key[i]);
    }
    printf("\n");

    printf("Original message  (TXT): ");
    for (i = 0; i < message_len; i++) {
        printf("%c", message[i]);
    }
    printf("\n");

    printf("Original message  (HEX): ");
    for (i = 0; i < message_len; i++) {
        printf("%02x", message[i]);
        if ((i + 1) % 16 == 0) {
            printf(" ");
        }
    }
    printf("\n");

    AES_MultiBlock_Encrypt_ECB(message, blocks, key);

    printf("Encrypted message (HEX): ");
    for (i = 0; i < message_len; i++) {
        printf("%02x", message[i]);
        if ((i + 1) % 16 == 0) {
            printf(" ");
        }
    }
    printf("\n");

    AES_MultiBlock_Decrypt_ECB(message, blocks, key);

    printf("Decrypted message (HEX): ");
    for (i = 0; i < message_len; i++) {
        printf("%02x", message[i]);
        if ((i + 1) % 16 == 0) {
            printf(" ");
        }
    }
    printf("\n");
}

void test_AES_multiblock_CBC() {
    /*
        Test AES encryption and decryption
    */

    int i;
    int message_len = 64; // 4 blocks
    int chunk_size = 16;
    int blocks = message_len / chunk_size;
    unsigned char key[16] = "123456789abcdefg";
    unsigned char message[64] = "123456789123456 123456789123456 123456789123456 123456789123456 ";
    unsigned char iv[16] = "23456789abcdefg1";

    printf("Key: ");
    for (i = 0; i < 16; i++) {
        printf("%c", key[i]);
    }
    printf("\n");

    printf("Original message  (TXT): ");
    for (i = 0; i < message_len; i++) {
        printf("%c", message[i]);
    }
    printf("\n");

    printf("Original message  (HEX): ");
    for (i = 0; i < message_len; i++) {
        printf("%02x", message[i]);
        if ((i + 1) % 16 == 0) {
            printf(" ");
        }
    }
    printf("\n");

    AES_MultiBlock_Encrypt_CBC(message, blocks, key, iv);

    printf("Encrypted message (HEX): ");
    for (i = 0; i < message_len; i++) {
        printf("%02x", message[i]);
        if ((i + 1) % 16 == 0) {
            printf(" ");
        }
    }
    printf("\n");

    AES_MultiBlock_Decrypt_CBC(message, blocks, key, iv);

    printf("Decrypted message (HEX): ");
    for (i = 0; i < message_len; i++) {
        printf("%02x", message[i]);
        if ((i + 1) % 16 == 0) {
            printf(" ");
        }
    }
    printf("\n");
}

void test_AES_multiblock_CBC_Bee_Movie() {
    int i;

    // Read in data from file into unsigned char
    FILE *fp;
    fp = fopen("bee_movie_script.txt", "r");
    if (fp == NULL) {
        printf("Error opening file");
        return;
    }

    // determine length of file
    fseek(fp, 0L, SEEK_END);
    int text_sz = ftell(fp);
    // seek back to beginning of file
    fseek(fp, 0L, SEEK_SET);

    // make size a multiple of 128 bits (16 bytes) (not chopping off any data)
    int sz = text_sz + (text_sz % 16);

    unsigned char *data = malloc(sz);
    fread(data, sz, 1, fp);
    fclose(fp);

    // print sz
    printf("File Size: %d bits\n", text_sz);
    
    if (text_sz % 16 != 0) {
        printf("Warning: File size is not a multiple of 128 bits. Data will be padded with %d 0s.\n", (text_sz % 16));
    }

    // 128-bit key
    unsigned char key[16] = "123456789abcdefg";
    unsigned char iv[16] = "23456789abcdefg1";

    //print the before encryption string
    printf("Before encryption: \n");
    for (i = 0; i < text_sz / 128; i++) { // limit text printed in console (/ 32)
        printf("%02x", data[i]);
    }
    printf("\n");
    for (i = 0; i < text_sz / 128; i++) { // limit text printed in console (/ 32)
        printf("%c", data[i]);
    }
    printf("\n\n");


    clock_t begin_encryption = clock();

    // encrypt
    AES_MultiBlock_Encrypt_CBC(data, sz, key, iv);

    clock_t end_encryption = clock();
    double time_encryption = (double)(end_encryption - begin_encryption) / CLOCKS_PER_SEC; 

    // Write encrypted data to file
    FILE *fp_encrypted;
    fp_encrypted = fopen("bee_movie_script_encrypted.txt", "w");
    if (fp_encrypted == NULL) {
        printf("Error opening file");
        return;
    }
    fwrite(data, sz, 1, fp_encrypted);
    fclose(fp_encrypted);

    //print the after encryption string
    printf("After encryption: \n");
    for (i = 0; i < sz / 128; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
    for (i = 0; i < text_sz / 128; i++) { // limit text printed in console (/ 32)
        printf("%c", data[i]);
    }
    printf("\n\n");

    clock_t begin_decryption = clock();

    // decrypt
    AES_MultiBlock_Decrypt_CBC(data, sz, key, iv);

    clock_t end_decryption = clock();
    double time_decryption = (double)(end_decryption - begin_decryption) / CLOCKS_PER_SEC;

    // Write decrypted data to file
    FILE *fp_decrypted;
    fp_decrypted = fopen("bee_movie_script_decrypted.txt", "w");
    if (fp_decrypted == NULL) {
        printf("Error opening file");
        return;
    }
    fwrite(data, sz, 1, fp_decrypted);
    fclose(fp_decrypted);

    //print the after encryption string
    printf("After decryption: \n");
    for (i = 0; i < text_sz / 128; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
    for (i = 0; i < text_sz / 128; i++) { // limit text printed in console (/ 32)
        printf("%c", data[i]);
    }
    printf("\n\n");

    printf("Encryption time: %f seconds\n", time_encryption);
    printf("Decryption time: %f seconds\n\n", time_decryption);

    // free memory
    free(data);
}

int main() {
    printf("Testing ECB\n");
    test_AES_multiblock_ECB();

    // Pause
    getchar();

    printf("Testing CBC\n");
    test_AES_multiblock_CBC();

    // Pause
    getchar();
    
    printf("Testing CBC with Bee Movie Script from txt file\n");
    test_AES_multiblock_CBC_Bee_Movie();
    return 0;
}