#include <stdlib.h>
#include <stdio.h>

/*
Functions:
    Byte Substitution
    Shift Rows (and inverse)
        -col 0, no shift
        -col 1, 1 shift (left)
        -col 2, 2 shift (left)
        -col 3, 3 shift (left)

    Mix Columns
    Key Addition?

Lookup Table:
    S-Box
    Inverse S-Box
*/

//AES S-Box
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

//AES Inverse S-Box
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


void shiftSubRows(unsigned char * state) {
    /*
        Shifts the rows of the state matrix
        Row 0: No shift
        Row 1: 1 shift (left)
        Row 2: 2 shift (left)
        Row 3: 3 shift (left)
    */
    unsigned char temp[16];
    int i;

    // Copy state into temp
    for (i = 0; i < 16; i++) {
        temp[i] = state[i];
    }

    // Shift subrows
    state[4] = temp[5];
    state[5] = temp[6];
    state[6] = temp[7];
    state[7] = temp[4];

    state[8] = temp[10];
    state[9] = temp[11];
    state[10] = temp[8];
    state[11] = temp[9];

    state[12] = temp[15];
    state[13] = temp[12];
    state[14] = temp[13];
    state[15] = temp[14];
}

void inverse_shiftSubRows(unsigned char * state) {
    /*
        Shifts the rows of the state matrix
        Row 0: No shift
        Row 1: 1 shift (right)
        Row 2: 2 shift (right)
        Row 3: 3 shift (right)
    */
    unsigned char temp[16];
    int i;

    // Copy state into temp
    for (i = 0; i < 16; i++) {
        temp[i] = state[i];
    }

    // Shift subrows
    state[4] = temp[7];
    state[5] = temp[4];
    state[6] = temp[5];
    state[7] = temp[6];

    state[8] = temp[10];
    state[9] = temp[11];
    state[10] = temp[8];
    state[11] = temp[9];

    state[12] = temp[13];
    state[13] = temp[14];
    state[14] = temp[15];
    state[15] = temp[12];
}

void subBytes(unsigned char * state) {
    /*
        Substitutes each byte of the state matrix with the corresponding byte in the S-Box
    */
    int i;
    for (i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

void inverse_subBytes(unsigned char * state) {
    /*
        Substitutes each byte of the state matrix with the corresponding byte in the inverse S-Box
    */
    int i;
    for (i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

unsigned char g(unsigned char a) {
    /*
        Keeps number within Galois Field
    */
    unsigned char hi_bit_set = (a & 0x80);

    // if the high bit is set, xor with 0x1b
    if (hi_bit_set == 0x80) {
        a = a ^ 0x1b;
    }

    return a;
}

void mixColumns(unsigned char * state) {
    unsigned char * temp = malloc(16);
    int i;
    int a, b, c, d;

    // addition in GF(2^8) is just XOR
    // multiplication in GF(2^8)
    // if 2^8 is high bit is set, xor with 0x1b and shift left
    // i applied this using the function g() on any multiplication

    // * 2 == << 1
    // * 3 == << 1 ^ original

    for (i = 0; i < 4; i++) {

        // Column Indexes
        a = i;
        b = i+4;
        c = i+8;
        d = i+12;

        // ~ = 2, 3, 1, 1
        temp[a] = (unsigned char) (
            g(state[a] << 1)
            ^
            (g(state[b] << 1) ^ state[b])
            ^
            (state[c])
            ^ 
            (state[d])
        );
        // ~ = 1, 2, 3, 1
        temp[b] = (unsigned char) (
            (state[a])
            ^
            g(state[b] << 1)
            ^
            (g(state[c] << 1) ^ state[c])
            ^
            (state[d])
        );
        // ~ = 1, 1, 2, 3
        temp[c] = (unsigned char) (
            (state[a])
            ^
            (state[b])
            ^
            g(state[c] << 1)
            ^
            (g(state[d] << 1) ^ state[d])
        );
        // ~ = 3, 1, 1, 2
        temp[d] = (unsigned char) (
            (g(state[a] << 1) ^ state[a])
            ^
            (state[b])
            ^
            (state[c])
            ^
            g(state[d] << 1)
        );
    }

    printf("\n");

    for (i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
    free(temp);
}

void inverse_mixColumns(unsigned char * state) {
    unsigned char * temp = malloc(16);
    int i;
    int j;

    // * 9 == << 3 + original
    // * 11 == << 3 + << 1 + original
    // * 13 == << 3 + << 2 + original
    // * 14 == << 3 + << 2 + << 1 + original

    for (i = 0; i < 4; i++) {
        j = i * 4;
        // ~ = 14, 11, 13, 9
        temp[j] = (unsigned char) (
            // 14 * a0
            ((state[j] << 3) + (state[j] << 2) + (state[j] << 1) + state[j])
            ^
            // 11 * a1
            ((state[j+1] << 3) + (state[j+1] << 1) + state[j+1])
            ^
            // 13 * a2
            ((state[j+2] << 3) + (state[j+2] << 2) + state[j+2])
            ^
            // 9 * a3
            ((state[j+3] << 3) + state[j+3]));
        // ~ = 9, 14, 11, 13
        temp[j+1] = (unsigned char) (
            // 9 * a0
            ((state[j] << 3) + state[j])
            ^
            // 14 * a1
            ((state[j+1] << 3) + (state[j+1] << 2) + (state[j+1] << 1) + state[j+1])
            ^
            // 11 * a2
            ((state[j+2] << 3) + (state[j+2] << 1) + state[j+2])
            ^
            // 13 * a3
            ((state[j+3] << 3) + (state[j+3] << 2) + state[j+3]));
        // ~ = 13, 9, 14, 11
        temp[j+2] = (unsigned char) (
            // 13 * a0
            ((state[j] << 3) + (state[j] << 2) + state[j])
            ^
            // 9 * a1
            ((state[j+1] << 3) + state[j+1])
            ^
            // 14 * a2
            ((state[j+2] << 3) + (state[j+2] << 2) + (state[j+2] << 1) + state[j+2])
            ^
            // 11 * a3
            ((state[j+3] << 3) + (state[j+3] << 1) + state[j+3]));
        // ~ = 11, 13, 9, 14
        temp[j+3] = (unsigned char) (
            // 11 * a0
            ((state[j] << 3) + (state[j] << 1) + state[j])
            ^
            // 13 * a1
            ((state[j+1] << 3) + (state[j+1] << 2) + state[j+1])
            ^
            // 9 * a2
            ((state[j+2] << 3) + state[j+2])
            ^
            // 14 * a3
            ((state[j+3] << 3) + (state[j+3] << 2) + (state[j+3] << 1) + state[j+3]));
    }

    for (i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
    free(temp);
}

void printMatrix(unsigned char * state) {
    int i;
    for (i = 0; i < 16; i++) {
        printf("%02x ", state[i]);
        if (i % 4 == 3) {
            printf("\n");
        }
    }
}

void printBinary(unsigned char n) {
    int i;
    for (i = 7; i >= 0; i--) {
        printf("%d", (n >> i) & 1);
    }
    printf("\n");
}

int main() {
    unsigned char a[16] = {
        0x87, 0xF2, 0x4D, 0x97, 
        0x6E, 0x4C, 0x90, 0xEC, 
        0x46, 0xE7, 0x4A, 0xC3, 
        0xA6, 0x8C, 0xD8, 0x95
    };

    printf("Before:\n");
    printMatrix(a);
    printf("\n");

    mixColumns(a);
    //subBytes(a);
    //shiftSubRows(a);

    printf("After:\n");
    printMatrix(a);

    /*
        Expected Output of a:
        47 40 A3 4C
        37 D4 70 9F
        94 E4 3A 42
        ED A5 A6 BC
    */

    //inverse_mixColumns(a);
    //inverse_subBytes(a);
    //inverse_shiftSubRows(a);

    //printf("\nAfter inverse:\n");
    //printMatrix(a);

    /*
    unsigned char d;
    unsigned char e;
    for (int i = 128; i < 256; i++) {
        d = 0x02 * i;
        e = (0x02 * i) ^ 0;
        printf("%d, %02x %02x %02x\n", i, mul2[i], d, e);
    }
    */

    unsigned char e = 0x4C;
    unsigned char f = g(e << 1) ^ e;

    printf("\n%02x %02x\n", e, f);

    printf("f: ");
    printBinary(f);

    return 0;
}