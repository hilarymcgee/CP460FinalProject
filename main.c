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

    // Flip diagonally
    for (i = 0; i < 4; i++) {
        state[i] = temp[i * 4];
        state[i + 4] = temp[i * 4 + 1];
        state[i + 8] = temp[i * 4 + 2];
        state[i + 12] = temp[i * 4 + 3];
    }

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

void printMatrix(unsigned char * state) {
    int i;
    for (i = 0; i < 16; i++) {
        printf("%02x ", state[i]);
        if (i % 4 == 3) {
            printf("\n");
        }
    }
}

int main() {
    unsigned char * a = malloc(16);
    
    // set values of a in hex
    a[0]  = 0x00;
    a[1]  = 0x01;
    a[2]  = 0x02;
    a[3]  = 0x03;
    a[4]  = 0x04;
    a[5]  = 0x05;
    a[6]  = 0x06;
    a[7]  = 0x07;
    a[8]  = 0x08;
    a[9]  = 0x09;
    a[10] = 0x0A;
    a[11] = 0x0B;
    a[12] = 0x0C;
    a[13] = 0x0D;
    a[14] = 0x0E;
    a[15] = 0x0F;


    printf("Before:\n");
    printMatrix(a);
    printf("\n");

    shiftSubRows(a);

    printf("After:\n");
    printMatrix(a);

    return 0;
}