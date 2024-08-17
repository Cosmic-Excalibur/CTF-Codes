#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))


#ifndef BYTES_PACK_H
#define BYTES_PACK_H

uint32_t chars_to_uint32(char* msg)
{
    int len = strlen(msg);
    len = len > 4 ? 4 : len;
    uint32_t res = 0;
    for(int i=0; i<len; i++) res += (msg[i] & 0xff) << i * 8;
    return res;
}

void uint32_to_chars(char* output, uint32_t num)
{
    for(int i=0; i<4; i++) output[i] = (num >> i * 8) & 0xff;
}

#endif


//https://github.com/0x000000AC/Tiny-Encryption-Algorithm/blob/master/tea32.c

#ifndef AES_H
#define AES_H

void _tea_encipher(uint32_t* v, uint32_t* KEY) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;             // set up
    uint32_t delta=0x9e3779b9;                       // a key schedule constant
    for (i=0; i < 32; i++) {                         // basic cycle start
        sum += delta;
        v0 += ((v1<<4) + KEY[0]) ^ (v1 + sum) ^ ((v1>>5) + KEY[1]);
        v1 += ((v0<<4) + KEY[2]) ^ (v0 + sum) ^ ((v0>>5) + KEY[3]);
    }                                                // end cycle
    v[0]=v0; v[1]=v1;
}

void _tea_decipher(uint32_t* v, uint32_t* KEY) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  // set up
    uint32_t delta=0x9e3779b9;                     // a key schedule constant
    for (i=0; i<32; i++) {                         // basic cycle start
        v1 -= ((v0<<4) + KEY[2]) ^ (v0 + sum) ^ ((v0>>5) + KEY[3]);
        v0 -= ((v1<<4) + KEY[0]) ^ (v1 + sum) ^ ((v1>>5) + KEY[1]);
        sum -= delta;
    }                                              // end cycle
    v[0]=v0; v[1]=v1;
}

void tea_encrypt(char* output, char* pt, char* key)
{
    // len(key) == 4 * 4 == 16
    uint32_t KEY[4] = {0,};
    for(int i=0; i<4; i++)
    {
        char temp[5] = {key[i*4], key[i*4+1], key[i*4+2], key[i*4+3], 0};
        KEY[i] = chars_to_uint32(temp);
    }

    int len = strlen(pt);
    for(int i=0; i<len; i+=8)
    {
        char temp1[5] = {pt[min(i+0,len)], pt[min(i+1,len)], pt[min(i+2,len)], pt[min(i+3,len)], 0};
        char temp2[5] = {pt[min(i+4,len)], pt[min(i+5,len)], pt[min(i+6,len)], pt[min(i+7,len)], 0};
        uint32_t v1 = chars_to_uint32(temp1);
        uint32_t v2 = chars_to_uint32(temp2);
        uint32_t v[2] = {v1, v2};
        _tea_encipher(v, KEY);
        char temp_[9] = {0,};
        uint32_to_chars(temp_+0, v[0]);
        uint32_to_chars(temp_+4, v[1]);
        for(int j=0; j<8; j++) output[i+j] = temp_[j];
    }
}

void tea_decrypt(char* output, char* ct, char* key)
{
    // len(key) == 4 * 4 == 16
    uint32_t KEY[4] = {0,};
    for(int i=0; i<4; i++)
    {
        char temp[5] = {key[i*4], key[i*4+1], key[i*4+2], key[i*4+3], 0};
        KEY[i] = chars_to_uint32(temp);
    }

    int len = strlen(ct);
    for(int i=0; i<len; i+=8)
    {
        char temp1[5] = {ct[min(i+0,len)], ct[min(i+1,len)], ct[min(i+2,len)], ct[min(i+3,len)], 0};
        char temp2[5] = {ct[min(i+4,len)], ct[min(i+5,len)], ct[min(i+6,len)], ct[min(i+7,len)], 0};
        uint32_t v1 = chars_to_uint32(temp1);
        uint32_t v2 = chars_to_uint32(temp2);
        uint32_t v[2] = {v1, v2};
        _tea_decipher(v, KEY);
        char temp_[9] = {0,};
        uint32_to_chars(temp_+0, v[0]);
        uint32_to_chars(temp_+4, v[1]);
        for(int j=0; j<8; j++) output[i+j] = temp_[j];
    }
}


#endif
