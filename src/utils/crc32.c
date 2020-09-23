/*
 * crc32.c
 *
 *  Created on: 2019-12-13
 *      Author: andy
 */


#include <stdio.h>
#include <stdint.h>

static uint32_t table[256];

//位逆转
static uint32_t bitrev(uint32_t input, int bw)
{
	int i;
	uint32_t var;
	var = 0;
	for (i = 0; i < bw; i++)
	{
		if (input & 0x01)
		{
			var |= 1 << (bw - 1 - i);
		}
		input >>= 1;
	}
	return var;
}

//码表生成
//如:X32+X26+...X1+1,poly=(1<<26)|...|(1<<1)|(1<<0)
void crc32_init(uint32_t poly)
{
	int i;
	int j;
	uint32_t c;

	poly = bitrev(poly, 32);
	for (i = 0; i < 256; i++)
	{
		c = i;
		for (j = 0; j < 8; j++)
		{
			if (c & 1)
			{
				c = poly ^ (c >> 1);
			}
			else
			{
				c = c >> 1;
			}
		}
		table[i] = c;
	}
}

uint32_t crc32(uint32_t crc, void* input, int len)
{
	int i;
	uint8_t index;
	uint8_t* pch;
	pch = (uint8_t*)input;
	for (i = 0; i < len; i++)
	{
		index = (uint8_t)(crc^*pch);
		crc = (crc >> 8) ^ table[index];
		pch++;
	}
	return crc ^ 0xFFFFFFFF;
}
