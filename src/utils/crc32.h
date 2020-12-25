/*
 * crc32.h
 *
 *  Created on: 2019-12-13
 *      Author: andy
 */

#ifndef CRC32_H_
#define CRC32_H_


void crc32_init(uint32_t poly);
uint32_t crc32(uint32_t crc, void* input, int len);

#endif /* CRC32_H_ */
