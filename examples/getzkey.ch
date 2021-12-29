
/*
The following machine generated code must be used as follows:

   uint8_t buf[64]; // or larger
   getZoneKey(buf);

*/

#if __STDC_VERSION__ < 199901L
#define uint8_t unsigned char
#endif

#pragma GCC diagnostic ignored "-Wsequence-point"

static const uint8_t zkASCII[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};


static const uint8_t zKeyData[]={
	218,
	0x60 /* 01 ix:06 60 = B3 ^ D3 */,
	0xD3 /* 02 ix:06 XOR mask */,
	0x23 /* 03 ix:08 23 = 34 ^ 17 */,
	0x50 /* 04 ix:11 XOR mask */,
	0xC4 /* 05 ix:32 C4 = FC ^ 38 */,
	0x8E /* 06 ix:30 XOR mask */,
	0x3F /* 07 ix:09 3F = 0C ^ 33 */,
	0x85 /* 08 ix:12 XOR mask */,
	0x6B /* 09 ix:20 6B = B8 ^ D3 */,
	0x94 /* 10 ix:19 XOR mask */,
	0x11 /* 11 ix:30 11 = 9F ^ 8E */,
	0xA6 /* 12 ix:22 XOR mask */,
	0xF6 /* 13 ix:29 F6 = FE ^ 08 */,
	0x25 /* 14 ix:24 XOR mask */,
	0x68 /* 15 ix:01 68 = 04 ^ 6C */,
	0x28 /* 16 ix:15 XOR mask */,
	0xAA /* 17 ix:07 AA = 64 ^ CE */,
	0xEA /* 18 ix:14 XOR mask */,
	0x35 /* 19 ix:04 35 = 1B ^ 2E */,
	0x38 /* 20 ix:32 XOR mask */,
	0xEE /* 21 ix:19 EE = 7A ^ 94 */,
	0x21 /* 22 ix:23 XOR mask */,
	0x5E /* 23 ix:12 5E = DB ^ 85 */,
	0x2E /* 24 ix:04 XOR mask */,
	0x30 /* 25 ix:24 30 = 15 ^ 25 */,
	0x90 /* 26 ix:16 XOR mask */,
	0x05 /* 27 ix:03 05 = 86 ^ 83 */,
	0x44 /* 28 ix:18 XOR mask */,
	0xBF /* 29 ix:27 BF = 67 ^ D8 */,
	0x5F /* 30 ix:25 XOR mask */,
	0x8F /* 31 ix:26 8F = AB ^ 24 */,
	0x08 /* 32 ix:29 XOR mask */,
	0x81 /* 33 ix:13 81 = D3 ^ 52 */,
	0x17 /* 34 ix:08 XOR mask */,
	0x8C /* 35 ix:17 8C = 50 ^ DC */,
	0x0D /* 36 ix:10 XOR mask */,
	0x51 /* 37 ix:05 51 = F0 ^ A1 */,
	0xCB /* 38 ix:21 XOR mask */,
	0x0A /* 39 ix:02 0A = 50 ^ 5A */,
	0xCE /* 40 ix:07 XOR mask */,
	0x84 /* 41 ix:11 84 = D4 ^ 50 */,
	0x52 /* 42 ix:13 XOR mask */,
	0xFC /* 43 ix:28 FC = F5 ^ 09 */,
	0x6C /* 44 ix:01 XOR mask */,
	0x36 /* 45 ix:31 36 = 3E ^ 08 */,
	0x83 /* 46 ix:03 XOR mask */,
	0x6E /* 47 ix:21 6E = A5 ^ CB */,
	0x5A /* 48 ix:02 XOR mask */,
	0xB8 /* 49 ix:18 B8 = FC ^ 44 */,
	0x33 /* 50 ix:09 XOR mask */,
	0x48 /* 51 ix:15 48 = 60 ^ 28 */,
	0x09 /* 52 ix:28 XOR mask */,
	0x17 /* 53 ix:25 17 = 48 ^ 5F */,
	0xA1 /* 54 ix:05 XOR mask */,
	0x3E /* 55 ix:10 3E = 33 ^ 0D */,
	0xDC /* 56 ix:17 XOR mask */,
	0x6C /* 57 ix:16 6C = FC ^ 90 */,
	0x08 /* 58 ix:31 XOR mask */,
	0xF5 /* 59 ix:23 F5 = D4 ^ 21 */,
	0xD8 /* 60 ix:27 XOR mask */,
	0xAE /* 61 ix:14 AE = 44 ^ EA */,
	0x24 /* 62 ix:26 XOR mask */,
	0xF6 /* 63 ix:22 F6 = 50 ^ A6 */,
	0xD3 /* 64 ix:20 XOR mask */
};

static void getZoneKey(uint8_t buf[64])
{
	buf[ 2] = zKeyData[39] ^ zKeyData[48]; /* 50 = 0A ^ 5A */
	buf[ 3] = buf[ 2] << 4;
	buf[ 2] = zkASCII[buf[ 2] >>= 4];
	buf[ 3] = zkASCII[buf[ 3] >> 4];
	buf[ 8] = zKeyData[37] ^ zKeyData[54]; /* F0 = 51 ^ A1 */
	buf[ 9] = buf[ 8] << 4;
	buf[ 8] = zkASCII[buf[ 8] >>= 4];
	buf[ 9] = zkASCII[buf[ 9] >> 4];
	buf[62] = zKeyData[ 5] ^ zKeyData[20]; /* FC = C4 ^ 38 */
	buf[63] = buf[62] << 4;
	buf[62] = zkASCII[buf[62] >>= 4];
	buf[63] = zkASCII[buf[63] >> 4];
	buf[56] = zKeyData[13] ^ zKeyData[32]; /* FE = F6 ^ 08 */
	buf[57] = buf[56] << 4;
	buf[56] = zkASCII[buf[56] >>= 4];
	buf[57] = zkASCII[buf[57] >> 4];
	buf[28] = zKeyData[51] ^ zKeyData[16]; /* 60 = 48 ^ 28 */
	buf[29] = buf[28] << 4;
	buf[28] = zkASCII[buf[28] >>= 4];
	buf[29] = zkASCII[buf[29] >> 4];
	buf[10] = zKeyData[ 1] ^ zKeyData[ 2]; /* B3 = 60 ^ D3 */
	buf[11] = buf[10] << 4;
	buf[10] = zkASCII[buf[10] >>= 4];
	buf[11] = zkASCII[buf[11] >> 4];
	buf[40] = zKeyData[47] ^ zKeyData[38]; /* A5 = 6E ^ CB */
	buf[41] = buf[40] << 4;
	buf[40] = zkASCII[buf[40] >>= 4];
	buf[41] = zkASCII[buf[41] >> 4];
	buf[24] = zKeyData[33] ^ zKeyData[42]; /* D3 = 81 ^ 52 */
	buf[25] = buf[24] << 4;
	buf[24] = zkASCII[buf[24] >>= 4];
	buf[25] = zkASCII[buf[25] >> 4];
	buf[ 0] = zKeyData[15] ^ zKeyData[44]; /* 04 = 68 ^ 6C */
	buf[ 1] = buf[ 0] << 4;
	buf[ 0] = zkASCII[buf[ 0] >>= 4];
	buf[ 1] = zkASCII[buf[ 1] >> 4];
	buf[50] = zKeyData[31] ^ zKeyData[62]; /* AB = 8F ^ 24 */
	buf[51] = buf[50] << 4;
	buf[50] = zkASCII[buf[50] >>= 4];
	buf[51] = zkASCII[buf[51] >> 4];
	buf[16] = zKeyData[ 7] ^ zKeyData[50]; /* 0C = 3F ^ 33 */
	buf[17] = buf[16] << 4;
	buf[16] = zkASCII[buf[16] >>= 4];
	buf[17] = zkASCII[buf[17] >> 4];
	buf[42] = zKeyData[63] ^ zKeyData[12]; /* 50 = F6 ^ A6 */
	buf[43] = buf[42] << 4;
	buf[42] = zkASCII[buf[42] >>= 4];
	buf[43] = zkASCII[buf[43] >> 4];
	buf[52] = zKeyData[29] ^ zKeyData[60]; /* 67 = BF ^ D8 */
	buf[53] = buf[52] << 4;
	buf[52] = zkASCII[buf[52] >>= 4];
	buf[53] = zkASCII[buf[53] >> 4];
	buf[58] = zKeyData[11] ^ zKeyData[ 6]; /* 9F = 11 ^ 8E */
	buf[59] = buf[58] << 4;
	buf[58] = zkASCII[buf[58] >>= 4];
	buf[59] = zkASCII[buf[59] >> 4];
	buf[14] = zKeyData[ 3] ^ zKeyData[34]; /* 34 = 23 ^ 17 */
	buf[15] = buf[14] << 4;
	buf[14] = zkASCII[buf[14] >>= 4];
	buf[15] = zkASCII[buf[15] >> 4];
	buf[18] = zKeyData[55] ^ zKeyData[36]; /* 33 = 3E ^ 0D */
	buf[19] = buf[18] << 4;
	buf[18] = zkASCII[buf[18] >>= 4];
	buf[19] = zkASCII[buf[19] >> 4];
	buf[34] = zKeyData[49] ^ zKeyData[28]; /* FC = B8 ^ 44 */
	buf[35] = buf[34] << 4;
	buf[34] = zkASCII[buf[34] >>= 4];
	buf[35] = zkASCII[buf[35] >> 4];
	buf[44] = zKeyData[59] ^ zKeyData[22]; /* D4 = F5 ^ 21 */
	buf[45] = buf[44] << 4;
	buf[44] = zkASCII[buf[44] >>= 4];
	buf[45] = zkASCII[buf[45] >> 4];
	buf[20] = zKeyData[41] ^ zKeyData[ 4]; /* D4 = 84 ^ 50 */
	buf[21] = buf[20] << 4;
	buf[20] = zkASCII[buf[20] >>= 4];
	buf[21] = zkASCII[buf[21] >> 4];
	buf[ 6] = zKeyData[19] ^ zKeyData[24]; /* 1B = 35 ^ 2E */
	buf[ 7] = buf[ 6] << 4;
	buf[ 6] = zkASCII[buf[ 6] >>= 4];
	buf[ 7] = zkASCII[buf[ 7] >> 4];
	buf[60] = zKeyData[45] ^ zKeyData[58]; /* 3E = 36 ^ 08 */
	buf[61] = buf[60] << 4;
	buf[60] = zkASCII[buf[60] >>= 4];
	buf[61] = zkASCII[buf[61] >> 4];
	buf[48] = zKeyData[53] ^ zKeyData[30]; /* 48 = 17 ^ 5F */
	buf[49] = buf[48] << 4;
	buf[48] = zkASCII[buf[48] >>= 4];
	buf[49] = zkASCII[buf[49] >> 4];
	buf[26] = zKeyData[61] ^ zKeyData[18]; /* 44 = AE ^ EA */
	buf[27] = buf[26] << 4;
	buf[26] = zkASCII[buf[26] >>= 4];
	buf[27] = zkASCII[buf[27] >> 4];
	buf[30] = zKeyData[57] ^ zKeyData[26]; /* FC = 6C ^ 90 */
	buf[31] = buf[30] << 4;
	buf[30] = zkASCII[buf[30] >>= 4];
	buf[31] = zkASCII[buf[31] >> 4];
	buf[22] = zKeyData[23] ^ zKeyData[ 8]; /* DB = 5E ^ 85 */
	buf[23] = buf[22] << 4;
	buf[22] = zkASCII[buf[22] >>= 4];
	buf[23] = zkASCII[buf[23] >> 4];
	buf[54] = zKeyData[43] ^ zKeyData[52]; /* F5 = FC ^ 09 */
	buf[55] = buf[54] << 4;
	buf[54] = zkASCII[buf[54] >>= 4];
	buf[55] = zkASCII[buf[55] >> 4];
	buf[32] = zKeyData[35] ^ zKeyData[56]; /* 50 = 8C ^ DC */
	buf[33] = buf[32] << 4;
	buf[32] = zkASCII[buf[32] >>= 4];
	buf[33] = zkASCII[buf[33] >> 4];
	buf[ 4] = zKeyData[27] ^ zKeyData[46]; /* 86 = 05 ^ 83 */
	buf[ 5] = buf[ 4] << 4;
	buf[ 4] = zkASCII[buf[ 4] >>= 4];
	buf[ 5] = zkASCII[buf[ 5] >> 4];
	buf[36] = zKeyData[21] ^ zKeyData[10]; /* 7A = EE ^ 94 */
	buf[37] = buf[36] << 4;
	buf[36] = zkASCII[buf[36] >>= 4];
	buf[37] = zkASCII[buf[37] >> 4];
	buf[38] = zKeyData[ 9] ^ zKeyData[64]; /* B8 = 6B ^ D3 */
	buf[39] = buf[38] << 4;
	buf[38] = zkASCII[buf[38] >>= 4];
	buf[39] = zkASCII[buf[39] >> 4];
	buf[12] = zKeyData[17] ^ zKeyData[40]; /* 64 = AA ^ CE */
	buf[13] = buf[12] << 4;
	buf[12] = zkASCII[buf[12] >>= 4];
	buf[13] = zkASCII[buf[13] >> 4];
	buf[46] = zKeyData[25] ^ zKeyData[14]; /* 15 = 30 ^ 25 */
	buf[47] = buf[46] << 4;
	buf[46] = zkASCII[buf[46] >>= 4];
	buf[47] = zkASCII[buf[47] >> 4];
}
