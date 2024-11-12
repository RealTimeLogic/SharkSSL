
/*
The following machine generated code must be used as follows:

   uint8_t buf[64]; // or larger
   getZoneKey(buf);

*/

#if __STDC_VERSION__ < 199901L
#define uint8_t unsigned char
#endif

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wsequence-point"
#endif
#ifdef __ICCARM__
#pragma diag_suppress=Pa079
#endif

static const uint8_t zkASCII[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};


static const uint8_t zKeyData[]={
	101,
	0xB1 /* 01 ix:27 B1 = 68 ^ D9 */,
	0xC1 /* 02 ix:19 XOR mask */,
	0xB1 /* 03 ix:05 B1 = 99 ^ 28 */,
	0x6B /* 04 ix:15 XOR mask */,
	0x82 /* 05 ix:32 82 = 11 ^ 93 */,
	0xE2 /* 06 ix:11 XOR mask */,
	0xD5 /* 07 ix:20 D5 = 1F ^ CA */,
	0x03 /* 08 ix:02 XOR mask */,
	0x19 /* 09 ix:03 19 = 1B ^ 02 */,
	0xAD /* 10 ix:21 XOR mask */,
	0xCF /* 11 ix:21 CF = 62 ^ AD */,
	0x80 /* 12 ix:24 XOR mask */,
	0x41 /* 13 ix:08 41 = 76 ^ 37 */,
	0xFC /* 14 ix:25 XOR mask */,
	0x97 /* 15 ix:17 97 = EF ^ 78 */,
	0xC8 /* 16 ix:10 XOR mask */,
	0x39 /* 17 ix:13 39 = 0A ^ 33 */,
	0x37 /* 18 ix:08 XOR mask */,
	0x2A /* 19 ix:12 2A = E6 ^ CC */,
	0xCC /* 20 ix:16 XOR mask */,
	0xE6 /* 21 ix:30 E6 = 3D ^ DB */,
	0x93 /* 22 ix:32 XOR mask */,
	0x75 /* 23 ix:29 75 = 89 ^ FC */,
	0x34 /* 24 ix:06 XOR mask */,
	0x5B /* 25 ix:01 5B = 25 ^ 7E */,
	0x33 /* 26 ix:13 XOR mask */,
	0xFD /* 27 ix:23 FD = 05 ^ F8 */,
	0xD1 /* 28 ix:18 XOR mask */,
	0x96 /* 29 ix:09 96 = D0 ^ 46 */,
	0xDB /* 30 ix:30 XOR mask */,
	0x60 /* 31 ix:06 60 = 54 ^ 34 */,
	0x13 /* 32 ix:07 XOR mask */,
	0x84 /* 33 ix:24 84 = 04 ^ 80 */,
	0x2F /* 34 ix:26 XOR mask */,
	0x9A /* 35 ix:28 9A = C2 ^ 58 */,
	0xCC /* 36 ix:12 XOR mask */,
	0x8D /* 37 ix:31 8D = 9E ^ 13 */,
	0x08 /* 38 ix:22 XOR mask */,
	0x6A /* 39 ix:04 6A = B8 ^ D2 */,
	0x13 /* 40 ix:31 XOR mask */,
	0x92 /* 41 ix:19 92 = 53 ^ C1 */,
	0x28 /* 42 ix:05 XOR mask */,
	0xC9 /* 43 ix:22 C9 = C1 ^ 08 */,
	0x46 /* 44 ix:09 XOR mask */,
	0x3B /* 45 ix:26 3B = 14 ^ 2F */,
	0xD2 /* 46 ix:04 XOR mask */,
	0xD0 /* 47 ix:07 D0 = C3 ^ 13 */,
	0x58 /* 48 ix:28 XOR mask */,
	0xF4 /* 49 ix:11 F4 = 16 ^ E2 */,
	0x23 /* 50 ix:14 XOR mask */,
	0x36 /* 51 ix:18 36 = E7 ^ D1 */,
	0xF8 /* 52 ix:23 XOR mask */,
	0xA2 /* 53 ix:16 A2 = 6E ^ CC */,
	0xD9 /* 54 ix:27 XOR mask */,
	0x40 /* 55 ix:02 40 = 43 ^ 03 */,
	0xFC /* 56 ix:29 XOR mask */,
	0x8D /* 57 ix:25 8D = 71 ^ FC */,
	0xCA /* 58 ix:20 XOR mask */,
	0x7B /* 59 ix:14 7B = 58 ^ 23 */,
	0x02 /* 60 ix:03 XOR mask */,
	0x64 /* 61 ix:10 64 = AC ^ C8 */,
	0x78 /* 62 ix:17 XOR mask */,
	0x7E /* 63 ix:15 7E = 15 ^ 6B */,
	0x7E /* 64 ix:01 XOR mask */
};

static void getZoneKey(uint8_t buf[64])
{
	buf[32] = zKeyData[15] ^ zKeyData[62]; /* EF = 97 ^ 78 */
	buf[33] = buf[32] << 4;
	buf[32] = zkASCII[buf[32] >>= 4];
	buf[33] = zkASCII[buf[33] >> 4];
	buf[62] = zKeyData[ 5] ^ zKeyData[22]; /* 11 = 82 ^ 93 */
	buf[63] = buf[62] << 4;
	buf[62] = zkASCII[buf[62] >>= 4];
	buf[63] = zkASCII[buf[63] >> 4];
	buf[60] = zKeyData[37] ^ zKeyData[40]; /* 9E = 8D ^ 13 */
	buf[61] = buf[60] << 4;
	buf[60] = zkASCII[buf[60] >>= 4];
	buf[61] = zkASCII[buf[61] >> 4];
	buf[58] = zKeyData[21] ^ zKeyData[30]; /* 3D = E6 ^ DB */
	buf[59] = buf[58] << 4;
	buf[58] = zkASCII[buf[58] >>= 4];
	buf[59] = zkASCII[buf[59] >> 4];
	buf[56] = zKeyData[23] ^ zKeyData[56]; /* 89 = 75 ^ FC */
	buf[57] = buf[56] << 4;
	buf[56] = zkASCII[buf[56] >>= 4];
	buf[57] = zkASCII[buf[57] >> 4];
	buf[ 8] = zKeyData[ 3] ^ zKeyData[42]; /* 99 = B1 ^ 28 */
	buf[ 9] = buf[ 8] << 4;
	buf[ 8] = zkASCII[buf[ 8] >>= 4];
	buf[ 9] = zkASCII[buf[ 9] >> 4];
	buf[24] = zKeyData[17] ^ zKeyData[26]; /* 0A = 39 ^ 33 */
	buf[25] = buf[24] << 4;
	buf[24] = zkASCII[buf[24] >>= 4];
	buf[25] = zkASCII[buf[25] >> 4];
	buf[16] = zKeyData[29] ^ zKeyData[44]; /* D0 = 96 ^ 46 */
	buf[17] = buf[16] << 4;
	buf[16] = zkASCII[buf[16] >>= 4];
	buf[17] = zkASCII[buf[17] >> 4];
	buf[ 0] = zKeyData[25] ^ zKeyData[64]; /* 25 = 5B ^ 7E */
	buf[ 1] = buf[ 0] << 4;
	buf[ 0] = zkASCII[buf[ 0] >>= 4];
	buf[ 1] = zkASCII[buf[ 1] >> 4];
	buf[20] = zKeyData[49] ^ zKeyData[ 6]; /* 16 = F4 ^ E2 */
	buf[21] = buf[20] << 4;
	buf[20] = zkASCII[buf[20] >>= 4];
	buf[21] = zkASCII[buf[21] >> 4];
	buf[28] = zKeyData[63] ^ zKeyData[ 4]; /* 15 = 7E ^ 6B */
	buf[29] = buf[28] << 4;
	buf[28] = zkASCII[buf[28] >>= 4];
	buf[29] = zkASCII[buf[29] >> 4];
	buf[10] = zKeyData[31] ^ zKeyData[24]; /* 54 = 60 ^ 34 */
	buf[11] = buf[10] << 4;
	buf[10] = zkASCII[buf[10] >>= 4];
	buf[11] = zkASCII[buf[11] >> 4];
	buf[54] = zKeyData[35] ^ zKeyData[48]; /* C2 = 9A ^ 58 */
	buf[55] = buf[54] << 4;
	buf[54] = zkASCII[buf[54] >>= 4];
	buf[55] = zkASCII[buf[55] >> 4];
	buf[46] = zKeyData[33] ^ zKeyData[12]; /* 04 = 84 ^ 80 */
	buf[47] = buf[46] << 4;
	buf[46] = zkASCII[buf[46] >>= 4];
	buf[47] = zkASCII[buf[47] >> 4];
	buf[30] = zKeyData[53] ^ zKeyData[20]; /* 6E = A2 ^ CC */
	buf[31] = buf[30] << 4;
	buf[30] = zkASCII[buf[30] >>= 4];
	buf[31] = zkASCII[buf[31] >> 4];
	buf[22] = zKeyData[19] ^ zKeyData[36]; /* E6 = 2A ^ CC */
	buf[23] = buf[22] << 4;
	buf[22] = zkASCII[buf[22] >>= 4];
	buf[23] = zkASCII[buf[23] >> 4];
	buf[52] = zKeyData[ 1] ^ zKeyData[54]; /* 68 = B1 ^ D9 */
	buf[53] = buf[52] << 4;
	buf[52] = zkASCII[buf[52] >>= 4];
	buf[53] = zkASCII[buf[53] >> 4];
	buf[50] = zKeyData[45] ^ zKeyData[34]; /* 14 = 3B ^ 2F */
	buf[51] = buf[50] << 4;
	buf[50] = zkASCII[buf[50] >>= 4];
	buf[51] = zkASCII[buf[51] >> 4];
	buf[48] = zKeyData[57] ^ zKeyData[14]; /* 71 = 8D ^ FC */
	buf[49] = buf[48] << 4;
	buf[48] = zkASCII[buf[48] >>= 4];
	buf[49] = zkASCII[buf[49] >> 4];
	buf[44] = zKeyData[27] ^ zKeyData[52]; /* 05 = FD ^ F8 */
	buf[45] = buf[44] << 4;
	buf[44] = zkASCII[buf[44] >>= 4];
	buf[45] = zkASCII[buf[45] >> 4];
	buf[18] = zKeyData[61] ^ zKeyData[16]; /* AC = 64 ^ C8 */
	buf[19] = buf[18] << 4;
	buf[18] = zkASCII[buf[18] >>= 4];
	buf[19] = zkASCII[buf[19] >> 4];
	buf[26] = zKeyData[59] ^ zKeyData[50]; /* 58 = 7B ^ 23 */
	buf[27] = buf[26] << 4;
	buf[26] = zkASCII[buf[26] >>= 4];
	buf[27] = zkASCII[buf[27] >> 4];
	buf[ 2] = zKeyData[55] ^ zKeyData[ 8]; /* 43 = 40 ^ 03 */
	buf[ 3] = buf[ 2] << 4;
	buf[ 2] = zkASCII[buf[ 2] >>= 4];
	buf[ 3] = zkASCII[buf[ 3] >> 4];
	buf[36] = zKeyData[41] ^ zKeyData[ 2]; /* 53 = 92 ^ C1 */
	buf[37] = buf[36] << 4;
	buf[36] = zkASCII[buf[36] >>= 4];
	buf[37] = zkASCII[buf[37] >> 4];
	buf[42] = zKeyData[43] ^ zKeyData[38]; /* C1 = C9 ^ 08 */
	buf[43] = buf[42] << 4;
	buf[42] = zkASCII[buf[42] >>= 4];
	buf[43] = zkASCII[buf[43] >> 4];
	buf[40] = zKeyData[11] ^ zKeyData[10]; /* 62 = CF ^ AD */
	buf[41] = buf[40] << 4;
	buf[40] = zkASCII[buf[40] >>= 4];
	buf[41] = zkASCII[buf[41] >> 4];
	buf[12] = zKeyData[47] ^ zKeyData[32]; /* C3 = D0 ^ 13 */
	buf[13] = buf[12] << 4;
	buf[12] = zkASCII[buf[12] >>= 4];
	buf[13] = zkASCII[buf[13] >> 4];
	buf[38] = zKeyData[ 7] ^ zKeyData[58]; /* 1F = D5 ^ CA */
	buf[39] = buf[38] << 4;
	buf[38] = zkASCII[buf[38] >>= 4];
	buf[39] = zkASCII[buf[39] >> 4];
	buf[ 4] = zKeyData[ 9] ^ zKeyData[60]; /* 1B = 19 ^ 02 */
	buf[ 5] = buf[ 4] << 4;
	buf[ 4] = zkASCII[buf[ 4] >>= 4];
	buf[ 5] = zkASCII[buf[ 5] >> 4];
	buf[34] = zKeyData[51] ^ zKeyData[28]; /* E7 = 36 ^ D1 */
	buf[35] = buf[34] << 4;
	buf[34] = zkASCII[buf[34] >>= 4];
	buf[35] = zkASCII[buf[35] >> 4];
	buf[ 6] = zKeyData[39] ^ zKeyData[46]; /* B8 = 6A ^ D2 */
	buf[ 7] = buf[ 6] << 4;
	buf[ 6] = zkASCII[buf[ 6] >>= 4];
	buf[ 7] = zkASCII[buf[ 7] >> 4];
	buf[14] = zKeyData[13] ^ zKeyData[18]; /* 76 = 41 ^ 37 */
	buf[15] = buf[14] << 4;
	buf[14] = zkASCII[buf[14] >>= 4];
	buf[15] = zkASCII[buf[15] >> 4];
}
