#include "RsaStream.h"
#include <cassert>
#include <openssl/rsa.h>

#ifdef TH145
#define arrRsaN TH145_RsaN
#define arrRsaD TH135_RsaD
#else
#define arrRsaN TH135_RsaN
#define arrRsaD TH135_RsaD
#endif
// http://bbs.nyasama.com/forum.php?mod=viewthread&tid=47682
const uchar TH145_RsaN[RsaStream::s_blockSize] = {
	0xC6, 0x43, 0xE0, 0x9D, 0x35, 0x5E, 0x98, 0x1D, 0xBE, 0x63, 0x6D, 0x3A, 0x5F, 0x84, 0x0F, 0x49,
	0xB8, 0xE8, 0x53, 0xF5, 0x42, 0x06, 0x37, 0x3B, 0x36, 0x25, 0xCB, 0x65, 0xCE, 0xDD, 0x68, 0x8C,
	0xF7, 0x5D, 0x72, 0x0A, 0xC0, 0x47, 0xBD, 0xFA, 0x3B, 0x10, 0x4C, 0xD2, 0x2C, 0xFE, 0x72, 0x03,
	0x10, 0x4D, 0xD8, 0x85, 0x15, 0x35, 0x55, 0xA3, 0x5A, 0xAF, 0xC3, 0x4A, 0x3B, 0xF3, 0xE2, 0x37
};
const uchar TH135_RsaN[RsaStream::s_blockSize] = {
	0xC7, 0x9A, 0x9E, 0x9B, 0xFB, 0xC2, 0x0C, 0xB0, 0xC3, 0xE7, 0xAE, 0x27, 0x49, 0x67, 0x62, 0x8A,
	0x78, 0xBB, 0xD1, 0x2C, 0xB2, 0x4D, 0xF4, 0x87, 0xC7, 0x09, 0x35, 0xF7, 0x01, 0xF8, 0x2E, 0xE5,
	0x49, 0x3B, 0x83, 0x6B, 0x84, 0x26, 0xAA, 0x42, 0x9A, 0xE1, 0xCC, 0xEE, 0x08, 0xA2, 0x15, 0x1C,
	0x42, 0xE7, 0x48, 0xB1, 0x9C, 0xCE, 0x7A, 0xD9, 0x40, 0x1A, 0x4D, 0xD4, 0x36, 0x37, 0x5C, 0x89
}; // In Big Endian
const uchar TH135_RsaD[RsaStream::s_blockSize] = {
	0x34, 0x78, 0x84, 0xF1, 0x64, 0x41, 0x22, 0xAC, 0xE5, 0x12, 0xE6, 0x49, 0x15, 0x96, 0xC3, 0xE4,
	0xBA, 0xD0, 0x44, 0xB0, 0x87, 0x3E, 0xCE, 0xE5, 0x52, 0x81, 0x2D, 0x5A, 0x7D, 0x7E, 0x0C, 0x75,
	0x6A, 0x96, 0x7C, 0xE7, 0x5F, 0xDF, 0x7A, 0x21, 0x86, 0x40, 0x5B, 0x10, 0x43, 0xFD, 0x47, 0xDA,
	0x7B, 0xA7, 0xA4, 0xAC, 0x89, 0x20, 0xA6, 0x93, 0x91, 0x1C, 0x63, 0x5A, 0x83, 0x8E, 0x08, 0x01
}; // for 279.96 * 8 core hours.
const uint uRsaE = 0x10001;

const unsigned char arrPadding[RsaStream::s_blockSize / 2] = {
	0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00
};

RsaStream::RsaStream(QFile* pFile)
	: m_pFile(pFile)
{
	initRsaKey();
}

RsaStream::~RsaStream()
{
	RSA_free(m_pRsa);
}

void RsaStream::initRsaKey()
{
	BIGNUM *rsaN = BN_new();
	BIGNUM *rsaE = BN_new();
	BIGNUM *rsaD = BN_new();
	BN_bin2bn(arrRsaN, s_blockSize, rsaN);
	BN_set_word(rsaE, uRsaE);
	BN_bin2bn(arrRsaD, s_blockSize, rsaD);

	m_pRsa = RSA_new();
	m_pRsa->n = rsaN;
	m_pRsa->e = rsaE;
	m_pRsa->d = rsaD;
	assert(s_blockSize == RSA_size(m_pRsa));

#ifdef _DEBUG
#ifndef TH145
	char testbuff[s_blockSize];
	char testData[] = "hello world!";
	memcpy(testbuff, arrPadding, s_maxDatSize);
	memcpy(testbuff + s_maxDatSize, testData, sizeof(testData));

	uchar encodeBuff[s_blockSize];
	uchar decodeBuff[s_blockSize];
	RSA_private_encrypt(s_blockSize, (uchar*)testbuff, (uchar*)encodeBuff, m_pRsa, RSA_NO_PADDING);
	RSA_public_decrypt(s_blockSize, (uchar*)encodeBuff, (uchar*)decodeBuff, m_pRsa, RSA_NO_PADDING);
	assert(0 == memcmp(testbuff, decodeBuff, s_blockSize));
#endif
#endif
}

void RsaStream::read(char* pData, uint uSize, uint copySize /*= -1*/)
{
	if (copySize > uSize)
		copySize = uSize;

	memset(pData, 0, copySize);

	assert(uSize <= s_maxDatSize);
	char inbuff[s_blockSize];
	m_pFile->read(inbuff, s_blockSize);

	static char outbuff[s_blockSize];
	int rsaErr = RSA_public_decrypt(s_blockSize, (uchar*)inbuff, (uchar*)outbuff, m_pRsa, RSA_NO_PADDING);
	assert(rsaErr != -1);

#ifdef TH145
	assert(1 == outbuff[1]);
	char* pDat = &outbuff[0] + 2;
	char* pEnd = &outbuff[0] + s_blockSize;
	while (0xFF == (uchar)*pDat)
	{
		++pDat;
		if (pDat >= pEnd)
			break;
	}
	assert(0 == *pDat);
	++pDat;
	assert(pEnd - pDat == uSize);
#else
	bool bCheckPadding = (0 == memcmp(outbuff, arrPadding, sizeof(arrPadding)));
	assert(bCheckPadding);
	if (!bCheckPadding)
		return;
	char* pDat = outbuff + sizeof(arrPadding);
#endif
	memcpy(pData, pDat, copySize);
}

uint RsaStream::readBigData(char* pBuff, uint uSize)
{
	memset(pBuff, 0, uSize);
	uint uReadedSize = 0;
	uint uReadCount = 0;

	while (uReadedSize < uSize)
	{
		uint diff = uSize - uReadedSize;
		uint uSizeToRead = qMin(diff, s_maxDatSize);
		read(pBuff + uReadedSize, s_maxDatSize, uSizeToRead);
		uReadedSize += uSizeToRead;
		++uReadCount;
	}
	return uReadCount;
}

void RsaStream::write(const char* pData, uint uSize)
{
	assert(uSize <= s_maxDatSize);

	static char inbuff[s_blockSize];
	memcpy(inbuff, arrPadding, s_maxDatSize);
	memcpy(inbuff + s_maxDatSize, pData, uSize);

	static char outbuff[s_blockSize];	
	int rsaErr = RSA_private_encrypt(s_blockSize, (uchar*)inbuff, (uchar*)outbuff, m_pRsa, RSA_NO_PADDING);
	assert(rsaErr != -1);

	m_pFile->write(outbuff, s_blockSize);
}

uint RsaStream::writeBigData(char* pBuff, uint uSize)
{
	uint uWritedSize = 0;
	uint uBlockCount = 0;
	while (uWritedSize < uSize)
	{
		uint uSizeToWrite = uSize - uWritedSize;
		if (uSizeToWrite > s_maxDatSize)
			uSizeToWrite = s_maxDatSize;
		write(pBuff + uWritedSize, uSizeToWrite);
		uWritedSize += uSizeToWrite;
		++uBlockCount;
	}
	return uBlockCount;
}
