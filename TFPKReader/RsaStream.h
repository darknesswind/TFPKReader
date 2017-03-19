#pragma once
#include <QFileInfo>
#include <openssl/rsa.h>

class RsaStream
{
public:
	RsaStream(QFile* pFile);
	~RsaStream();

	void read(char* pBuff, uint uSize, uint copySize = -1);
	template <typename T>
	void readTo(T& data)
	{
		read((char*)&data, sizeof(T));
	}
	uint readBigData(char* pBuff, uint uSize); // return readed block count

	void write(const char* pData, uint uSize);
	template <typename T>
	void writeFrom(const T& data)
	{
		write((const char*)&data, sizeof(T));
	}
	uint writeBigData(char* pBuff, uint uSize);

	quint64 pos() const { return m_pFile->pos(); }
private:
	void initRsaKey();

public:
	static const uint s_blockSize = 0x40;
	static const uint s_maxDatSize = s_blockSize / 2;

private:
	QFile* m_pFile;
	RSA* m_pRsa;
};
