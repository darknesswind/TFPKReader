#include "TFPKReader.h"
#include <cassert>
#include <openssl/rsa.h>
#include <QtZlib/zlib.h>
#include <QTextCodec>
#include <QSet>
#include <QTextStream>
#include <QDir>
#include <QDebug>
#include <map>
#include <random>
#include <QDataStream>
#include <fstream>
#include <sstream>
#include "NutScript.h"
#include <QJsonDocument>
#include "RsaStream.h"
#include <iostream>
#if __GUI_SUPPORT__
#include <QImage>
#include <QMessageBox>
#else
namespace QMessageBox
{
	void warning(void*, const QString& title, const QString& msg)
	{
		qDebug() << title << ": " << msg << endl;
	}
	void information(void*, const QString& title, const QString& msg)
	{
		qDebug() << title << ": " << msg << endl;
	}
}
#endif

QTextCodec* g_jpCodec = QTextCodec::codecForName("Shift-JIS");
QTextCodec* g_cnCodec = QTextCodec::codecForName("GBK");

template <class Function>
static void ForeachFile(const QFileInfo& fileInfo, Function func)
{
	if (fileInfo.isDir())
	{
		QString sPath = fileInfo.filePath();
		QDir curDir(sPath);
		QFileInfoList infos = curDir.entryInfoList(QDir::AllEntries | QDir::NoDotAndDotDot);
		for (int i = 0; i < infos.size(); ++i)
			ForeachFile(infos[i], func);
	}
	else if (fileInfo.isFile())
	{
		func(fileInfo);
	}
}

TFPKReader::TFPKReader(QTextCodec* pSrcCodec, QTextCodec* pDstCodec)
	: m_pSrcCodec(pSrcCodec)
	, m_pDstCodec(pDstCodec)
{
	BinaryReader::SetCodec(m_pSrcCodec);
}

void TFPKReader::unpack(const QString& pakFile)
{
	m_resFileInfo.setFile(pakFile);
	m_resFileInfo.makeAbsolute();
	if (!m_resFileInfo.isFile())
	{
		qDebug() << "Invalid File Name.";
		return;
	}

	QFile datFile(m_resFileInfo.filePath());
	if (!datFile.open(QFile::ReadOnly))
	{
		qDebug() << datFile.errorString();
		return;
	}

	const uint uMagicLen = 5;
	char magic[5];
	datFile.read(magic, 5);
	magic[4] = 0;
	if (strcmp("TFPK", magic))	// not tfpk file
	{
		std::cout << "not a tfpk file" << std::endl;
		return;
	}

// 	uint x = FNVHashString("dat/actor/trophy/");
// 	x = FNVHashString("dat/system/trophy/");
// 	x = FNVHashString("dat/trophy/");
	loadDirList();

	RsaStream rsaReader(&datFile);
	readDirList(rsaReader);
	readFileNames(rsaReader);
#ifdef TH145
 	readFileList145(rsaReader);
	readFile145(datFile);
#else
	readFileList(rsaReader);
	readFile(datFile);
#endif

	datFile.close();
	std::cout << "succeed" << std::endl;
}

uint TFPKReader::readDirList(RsaStream& reader)
{
	std::cout << "loading dir " << std::endl;

	uint nDirCount = 0;
	reader.readTo(nDirCount);
	if (nDirCount)
		m_dirList.resize(nDirCount);
	for (uint i = 0; i < nDirCount; ++i)
	{
		reader.readTo((TFPKDir_Base&)m_dirList[i]);
		matchHashPath(m_dirList[i]);
		m_dirList[i].fileList.resize(m_dirList[i].nFileCount);
		std::cout << ".";
	}
	std::cout << std::endl;

	return nDirCount;
}

void TFPKReader::readFileList145(RsaStream& reader)
{
	Data64 arg1, arg2;

	uint nFileCount = 0;
	reader.readTo(nFileCount);
	if (nFileCount)
		m_files145.resize(nFileCount);
	
	uint nFileBeginPos = reader.pos() + 3 * nFileCount * RsaStream::s_blockSize;
	for (uint i = 0; i < nFileCount; ++i)
	{
		FileInfo145& info = m_files145[i];

		reader.readTo(arg1);
		reader.readTo(arg2);
		reader.readTo(info.xorKeys);

		uint xorPart1 = info.xorKeys[0] ^ arg1.lw;
		uint xorPart2 = info.xorKeys[1] ^ arg1.hi;
		uint xorPart3 = info.xorKeys[2] ^ arg2.lw;
		uint xorPart4 = info.xorKeys[3] ^ arg2.hi;

		info.key = xorPart3;
		info.pakId = 0;
		info._key = info.key;
		info.unk1 = xorPart4;
		info.pos = nFileBeginPos + xorPart2;
		info.size = xorPart1;

		std::cout << ".";
	}
}

void TFPKReader::readFile145(QFile& file)
{
	for (auto iter = m_files145.begin(); iter != m_files145.end(); ++iter)
	{
		FileInfo145& info = *iter;

		file.seek(info.pos);
		QByteArray dat = file.read(info.size);
		decodeFile145(info.xorKeys, (uchar*)dat.data(), dat.size());
// 		decodeFile(info.xorKeys, (uchar*)dat.data(), dat.size());

		PAKFileFormat fm = getFileFormat((uchar*)dat.data());
	}
}

#define LOBYTE(w) ((uchar)(((uint)(w)) & 0xff))
#define HIWORD(l) ((ushort)((((uint)(l)) >> 16) & 0xffff))
#define LOWORD(l) ((ushort)(((uint)(l)) & 0xffff))
void TFPKReader::decodeFile145(uint xorkeys[4], uchar* pData, uint decodeSize)
{
	uchar* currentlp = pData;
	uint uk2 = xorkeys[0];

	uint keys[5];
	memcpy(keys, xorkeys, sizeof(xorkeys));
	keys[4] = xorkeys[0];

	uchar* key = (uchar*)&keys;

	if (!strncmp((char*)(currentlp), "TFWA", 4) ||
		!strncmp((char*)(currentlp), "TFBM", 4) ||
		!strncmp((char*)(currentlp), "OggS", 4) ||
		!strncmp((char*)(currentlp + 2), "RI", 2))
	{
		uk2 = *(uint*)currentlp;
		currentlp += 4;
		uk2 >>= 8;
		uk2 += (*currentlp) * 0x1000000;
		*currentlp ^= *(key + 4);
		*currentlp ^= *(currentlp - 4);
		currentlp++;
	}

	if (decodeSize & 1)
	{
		uint tmpKey = uk2 >> 8;
		tmpKey += (*currentlp) * 0x1000000;

		uint current = (currentlp - pData) & 0xf;

		(*(uchar*)currentlp) ^= *(uchar*)(key + current);
		(*(uchar*)currentlp) ^= LOBYTE(uk2);

		uk2 = tmpKey;
		currentlp++;
	}
	else if (decodeSize & 2)
	{
		uint tmpKey = HIWORD(uk2) + LOWORD((*(uint*)currentlp)) * 0x10000;
		uint current = (currentlp - pData) & 0xf;

		(*(ushort*)currentlp) ^= *(ushort*)(key + current);
		(*(ushort*)currentlp) ^= LOWORD(uk2);

		currentlp += 2;
		uk2 = tmpKey;
	}

	if (currentlp < pData + decodeSize)
	{
		do
		{
			uint tmp = *(uint*)currentlp;
			uint keyOffset = (currentlp - pData) & 0xf;
			(*(uint*)currentlp) ^= *(uint*)(key + keyOffset);
			(*(uint*)currentlp) ^= uk2;
			uk2 = tmp;
			currentlp += 4;
		} while (currentlp < pData + decodeSize);
	}
}

void TFPKReader::matchHashPath(TFPKDir& tfpkDir)
{
	tfpkDir.sPath = matchHashPath(tfpkDir.nPathHash);
}

QString& TFPKReader::matchHashPath(uint hash)
{
	if (!m_dirPathLookUp.contains(hash))
		m_dirPathLookUp[hash] = QString("unk_%1/").arg(QString::number(hash, 16)).toUpper();

	return m_dirPathLookUp[hash];
}

void TFPKReader::readFileNames(RsaStream& reader)
{
	std::cout << "loading file names " << std::endl;
	FileNamePakHeader fnHeader;
	reader.readTo(fnHeader);
	QByteArray originData(fnHeader.OrigSize, 0);
	{
		QByteArray compressFN(fnHeader.CompSize, 0);
		uint cnt = reader.readBigData(compressFN.data(), fnHeader.CompSize);
		assert(cnt == fnHeader.BlockCnt);
		z_uLongf outSize = fnHeader.OrigSize;
		uncompress((uchar*)originData.data(), &outSize, (uchar*)compressFN.data(), compressFN.size());
		assert(outSize == fnHeader.OrigSize);
	}

	std::vector<TFPKDir>::iterator iterDir = m_dirList.begin();
	std::vector<TFPKFileInfo*>::iterator iterFile = iterDir->fileList.begin();

	uint fileCount = 0;
	for (int i = 0; i < originData.size(); ++i)
		if ((uchar)originData[i] == 0)
			++fileCount;

	QSet<uint> testSet;
	char* pIter = originData.data();
	char* pEnd = pIter + originData.size();
	while (pIter < pEnd)
	{
		if (iterFile == iterDir->fileList.end())
		{
			++iterDir;
			if (iterDir == m_dirList.end())
				break;
			iterFile = iterDir->fileList.begin();
		}

		uint datSize = strlen(pIter);		
		QString sName = m_pSrcCodec->toUnicode(pIter);
		uint hash = FNVHashString(sName, iterDir->nPathHash);
		std::cout << ".";
// debug begin
		if (testSet.contains(hash))
		{
			TFPKFileInfo& file2 = m_files[hash];
			qDebug() << file2.sName;
		}

 		assert(!testSet.contains(hash));
		testSet.insert(hash);
// debug end

		TFPKFileInfo& file = m_files[hash];
		file.sName = sName;
		file.nNameHash = hash;
		file.nPathHash = iterDir->nPathHash;

		*iterFile = &file;
		pIter += datSize + 1;
		++iterFile;
	}
	std::cout << std::endl;
	assert(fileCount == m_files.size());
}

uint SpecialFNVHash(char *begin, char *end, uint initHash = 0x811C9DC5u)
{
	uint hash = 0; // eax@1
	uint ch = 0; // esi@2

	int inMBCS = 0;
	for (hash = initHash; begin != end; hash = ch ^ 0x1000193 * hash)
	{
		ch = *begin++;
		if (!inMBCS &&
#ifdef TH145
			ch >= 128)
#else
			((unsigned char)ch >= 0x81u && (unsigned char)ch <= 0x9Fu || (unsigned char)ch + 32 <= 0x1Fu))
#endif
			inMBCS = 2;
		if (!inMBCS)
		{
			ch = tolower(ch);  // bad ass style but WORKS PERFECTLY!
			if (ch == '/') ch = '\\';
		}
		else inMBCS--;
	}
	return hash;
}

static QTextCodec* g_pHashCodec = QTextCodec::codecForName("SHIFT-JIS");
uint TFPKReader::FNVHashString(const QString& str, uint initHash /*= 0x811C9DC5u*/)
{	// 0x55fe982f
#ifdef TH145
	QByteArray bytes = g_pHashCodec->fromUnicode(str);
	uint hash = SpecialFNVHash(bytes.data(), bytes.data() + bytes.size(), initHash);
	return hash;
#else
	QByteArray bytes = g_pHashCodec->fromUnicode(str.toLower().replace('/', '\\'));
	const uint addition = 1;
	uint hash = initHash;
	uint i = 0;
	uint ch = 0;
	do
	{
		ch = (uchar)bytes[i];
		hash = (0x1000193 * hash) ^ ch;
		i += addition;
	} while (i < (uint)bytes.size());

	uint thash = SpecialFNVHash(bytes.data(), bytes.data() + bytes.size(), initHash);
	assert(thash == hash);
	return hash;
#endif
}

void TFPKReader::readFileList(RsaStream& reader)
{
	std::cout << "reading file info" << std::endl;
	FileListPakHeader listHeader;
	reader.readTo(listHeader);
	assert(listHeader.uFileCount == m_files.size());

	m_filePosList.resize(listHeader.uFileCount);
	for (uint i = 0; i < listHeader.uFileCount; ++i)
	{
		FilePosInfo& info = m_filePosList[i];

		reader.readTo((FilePosInfo_Base&)info);
		reader.readTo(info.nameHash);
		reader.readTo(info.xorKey);
		std::cout << ".";
	}
	std::cout << std::endl;
}

void TFPKReader::readFile(QFile& file)
{
	static QRegExp regImg(".*\\.(png|bmp)", Qt::CaseInsensitive);
	static QRegExp regCSV(".*\\.(csv)", Qt::CaseInsensitive);

	std::cout << "exporting files" << std::endl;
	quint64 curPos = file.pos();
	for (uint i = 0; i < m_filePosList.size(); ++i)
	{
		FilePosInfo& info = m_filePosList[i];
		TFPKFileInfo& tfFile = m_files[info.nameHash];
		assert(tfFile.nNameHash && tfFile.nPathHash && !tfFile.sName.isEmpty());

		file.seek(curPos + info.Offset);
		tfFile.data = file.read(info.FileSize);
		decodeFile(info.xorKey, (uchar*)tfFile.data.data(), info.FileSize);
		std::cout << ".";

		if (regImg.exactMatch(tfFile.sName))
		{
			extraImage(tfFile);
		}
		else if (regCSV.exactMatch(tfFile.sName))
		{
			extraCSV(tfFile);
		}
		else
		{
			extraOther(tfFile);
		}
	}
	std::cout << std::endl;
}

void TFPKReader::decodeFile(uint key[4], uchar* pData, uint decodeSize)
{
	for (int j = 0; j < decodeSize / 4; j++)
	{
		*((uint*)pData + j) ^= key[j % 4];
	}

	int remain = decodeSize % 4;
	if (remain)
	{
		uint tk = key[decodeSize / 4 % 4];
		for (int j = 0; j < remain; j++)
		{
			pData[decodeSize - remain + j] ^= tk & 0xFF;
			tk >>= 8;
		}
	}
}

void TFPKReader::extraImage(TFPKFileInfo& imgFile)
{
#if __GUI_SUPPORT__
	TFBMFile* bmFile = (TFBMFile*)imgFile.data.data();
	if (strncmp(bmFile->magic, "TFBM", 4))
		return;
	assert(bmFile->width == bmFile->padding_width);	// 不一样的话写盘要注意了

	assert(bmFile->compSize == imgFile.data.size() - sizeof(TFBMFile_Base));
	static QByteArray unzipBuff;

	z_uLongf buffSize = bmFile->bit * bmFile->width * bmFile->height;
	unzipBuff.resize(buffSize);
	unzipBuff.fill(0);	

	int res = uncompress((uchar*)unzipBuff.data(), &buffSize, bmFile->variableData, bmFile->compSize);
	assert(Z_OK == res);

	QImage::Format fmt = QImage::Format_ARGB32;
	switch (bmFile->bit)
	{
	case 32: fmt = QImage::Format_ARGB32; break;
	case 24: fmt = QImage::Format_RGB888; break;
	case 16: fmt = QImage::Format_RGB16; break;
	case 8: fmt = QImage::Format_Indexed8; break;
	default:
		assert(!"unknown color bit");
		return;
	}

	QImage img((uchar*)unzipBuff.data(), bmFile->width, bmFile->height, QImage::Format_ARGB32);
	img.save(makeFilePath(imgFile));
#else
	extraOther(imgFile);
#endif
}

void TFPKReader::extraCSV(TFPKFileInfo& csvFile)
{
	TFCSFile* csFile = (TFCSFile*)csvFile.data.data();
	if (strncmp(csFile->magic, "TFCS", 4))
		return;

	assert(csFile->compSize == csvFile.data.size() - sizeof(TFCSFile_Base));
	QByteArray unzipBuff(csFile->origSize, 0);

	z_uLongf buffSize = csFile->origSize;
	int res = uncompress((uchar*)unzipBuff.data(), &buffSize, csFile->variableData, csFile->compSize);
	assert(Z_OK == res);

	CsvStream stream(makeFilePath(csvFile), m_pSrcCodec, m_pDstCodec);
	stream.writeToFile(unzipBuff);
}

void TFPKReader::extraOther(TFPKFileInfo& tfFile)
{
	QFile datFile(makeFilePath(tfFile));
	if (!datFile.open(QFile::WriteOnly))
	{
		qDebug() << datFile.errorString();
		return;
	}

	datFile.write(tfFile.data);
	datFile.close();
}

QString TFPKReader::makeFilePath(const TFPKFileInfo& tfFile)
{
	QString sPath = QString("%1/%2/%3")
		.arg(m_resFileInfo.path())
		.arg(m_resFileInfo.baseName())
		.arg(matchHashPath(tfFile.nPathHash));

	QDir dir(sPath);
	dir.mkpath(sPath);
	return sPath + tfFile.sName;
}

void TFPKReader::loadDirList()
{
	std::cout << "loading dir list" << std::endl;
	QString filePath = QString("%1/dirlist.txt")
		.arg(m_resFileInfo.path());

	QFile file(filePath);
	if (!file.open(QFile::ReadOnly))
	{
		qDebug() << file.errorString();
		return;
	}

	QTextStream stream(&file);
	stream.setCodec("utf-8");
	stream.setGenerateByteOrderMark(true);

	while (!stream.atEnd())
	{
		QString str = stream.readLine();
		uint hash = FNVHashString(str);
		m_dirPathLookUp[hash] = str;
	}	
}

PAKFileFormat TFPKReader::getFileFormat(const uchar* pDat)
{
	uint magic = *(uint*)pDat;
	uint tmp = *(const uint*)(const char*)"TFCS";
	return pak_unk;
}

void TFPKReader::package(const QString& pakPath)
{
	m_resFileInfo.setFile(pakPath);
	m_resFileInfo.makeAbsolute();
	if (!m_resFileInfo.isDir())
	{
		qDebug() << "Invalid Dir Name.";
		return;
	}

	QString sPakFilePath = QString("%1/%2.pak").arg(m_resFileInfo.path()).arg(m_resFileInfo.baseName());
	QFile datFile(sPakFilePath);
	if (!datFile.open(QFile::WriteOnly))
	{
		qDebug() << datFile.errorString();
		return;
	}

	datFile.write("TFPK", 5);

	RsaStream rsaWriter(&datFile);
	prepareDataToWrite();
	writeDirList(rsaWriter);
	writeFileNames(rsaWriter);
	writeFileList(rsaWriter);
	writeFile(datFile);

	datFile.close();
	std::cout << "package ended" << std::endl;
}

void TFPKReader::prepareDataToWrite()
{
	m_dirPathLookUp.clear();
	m_files.clear();
	m_dirList.clear();
	m_filePosList.clear();

	std::map<uint, uint> hashToDir;
	std::cout << "searching files" << std::endl;

	QDir curDir(m_resFileInfo.filePath());
	ForeachFile(m_resFileInfo, [&](const QFileInfo& info)
	{
#pragma region Prepare Path
		static QRegExp regUnkPath("UNK_([0-9A-F]{1,8})/", Qt::CaseInsensitive);
		QString sPath = curDir.relativeFilePath(info.path());
		if (sPath[sPath.size() - 1] != '/' ||
			sPath[sPath.size() - 1] != '\\')
			sPath += '/';
		uint hashPath = 0;
		if (0 == regUnkPath.indexIn(sPath))
			hashPath = regUnkPath.cap(1).toUInt(nullptr, 16);
		else
			hashPath = FNVHashString(sPath);

		if (hashToDir.find(hashPath) == hashToDir.end())
		{
			m_dirList.push_back(TFPKDir());
			TFPKDir& tfDir = m_dirList.back();
			tfDir.nPathHash = hashPath;
			tfDir.sPath = sPath;
			tfDir.nFileCount = 1;
			hashToDir[hashPath] = m_dirList.size() - 1;
		}
		else
		{
			++m_dirList[hashToDir[hashPath]].nFileCount;
		}
#pragma endregion

#pragma region Prepare FileName
		uint hashFile = FNVHashString(info.fileName(), hashPath);
		TFPKFileInfo& tfFile = m_files[hashFile];
		tfFile.nNameHash = hashFile;
		tfFile.nPathHash = hashPath;
		tfFile.sName = info.fileName();
		m_dirList[hashToDir[hashPath]].fileList.push_back(&tfFile);
#pragma endregion

#pragma region Prepare File
		m_filePosList.push_back(FilePosInfo());
		m_filePosList.back().nameHash = hashFile;
		if (0 == info.suffix().compare("png", Qt::CaseInsensitive) ||
			0 == info.suffix().compare("bmp", Qt::CaseInsensitive))
		{
			packImage(tfFile, info.filePath());
		}
		else if (0 == info.suffix().compare("csv", Qt::CaseInsensitive))
		{
			packCSV(tfFile, info.filePath());
		}
		else
		{
			packOther(tfFile, info.filePath());
		}
#pragma endregion
		std::cout << ".";
	});
	std::cout << std::endl;
}

void TFPKReader::writeDirList(RsaStream& writer)
{
	std::cout << "making dir list" << std::endl;

	uint nDirCount = 0;
	writer.writeFrom(m_dirList.size());
	for (uint i = 0; i < m_dirList.size(); ++i)
	{
		writer.writeFrom((TFPKDir_Base&)m_dirList[i]);
		std::cout << ".";
	}
	std::cout << std::endl;
}

void TFPKReader::writeFileNames(RsaStream& writer)
{
	std::cout << "compress file names" << std::endl;

	QByteArray originData;
	for (uint nDir = 0; nDir < m_dirList.size(); ++nDir)
	{
		std::vector<TFPKFileInfo*>& fileList = m_dirList[nDir].fileList;
		for (uint i = 0; i < fileList.size(); ++i)
		{
			originData.push_back(m_pDstCodec->fromUnicode(fileList[i]->sName));
			originData.push_back('\0');
			std::cout << ".";
		}
	}

	FileNamePakHeader fnHeader;
	fnHeader.OrigSize = originData.size();
	fnHeader.CompSize = compressBound(fnHeader.OrigSize);
	QByteArray compressFN(fnHeader.CompSize, 0);

	int res = compress((uchar*)compressFN.data(), (z_uLongf*)&fnHeader.CompSize, (uchar*)originData.data(), originData.size());
	assert(Z_OK == res);
	fnHeader.BlockCnt = std::ceil(fnHeader.CompSize * 1.0 / RsaStream::s_maxDatSize);

	writer.writeFrom(fnHeader);
	writer.writeBigData(compressFN.data(), fnHeader.CompSize);
}

void TFPKReader::writeFileList(RsaStream& writer)
{
	std::cout << "writing files" << std::endl;

	FileListPakHeader listHeader;
	listHeader.uFileCount = m_filePosList.size();
	writer.writeFrom(listHeader);

	std::mt19937 rng(time(NULL));
	uint uOffset = 0;
	for (uint i = 0; i < m_filePosList.size(); ++i)
	{
		FilePosInfo& info = m_filePosList[i];
		TFPKFileInfo& tfFile = m_files[info.nameHash];

		info.FileSize = tfFile.data.size();
		info.Offset = uOffset;
		uOffset += info.FileSize;

		for (int j = 0; j < 4; ++j)
			info.xorKey[j] = rng();

		writer.writeFrom((FilePosInfo_Base&)info);
		writer.writeFrom(info.nameHash);
		writer.writeFrom(info.xorKey);
		encodeFile(info.xorKey, (uchar*)tfFile.data.data(), tfFile.data.size());
		std::cout << ".";
	}
	std::cout << std::endl;
}

void TFPKReader::writeFile(QFile& file)
{
	qint64 begin = file.pos();
	for (uint i = 0; i < m_filePosList.size(); ++i)
	{
		FilePosInfo& info = m_filePosList[i];
		assert(begin + info.Offset == file.pos());
		file.write(m_files[info.nameHash].data);
	}
}

void TFPKReader::packImage(TFPKFileInfo& imgFile, const QString& filePath)
{
#if __GUI_SUPPORT__
	QImage img(filePath);

	TFBMFile_Base fileBase;
	memcpy(fileBase.magic, "TFBM", 5);
	fileBase.bit = img.depth();
	fileBase.width = img.width();
	fileBase.height = img.height();
	fileBase.padding_width = img.width();
	fileBase.compSize = compressBound(img.byteCount());
	QByteArray outBuff(fileBase.compSize, 0);

	int res = compress((uchar*)outBuff.data(), (z_uLongf*)&fileBase.compSize, img.constBits(), img.byteCount());
	assert(Z_OK == res);

	imgFile.data = QByteArray::fromRawData((const char*)&fileBase, sizeof(TFBMFile_Base));
	imgFile.data.append(outBuff.data(), fileBase.compSize);
#else
	packOther(imgFile, filePath);
#endif
}

void TFPKReader::packCSV(TFPKFileInfo& csvFile, const QString& filePath)
{
	TFCSFile_Base csFile;
	memcpy(csFile.magic, "TFCS", 5);
	
	CsvStream stream(filePath, m_pSrcCodec, m_pDstCodec);	
	QByteArray origin = stream.readToData();

	csFile.origSize = origin.size();
	csFile.compSize = compressBound(csFile.origSize);
	QByteArray outBuff(csFile.compSize, 0);
	int res = compress((uchar*)outBuff.data(), (z_uLongf*)&csFile.compSize, (uchar*)origin.data(), csFile.origSize);
	assert(Z_OK == res);

	csvFile.data = QByteArray::fromRawData((const char*)&csFile, sizeof(TFCSFile_Base));
	csvFile.data.append(outBuff.data(), csFile.compSize);
}

void TFPKReader::packOther(TFPKFileInfo& tfFile, const QString& filePath)
{
	QFile datFile(filePath);
	if (!datFile.open(QFile::ReadOnly))
	{
		qDebug() << datFile.errorString();
		return;
	}

	tfFile.data = datFile.readAll();
	datFile.close();
}

void TFPKReader::encodeFile(uint key[4], uchar* pData, uint encodeSize)
{
	for (int j = 0; j < encodeSize / 4; j++)
	{
		*((uint*)pData + j) ^= key[j % 4];
	}

	int remain = encodeSize % 4;
	if (remain)
	{
		uint tk = key[encodeSize / 4 % 4];
		for (int j = 0; j < remain; j++)
		{
			pData[encodeSize - remain + j] ^= tk & 0xFF;
			tk >>= 8;
		}
	}
}

//////////////////////////////////////////////////////////////////////////

CsvStream::CsvStream(const QString& fileName, QTextCodec* pSrcCodec, QTextCodec* pDstCodec)
	: m_name(fileName)
	, m_pSrcCodec(pSrcCodec)
	, m_pDstCodec(pDstCodec)
{
}

QByteArray CsvStream::readToData()
{
	QByteArray result;
	QFile datFile(m_name);
	if (!datFile.open(QFile::ReadOnly))
	{
		qDebug() << datFile.errorString();
		return result;
	}
	
	uint uIntDat = 0;
	result.append((char*)&uIntDat, sizeof(uint));
	
	QTextStream stream(&datFile);
	stream.setCodec(m_pSrcCodec);
	uint uLine = 0;
	while (!stream.atEnd())
	{
		QStringList sLine = stream.readLine().split(',');
		uIntDat = sLine.size();
		result.append((char*)&uIntDat, sizeof(uint));
		for (int i = 0; i < sLine.size(); ++i)
		{
			QByteArray mbcs = m_pDstCodec->fromUnicode(sLine[i]);
			uIntDat = mbcs.size();
			result.append((char*)&uIntDat, sizeof(uint));
			if (uIntDat)
				result.append(mbcs);
		}
		++uLine;
	}
	*(uint*)result.data() = uLine;
	return result;
}

void CsvStream::writeToFile(const QByteArray& data)
{
	const char* pData = data.data();
	const char* pEnd = pData + data.size();

	uint uRowCount = *(uint*)pData;
	pData += sizeof(uint);
	if (pData >= pEnd)
		return;

	QFile datFile(m_name);
	if (!datFile.open(QFile::WriteOnly))
	{
		qDebug() << datFile.errorString();
		return;
	}

	QTextStream stream(&datFile);
	stream.setCodec(m_pDstCodec);

	for (uint row = 0; row < uRowCount; ++row)
	{
		uint uColCount = *(uint*)pData;
		pData += sizeof(uint);

		for (uint col = 0; col < uColCount; ++col)
		{
			if (0 != col)
				stream << ',';

			uint ulen = *(uint*)pData;
			pData += sizeof(uint);
			if (0 == ulen)
				continue;

			assert(pData < pEnd);
			stream << m_pSrcCodec->toUnicode(pData, ulen);
			pData += ulen;
			assert(pData <= pEnd);
		}
		stream << endl;
	}
	datFile.close();
}

//////////////////////////////////////////////////////////////////////////

ActReader::ActReader()
{
	m_pTxtCodec = QTextCodec::codecForName("Shift-JIS");
	m_pTransCodec = QTextCodec::codecForName("GBK");
}

void ActReader::load(const QString& filePath)
{
	m_bLoad = true;
	QFileInfo pathinfo(filePath);
	ForeachFile(pathinfo, [this](const QFileInfo& info)
	{
		if (0 == info.suffix().compare("act", Qt::CaseInsensitive))
		{
			readFile(info.filePath());
		}
		else if (0 == info.suffix().compare("nut", Qt::CaseInsensitive))
		{
			NutReader reader(m_bLoad, m_strMap, m_transMap);
			reader.ReadFromPath(info.filePath());
		}
	});
	
	QString sTxtPath = QString("%1.txt").arg(pathinfo.path());
	QFile txtDmp(sTxtPath);
	if (!txtDmp.open(QFile::WriteOnly))
	{
		QMessageBox::warning(nullptr, "", txtDmp.errorString());
		return;
	}

	QTextStream txtStream;
	txtStream.setDevice(&txtDmp);
	txtStream.setCodec("UTF-8");
	txtStream.setGenerateByteOrderMark(true);
	for (auto iter = m_strMap.begin(); iter != m_strMap.end(); ++iter)
	{
		QString sOut = iter.key();
		sOut.replace('\\', "\\\\");
		sOut.replace('\r', "\\r");
		sOut.replace('\n', "\\n");
		txtStream << sOut << "\r\n";
	}

	txtDmp.close();
}

void ActReader::resetact(const QString& filePath)
{
	QFileInfo pathinfo(filePath);
	ForeachFile(pathinfo, [this](const QFileInfo& info)
	{
		if (0 == info.suffix().compare("act", Qt::CaseInsensitive) ||
			0 == info.suffix().compare("nut", Qt::CaseInsensitive))
		{
			QString target = info.filePath().replace("SSNTR_origin", "SSNTR").replace("SSNTRb_origin", "SSNTRb");
			if (target != info.filePath())
			{
				QFile(target).remove();
				QFile(info.filePath()).copy(target);
			}
		}
	});

}

static uint g_uDumpCount = 0;
static uint g_uTransCount = 0;
static QMap<QString, int> g_unTrans;
void ActReader::replace(const QString& path)
{
	m_bLoad = false;
	loadTranslateMap(path);

	QFileInfo pathinfo(path);
	pathinfo.makeAbsolute();
	ForeachFile(pathinfo, [this](const QFileInfo& info)
	{
		if (0 == info.suffix().compare("act", Qt::CaseInsensitive))
		{
			readFile(info.filePath());

			QFile tmpFile(info.filePath());
			if (!tmpFile.open(QFile::WriteOnly))
			{
				qDebug() << tmpFile.errorString();
				return;
			}

			tmpFile.write(m_outBuff);
			tmpFile.close();
		}
		else if (0 == info.suffix().compare("nut", Qt::CaseInsensitive))
		{
			NutReader reader(m_bLoad, m_strMap, m_transMap);
			bool bDecompile = (info.fileName() == "game_load.nut");
			reader.ReadFromPath(info.filePath(), bDecompile);
			QFile tmpFile(info.filePath());
			if (!tmpFile.open(QFile::WriteOnly))
			{
				qDebug() << tmpFile.errorString();
				return;
			}

			tmpFile.write(reader.buff());
			tmpFile.close();
		}

	});
	QMessageBox::information(nullptr, "Finish", QString("%1/%2").arg(g_uTransCount).arg(g_uDumpCount));
}

void ActReader::loadTranslateMap(const QString& path)
{
	QFile orignFile(QString("%1/../%2").arg(path).arg("SSNTR_jp.txt"));
	QFile transFile(QString("%1/../%2").arg(path).arg("SSNTR_cn.txt"));

	if (!orignFile.open(QFile::ReadOnly) ||
		!transFile.open(QFile::ReadOnly))
	{
		qDebug() << orignFile.errorString();
		qDebug() << transFile.errorString();
		return;
	}

	QTextStream orign(&orignFile);
	QTextStream trans(&transFile);

	orign.setCodec("UTF-8");
	trans.setCodec("UTF-8");

	while (!orign.atEnd() && !trans.atEnd())
	{
		QString src = orign.readLine().replace("\\n", "\n").replace("\\r", "\r").replace("\\\\", "\\");
		QString dst = trans.readLine().replace("\\n", "\n").replace("\\r", "\r").replace("\\\\", "\\");
		m_transMap[src] = dst;
	}

	orignFile.close();
	transFile.close();
}

void ActReader::readFile(const QString& filePath)
{
	QFile file(filePath);
	if (!file.open(QFile::ReadOnly))
	{
		qDebug() << file.errorString();
		return;
	}

	QDataStream stream(&file);
	stream.setByteOrder(QDataStream::LittleEndian);
	m_outBuff.clear();

	char magic[4];
	file.read(magic, 4);
	if (0 != memcmp(magic, "ACT1", 4))
		return;
	writeOutBuff(magic);

	int p1Count = 0;
	stream >> p1Count;
	writeOutBuff(p1Count);
	for (int i = 0; i < p1Count; ++i)
	{
		readGlobal(stream);	// base_script
		if (m_bLoad)
			assert(m_outBuff.size() == file.pos());
	}

	readSubTable1(stream);	// layout_info
	if (m_bLoad)
		assert(m_outBuff.size() == file.pos());

	readSubTable1(stream);	// resource_info
	if (m_bLoad)
		assert(m_outBuff.size() == file.pos());

	if (m_bLoad)
		assert(m_outBuff.size() == file.size());
	file.close();
}

void ActReader::readGlobal(QDataStream& stream)
{
	int id = 0;
	stream >> id;
	writeOutBuff(id);
	readStruct(stream, ActStruct::Global);
}

QVariant ActReader::readStruct(QDataStream& stream, ActStruct curStru)
{
	assert(ValidatStructType(curStru));
	const ActStructLayout& layout = getStructLayout(curStru);
	return readFromLayout(stream, curStru, layout);
}

const ActReader::ActStructLayout& ActReader::getStructLayout(ActStruct struc)
{
	static std::map<ActStruct, ActStructLayout> s_convMap;
	if (s_convMap.empty())
	{
		s_convMap[ActStruct::Global] = { ActValType::Table, ActValType::Table, ActValType::String };
		s_convMap[ActStruct::Layer] = { ActValType::Table, ActValType::SubTable1, ActValType::SubTable1, ActValType::Table, ActValType::String };
		s_convMap[ActStruct::KeyFrame] = { ActValType::Table, ActValType::SubTable2 };
		s_convMap[ActStruct::StringLayout] = { ActValType::Table };
		s_convMap[ActStruct::SpriteLayout] = { ActValType::Table };
		s_convMap[ActStruct::IFSMeshLayout] = { ActValType::Table };
		s_convMap[ActStruct::ChipLayout] = { ActValType::Table, ActValType::Array2D/*, ActValType::Int, ActValType::Table, ActValType::String*/ };
		s_convMap[ActStruct::ReservedLayout] = { ActValType::Table };
		s_convMap[ActStruct::ImageResource] = { ActValType::Table };
		s_convMap[ActStruct::BitmapFontResource] = { ActValType::Table, ActValType::Table, ActValType::Array2D };
		s_convMap[ActStruct::UnkResource] = { ActValType::Table };
		s_convMap[ActStruct::ChipResource] = { ActValType::Table };
	}
	return s_convMap[struc];
}

#define ActSimpleRead(valType)	\
{\
	valType val = 0;\
	stream >> val;\
	writeOutBuff(val);\
	var = val;\
}

QVariant ActReader::readFromLayout(QDataStream& stream, ActStruct curStru, const ActStructLayout& layout)
{
	QVariantList datList;
	uint nTableIdx = 0;
	for (uint i = 0; i < layout.size(); ++i)
	{
		ActValType varType = layout[i];
		QVariant var;
		switch (varType)
		{
		case ActValType::Int:
			ActSimpleRead(int);
			break;
		case ActValType::Float:
		{
			float val = 0;
			stream.readRawData((char*)&val, sizeof(float));
			writeOutBuff(val);
			var = val;
			break;
		}
		case ActValType::Bool:
			ActSimpleRead(uchar);
			break;
		case ActValType::String:
			var = readString(stream);
			break;
		case ActValType::WTF:
			ActSimpleRead(int);
			break;
		case ActValType::Table:
			var = readTable(stream, curStru, nTableIdx);
			break;
		case ActValType::SubTable1:
			var = readSubTable1(stream);
			break;
		case ActValType::SubTable2:
			var = readSubTable2(stream);
			break;
		case ActValType::Array1D:
			var = readArray1D(stream);
			break;
		case ActValType::Array2D:
			var = readArray2D(stream);
			break;
		default:
			assert(false);
			break;
		}
		datList << var;
		if (m_bLoad)
			assert(m_outBuff.size() == stream.device()->pos());
	}
	return datList;
}

// static QRegExp regExportText("[\\d\\sa-zA-Z/_+-\\\\,:\\.\\[\\]\\(\\)\\*%{}]*");
static QRegExp regExportText("[0-9 a-zA-Z_]*");
QVariant ActReader::readString(QDataStream& stream)
{
	uchar nutHeader[] = { 0xfa, 0xfa, 0x52, 0x49, 0x51, 0x53 };

	uint len = 0;
	stream >> len;
	QByteArray bytes(len, 0);
	stream.readRawData(bytes.data(), len);

	if (0 == memcmp(bytes.data(), nutHeader, sizeof(nutHeader)))
		return processNut(bytes);
	else
		return processStr(bytes);
}

QVariant ActReader::processNut(QByteArray& bytes)
{
	QFile tmpFile("tmp.nut");
	if (tmpFile.open(QFile::WriteOnly))
	{
		tmpFile.write(bytes);
		tmpFile.close();
		NutReader reader(m_bLoad, m_strMap, m_transMap);
		reader.ReadFromPath(tmpFile.fileName());

		writeOutBuff(reader.buff().size());
		m_outBuff.append(reader.buff());
		return reader.buff();
	}
	else
	{
		writeOutBuff(bytes.size());
		m_outBuff.append(bytes);
		return bytes;
	}
}

QVariant ActReader::processStr(QByteArray& bytes)
{
	bool bNeedTrans = false;
	QString str = m_pTxtCodec->toUnicode(bytes);
	if (!str.isEmpty() && (!m_bLoad || !regExportText.exactMatch(str)))
	{
		m_strMap[str] = 0;
		++g_uDumpCount;
		bNeedTrans = true;
	}

	if (m_transMap.contains(str))
	{
		QByteArray trans = m_pTransCodec->fromUnicode(m_transMap[str]);
		writeOutBuff(trans.size());
		m_outBuff.append(trans);
		++g_uTransCount;
	}
	else
	{
		if (m_bLoad)
		{
			writeOutBuff(bytes.size());
			m_outBuff.append(bytes);
		}
		else
		{
			if (bNeedTrans)
				g_unTrans[str] = 0;
			static QString dotJIS = m_pTxtCodec->toUnicode("\x81\x45");
			str.replace(dotJIS, QString::fromUtf16((ushort*)L"·"));

			QByteArray trans = m_pTransCodec->fromUnicode(str);
			writeOutBuff(trans.size());
			m_outBuff.append(trans);
		}
	}
	return str;
}

QVariant ActReader::readArray1D(QDataStream& stream)
{
	uint len = 0;
	stream >> len;
	writeOutBuff(len);
	QByteArray bytes(len, 0);
	stream.readRawData(bytes.data(), len);
	m_outBuff.append(bytes);
	return bytes;
}

QVariant ActReader::readArray2D(QDataStream& stream)
{
	QVariantList arr;
	uint row = 0;
	uint col = 0;
	stream >> row >> col;
	writeOutBuff(row);
	writeOutBuff(col);

	for (uint r = 0; r < row; ++r)
	{
		QByteArray bytes(col, 0);
		stream.readRawData(bytes.data(), col);
		m_outBuff.append(bytes);
		arr.push_back(bytes);
	}
	return arr;
}

const ActReader::ActStructLayout& ActReader::getTableLayout(ActStruct struc, uint uTableIdx)
{
	static std::map<ActStruct, std::vector<ActStructLayout>> s_convMap;
	if (s_convMap.empty())
	{
		s_convMap[ActStruct::Global] = {
			{ ActValType::Bool, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int,
				ActValType::Bool, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int,
				ActValType::Float, ActValType::Float, ActValType::Int, ActValType::Int, ActValType::Int,
				ActValType::String, ActValType::Int, ActValType::Bool, ActValType::Bool },
			{ ActValType::Bool, ActValType::String } };
		s_convMap[ActStruct::Layer] = {
			{ ActValType::Bool, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Bool,
				ActValType::Int, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Int,
				ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Int, ActValType::String,
				ActValType::Bool, ActValType::Bool },
			{ ActValType::Bool, ActValType::String } };
		s_convMap[ActStruct::KeyFrame] = {
			{ ActValType::Int, ActValType::Int, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Int, ActValType::String } };
		s_convMap[ActStruct::StringLayout] = {
			{ ActValType::Bool, ActValType::Int, ActValType::Float, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::WTF, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Bool, ActValType::Bool, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Bool, ActValType::String, ActValType::String, ActValType::String, ActValType::Bool, ActValType::Int, ActValType::Bool, ActValType::Int } };
		s_convMap[ActStruct::SpriteLayout] = {
			{ ActValType::Float, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Int } };
		s_convMap[ActStruct::IFSMeshLayout] = {
			{ ActValType::Float, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Int, ActValType::Bool } };
		s_convMap[ActStruct::ChipLayout] = {
			{
				ActValType::Float, ActValType::Bool, ActValType::Int, ActValType::Int, ActValType::Int,
				ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Int,
				ActValType::Int, ActValType::Float, ActValType::Int, ActValType::Bool, ActValType::Bool
			},
			{ ActValType::Bool, ActValType::String }
		};
		s_convMap[ActStruct::ReservedLayout] = {
			{ActValType::String} };
		s_convMap[ActStruct::ImageResource] = {
			{ ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::String, ActValType::String } };
		s_convMap[ActStruct::BitmapFontResource] = {
			{ ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::String, ActValType::String },
			{ ActValType::WTF, ActValType::WTF, ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::String, ActValType::String } };
		s_convMap[ActStruct::UnkResource] = {
			{ ActValType::Int, ActValType::Int, ActValType::Int, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::Float, ActValType::String, ActValType::String } };
		s_convMap[ActStruct::ChipResource] = {
			{ ActValType::Int, ActValType::String, ActValType::String } };

	}
	return s_convMap[struc][uTableIdx];
}

static std::vector<std::pair<QString, ActValType>> g_typeCache;
QVariant ActReader::readTable(QDataStream& stream, ActStruct curStru, uint nTableIdx)
{
	ActStructLayout layout = getTableLayout(curStru, nTableIdx);
	uint uTableCol = layout.size();
	
	uchar bHint = false;
	stream >> bHint;
	writeOutBuff(bHint);

	if (bHint)
	{
		g_typeCache.clear();

		stream >> uTableCol;
		writeOutBuff(uTableCol);

		layout.clear();
		for (uint j = 0; j < uTableCol; ++j)
		{
			QString name = readString(stream).toString();
			int type = 0;
			stream >> type;
			writeOutBuff(type);

			layout.push_back((ActValType)type);

			g_typeCache.push_back(std::make_pair(name, (ActValType)type));
		}
	}

	QVariant var = readFromLayout(stream, curStru, layout);
	if (curStru == ActStruct::StringLayout)
	{
		for (uint i = 0; i < uTableCol; ++i)
		{
			if (layout[i] == ActValType::WTF)
			{
				int nSize = var.toList()[i].toInt();
				QByteArray arr(nSize * 4, 0);
				stream.readRawData(arr.data(), arr.size());
				m_outBuff.append(arr);

				var.toList() << arr;
			}
		}
	}
	return var;
}

QVariant ActReader::readSubTable1(QDataStream& stream)
{
	uint nSize = 0;
	stream >> nSize;
	writeOutBuff(nSize);

	std::vector<ActStruct> strucLog;
	QVariantList varlist;
	for (uint i = 0; i < nSize; ++i)
	{
		uint subStru = 0;
		stream >> subStru;
		writeOutBuff(subStru);

		strucLog.push_back((ActStruct)subStru);
		varlist << readStruct(stream, (ActStruct)subStru);
		if (m_bLoad)
			assert(m_outBuff.size() == stream.device()->pos());
	}
	return varlist;
}

QVariant ActReader::readSubTable2(QDataStream& stream)
{
	uchar nSize = 0;
	stream >> nSize;
	writeOutBuff(nSize);

	QVariantList varlist;
	for (uint i = 0; i < nSize; ++i)
	{
		uint subStru = 0;
		stream >> subStru;
		writeOutBuff(subStru);

		varlist << readStruct(stream, (ActStruct)subStru);
	}
	return varlist;
}

bool ActReader::ValidatStructType(ActStruct struc)
{
	switch (struc)
	{
	case ActStruct::Global:
	case ActStruct::Layer:
	case ActStruct::KeyFrame:
	case ActStruct::StringLayout:
	case ActStruct::SpriteLayout:
	case ActStruct::IFSMeshLayout:
	case ActStruct::ReservedLayout:
	case ActStruct::ImageResource:
	case ActStruct::BitmapFontResource:
	case ActStruct::UnkResource:
	case ActStruct::ChipLayout:
	case ActStruct::ChipResource:
		return true;
	default:
		return false;
	}
}

NutReader::NutReader(bool bLoad, QMap<QString, int>& strMap, QMap<QString, QString>& transMap)
	: m_strMap(strMap)
	, m_transMap(transMap)
	, m_bLoad(bLoad)
{

}

NutReader::~NutReader()
{

}

void NutReader::ReaderHooker(void* obj, void* buffer, int size, bool bString)
{
	NutReader* reader = (NutReader*)obj;

	if (!bString)
	{
		reader->write(buffer, size);
	}
	else
	{
		QString str = g_jpCodec->toUnicode((char*)buffer, size);
		bool bNeedTrans = false;
		if (!str.isEmpty() && (!reader->m_bLoad || !regExportText.exactMatch(str)))
		{
			reader->m_strMap[str] = 0;
			++g_uDumpCount;
			bNeedTrans = true;
		}
		if (reader->m_transMap.contains(str))
		{
			QByteArray trans = g_cnCodec->fromUnicode(reader->m_transMap[str]);
			reader->rewriteStr(trans);
			++g_uTransCount;
		}
		else
		{
			if (bNeedTrans && !reader->m_bLoad)
				g_unTrans[str] = 0;
			reader->write(buffer, size);
		}
	}
}

void NutReader::write(void* buffer, int size)
{
	m_outBuff.append((char*)buffer, size);
}

void NutReader::rewriteStr(const QByteArray& str)
{
	int* pStrCnt = (int*)(m_outBuff.data() + m_outBuff.size() - sizeof(int));
	*pStrCnt = str.size();
	m_outBuff.append(str);
}

void NutReader::ReadFromPath(const QString& filePath, bool tryDecompile /*= false*/)
{
	NutScript script;
	BinaryReader::SetReaderHook(ReaderHooker, this);
	QByteArray path = g_cnCodec->fromUnicode(filePath);
	script.LoadFromFile(path.data());

	if (tryDecompile)
	{
		QString buff;
		QTextStream sstream(&buff);
		g_DebugMode = true;
		script.GetMain().GenerateBodySource(0, sstream);
		qDebug() << buff;
	}
}
