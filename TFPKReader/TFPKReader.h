#pragma once
#include <QFileInfo>
#include <openssl/rsa.h>
#include <QHash>
#include <QMap>
#include <QSet>
#define __GUI_SUPPORT__ 0

#pragma region TH135
struct TFPKDir_Base
{
	uint nPathHash;
	uint nFileCount;

	TFPKDir_Base() : nPathHash(0), nFileCount(0) {}
};

struct TFPKFileInfo
{
	uint nNameHash;
	uint nPathHash;
	QString sName;
	QByteArray data;
	TFPKFileInfo() : nNameHash(0), nPathHash(0) {};
};

struct TFPKDir : public TFPKDir_Base
{
	QString sPath;
	std::vector<TFPKFileInfo*> fileList;
};

struct FileNamePakHeader
{
	uint CompSize;
	uint OrigSize;
	uint BlockCnt;
	FileNamePakHeader() : CompSize(0), OrigSize(0), BlockCnt(0) {}
};

struct FileListPakHeader
{
	uint uFileCount;
#ifndef TH145
	uint unk1;
	uint unk2;
#endif
	FileListPakHeader()
		: uFileCount(0)
#ifndef TH145
		, unk1(0)
		, unk2(0)
#endif
	{}
};

struct FilePosInfo_Base
{
	uint FileSize;
	uint Offset;
};

struct FilePosInfo : public FilePosInfo_Base
{
	uint nameHash;
	uint xorKey[4];
};

#pragma pack(push)
#pragma pack(1)
struct TFBMFile_Base
{
	char magic[5];
	uchar bit;
	uint width;
	uint height;
	uint padding_width;
	uint compSize;
};

struct TFBMFile : public TFBMFile_Base
{
	uchar variableData[1];
};

struct TFCSFile_Base
{
	char magic[5];
	uint compSize;
	uint origSize;
};

struct TFCSFile : public TFCSFile_Base
{
	uchar variableData[1];
};

#pragma pack(pop)
#pragma endregion

#pragma region TH145

struct Data64 { uint lw, hi; };
struct FileInfo145
{
	uint key;

	uint pakId;
	uint _key;
	uint unk1;
	uint pos;
	uint size;
	uint xorKeys[4];
};

#pragma endregion

enum PAKFileFormat
{
	pak_bmp,
	pak_csv,
	pak_ogg,
	pak_nut,
	pak_xml,
	pak_act,
	pak_pl,
	pak_dds,
	pak_otf,
	pak_wav,
	pak_bmb,
	pak_pa,
	pak_unk
};

class RsaStream;
class TFPKReader
{
public:
	TFPKReader(QTextCodec* pSrcCodec, QTextCodec* pDstCodec);
	~TFPKReader(){};

	void unpack(const QString& pakFile);
	void package(const QString& pakPath);

	static uint FNVHashString(const QString& str, uint initHash = 0x811C9DC5u);

private:
	void matchHashPath(TFPKDir& tfpkDir);
	QString& matchHashPath(uint hash);
	void decodeFile(uint key[4], uchar* pData, uint decodeSize);
	void encodeFile(uint key[4], uchar* pData, uint encodeSize);
	QString makeFilePath(const TFPKFileInfo& tfFile);
	void loadDirList();
	PAKFileFormat getFileFormat(const uchar* pDat);

	uint readDirList(RsaStream& reader);
	void readFileNames(RsaStream& reader);
	void readFileList(RsaStream& reader);
	void readFile(QFile& file);
	void extraImage(TFPKFileInfo& imgFile);
	void extraCSV(TFPKFileInfo& csvFile);
	void extraOther(TFPKFileInfo& tfFile);

	void prepareDataToWrite();
	void writeDirList(RsaStream& writer);
	void writeFileNames(RsaStream& writer);
	void writeFileList(RsaStream& writer);
	void writeFile(QFile& file);
	void packImage(TFPKFileInfo& imgFile, const QString& filePath);
	void packCSV(TFPKFileInfo& csvFile, const QString& filePath);
	void packOther(TFPKFileInfo& tfFile, const QString& filePath);

	void readFileList145(RsaStream& reader);
	void readFile145(QFile& file);
	void decodeFile145(uint key[4], uchar* pData, uint decodeSize);

private:
	QFileInfo	m_resFileInfo;
	QTextCodec*	m_pSrcCodec;
	QTextCodec*	m_pDstCodec;
	QHash<uint, QString>		m_dirPathLookUp;
	QHash<uint, TFPKFileInfo>	m_files;
	std::vector<TFPKDir>		m_dirList;
	std::vector<FilePosInfo>	m_filePosList;

	std::vector<FileInfo145>	m_files145;
};

class CsvStream
{
public:
	CsvStream(const QString& fileName, QTextCodec* pSrcCodec, QTextCodec* pDstCodec);
	~CsvStream() {}

	QByteArray readToData();
	void writeToFile(const QByteArray& data);

private:
	QString m_name;
	QTextCodec*	m_pSrcCodec;
	QTextCodec*	m_pDstCodec;
};


enum class ActValType : uint
{
	Int = 0,
	Float = 1,
	Bool = 2,
	String = 3,
	WTF = 5, // it may be array but
	Table = 1000,
	SubTable1 = 1001,
	SubTable2 = 1002,
	Array1D = 1003,
	Array2D = 1004,
};

enum class ActStruct : uint
{
	Global = 0xDEADBEEF,	// [TYPE_TABLE,TYPE_TABLE,TYPE_STRING]
	Layer = 0x79890BB2,	// : [TYPE_TABLE, TYPE_SUBTABLE1, TYPE_SUBTABLE1, TYPE_TABLE, TYPE_STRING], # 
	KeyFrame = 0x16CD8498,	// : [TYPE_TABLE, TYPE_SUBTABLE2], # KeyFrame
	// Combined with types above
	StringLayout = 0xA597329B,	// : [TYPE_TABLE], # StringLayout
	SpriteLayout = 0xBCD50C74,	// : [TYPE_TABLE], # SpriteLayout
	IFSMeshLayout = 0xBBB44DB9,	// : [TYPE_TABLE], # IFSMeshLayout
	ReservedLayout = 0xECD7EF7B,	// : [TYPE_TABLE], # ReservedLayout  // ... 厘真。。。
	ChipLayout = 0x82a4162f,

	ImageResource = 0x44C0E960,	// : [TYPE_TABLE], # ImageResource
	BitmapFontResource = 0x9EDD843A,	// : [TYPE_TABLE, TYPE_TABLE, TYPE_ARR2D], # BitmapFontResource
	ChipResource = 0xF4E12505,
	UnkResource = 0x8CB4D3C0,	// : [TYPE_TABLE],
};

class ActReader
{
public:
	typedef std::vector<ActValType> ActStructLayout;

public:
	ActReader();
	~ActReader() {};

	void load(const QString& path);
	void resetact(const QString& path);
	void replace(const QString& path);

private:
	const ActStructLayout& getStructLayout(ActStruct struc);
	const ActStructLayout& getTableLayout(ActStruct struc, uint uTableIdx);
	bool ValidatStructType(ActStruct struc);

	void readFile(const QString& filePath);
	void readGlobal(QDataStream& stream);
	QVariant readStruct(QDataStream& stream, ActStruct curStru);
	QVariant readFromLayout(QDataStream& stream, ActStruct curStru, const ActStructLayout& layout);
	QVariant readTable(QDataStream& stream, ActStruct curStru, uint nTableIdx);
	QVariant readString(QDataStream& stream);
	QVariant readArray1D(QDataStream& stream);
	QVariant readArray2D(QDataStream& stream);
	QVariant readSubTable1(QDataStream& stream);
	QVariant readSubTable2(QDataStream& stream);

	QVariant processNut(QByteArray& bytes);
	QVariant processStr(QByteArray& bytes);

	template <typename T>
	void writeOutBuff(const T& data)
	{
		m_outBuff.append((const char*)&data, sizeof(data));
	}
	void loadTranslateMap(const QString& path);

private:
	QTextCodec* m_pTxtCodec;
	QTextCodec* m_pTransCodec;

	QMap<QString, int> m_strMap;
	QMap<QString, QString> m_transMap;
	QByteArray m_outBuff;
	bool m_bLoad = false;
};

class NutReader
{
public:
	NutReader(bool bLoad, QMap<QString, int>& strMap, QMap<QString, QString>& transMap);
	~NutReader();

	void ReadFromPath(const QString& filePath, bool tryDecompile = false);
	const QByteArray& buff() const { return m_outBuff; }

	static void ReaderHooker(void* obj, void* buffer, int size, bool bString);

private:
	void write(void* buffer, int size);
	void rewriteStr(const QByteArray& str);

private:
	bool m_bLoad;
	QByteArray m_outBuff;
	QMap<QString, int> &m_strMap;
	QMap<QString, QString> &m_transMap;
};