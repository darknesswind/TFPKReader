#include <iostream>
#include "TFPKReader.h"
#include <QTextCodec>
// #include <Windows.h>

void Usage(void)
{
	std::cout << "TFPKReader without image process." << std::endl;;
	std::cout << std::endl;
	std::cout << "  Usage:" << std::endl;
	std::cout << "    tfpkreader [-codec <name>] -pack <dir>" << std::endl;
	std::cout << "    tfpkreader [-codec <name>] -unpack <file>" << std::endl;
	std::cout << "    tfpkreader [-codec <name>] -replace <file>" << std::endl;
	std::cout << std::endl;
	std::cout << "  Options:" << std::endl;
	std::cout << "   -codec  <name>   Set the text codec name. " << std::endl;
	std::cout << "                    Exp: GBK, Shift-JIS, UTF-8 etc..." << std::endl;
	std::cout << "                    The default text codec is Shift-JIS." << std::endl;
	std::cout << "   -pack   <dir>    Package <dir> to pak file." << std::endl;
	std::cout << "   -unpack <file>   Unpackage a pak file." << std::endl;
	std::cout << "   -replace <dir>   Replace string in the .nut, .act file in <dir>." << std::endl;
	std::cout << std::endl;
	std::cout << std::endl;
}

enum ArgSetting
{
	flag_none		= 0,
	flag_pack		= 0x1,
	flag_unpack		= 0x2,
	flag_replace	= 0x4,
};

#define CheckArgAddition(addition)\
{\
	if (i + addition >= argc)\
	{\
		Usage();\
		std::cout << "Error: Invalid arg number!" << std::endl;\
		return -1;\
	}\
}

typedef const char* (__stdcall *TransStringFn)(const char* str);
int main(int argc, char* argv[])
{
// 	DWORD res = GetLastError();
// 	HMODULE hm = LoadLibraryA("HookString.dll");
// 	res = GetLastError();
// 	TransStringFn TransString = (TransStringFn)GetProcAddress(hm, "TransString");
// 	res = GetLastError();
// 
// 	TransString("a");
	QTextCodec* pDstCodec = QTextCodec::codecForName("GBK");
	QTextCodec* pSrcCodec = QTextCodec::codecForName("GBK");
	QString target;

	uint action = flag_none;
	for (int i = 1; i < argc; ++i)
	{
		char* pArg = argv[i];

		if (0 == _stricmp(argv[i], "-pack"))
		{
			CheckArgAddition(1);
			action |= flag_pack;
		}
		else if (0 == _stricmp(argv[i], "-unpack"))
		{
			CheckArgAddition(1);
			action |= flag_unpack;
		}
		else if (0 == _stricmp(argv[i], "-replace"))
		{
			CheckArgAddition(1);
			action |= flag_replace;
		}
		else if (0 == _stricmp(argv[i], "-codec"))
		{
			CheckArgAddition(1);
			pSrcCodec = QTextCodec::codecForName(argv[i + 1]);
			++i;
			if (nullptr == pSrcCodec)
			{
				Usage();
				std::cout << "Error: Invalid codec name!" << std::endl;
				return -1;
			}
		}
		else
		{
			Usage();
			return -1;
		}

		if (action & (flag_pack | flag_unpack | flag_replace))
		{
			target = QString::fromLocal8Bit(argv[i + 1]);
			++i;
		}
	}

	

	if (target[0] == '"')
	{
		target = target.mid(1, target.count() - 2);
	}

	if (action & flag_pack)
	{
		TFPKReader reader(pSrcCodec, pDstCodec);
		reader.package(target);
	}
	else if (action & flag_unpack)
	{
		TFPKReader reader(pSrcCodec, pDstCodec);
		reader.unpack(target);
	}
	else if (action & flag_unpack)
	{
		ActReader act;
		act.replace(target);
	}
	else
	{
		Usage();
		return -1;
	}

	return 0;
}
