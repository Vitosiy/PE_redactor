#include <Windows.h>
#include <stdio.h>
#include <malloc.h>

typedef struct _PeHeaders {
	char* filename;      // имя файла

	HANDLE              fd;             // хендл открытого файла
	HANDLE              mapd;           // хендл файловой проекции
	PBYTE               mem;            // указатель на память спроецированного файла
	DWORD               filesize;       // размер спроецированной части файла

	IMAGE_DOS_HEADER* doshead;       // указатель на DOS заголовок
	IMAGE_NT_HEADERS* nthead;        // указатель на NT заголовок

	IMAGE_IMPORT_DESCRIPTOR* impdir;    // указатель на массив дескрипторов таблицы импорта
	DWORD               sizeImpdir;     // размер таблицы импорта
	DWORD               countImpdes;    // количество элементов в таблице импорта

	IMAGE_EXPORT_DIRECTORY* expdir;    // указатель на таблицу экспорта
	DWORD               sizeExpdir;     // размер таблицы экспорта

	IMAGE_SECTION_HEADER* sections;  // указатель на таблицу секций (на первый элемент)
	DWORD                   countSec;   // количество секций

	IMAGE_BASE_RELOCATION* relocs_directory;
	DWORD reloc_directory_size;

	BYTE pe32plus;

} PeHeaders;

ULONG_PTR RvaToOffset(ULONG_PTR rva, PeHeaders* pe);

BOOL LoadPeFile(char* filename, PeHeaders* pe);

void ChangeSignature(PeHeaders* pe);

void ChangeNumberOfSections(PeHeaders* pe);

void ChangeTimeStamp(PeHeaders* pe);

void ChangeSizeOfOptionalHeader(PeHeaders* pe);

void ChangeCharacteristics(PeHeaders* pe);

void ChangeMagic(PeHeaders* pe);

void ChangeAddressEntryPoint(PeHeaders* pe);

void ChangeImageBase(PeHeaders* pe);

void ChangeSectionAlignment(PeHeaders* pe);

void ChangeFileAlignment(PeHeaders* pe);

void ChangeSizeOfImage(PeHeaders* pe);

void ChangeSizeOfHeaders(PeHeaders* pe);

void ChangeSubsystem(PeHeaders* pe);

void ChangeNumberOfRvaAndSizes(PeHeaders* pe);

void EditTableSection(PeHeaders* pe);

void EditDataDirectory(PeHeaders* pe);

void EditRelocs(PeHeaders* pe);

void EditRelocs2(PeHeaders* pe);

void EditRelocs3(PeHeaders* pe);

void EditRelocs3NewBlock(PeHeaders* pe);

void EditImportTable(PeHeaders* pe);

void EditImportTable2(PeHeaders* pe);

void EditImportTable2Header(PeHeaders* pe);

//void EditImportTable3(PeHeaders* pe);

void EditExportTable(PeHeaders* pe);

void EditExportTable2(PeHeaders* pe);

void ExtendFileSize(PeHeaders* pe);

DWORD ExtendFileSizeCreatingNewSection(PeHeaders* pe);

DWORD ExtendFileSizeCreatingNewSectionNeededSize(PeHeaders* pe, const DWORD size);
