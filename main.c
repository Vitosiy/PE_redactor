#include "editor.h"


void usage(const char* progname) {
	printf("%s <filepath> <option>\n", progname);
	puts("signature - change PE signature");
	puts("sections - change number of sections");
	puts("timestamp - change timestamp");
	puts("opthead - change size of optional header");
	puts("characteristics - change characteristics of file");
	puts("magic - change magic bytes");
	puts("entry - change address of the entry point");
	puts("imagebase - change image base value");
	puts("secalig - change section aligment value");
	puts("filealig - change section aligment value");
	puts("sizeofimage - change size of image value");
	puts("sizeofheaders - change size of headers value");
	puts("subsystem - change subsystem");
	puts("rvas - change NumberOfRvaAndSizes value");

	puts("sections_interactive - change sections different data");
	puts("data_directory_interactive - reset data directory different data");

}

int main(int argc, char** argv) {

	PeHeaders pe;

	if (argc > 2) {
		if (!LoadPeFile(argv[1], &pe)) {
			puts("file did not load");
			return -1;
		}

		if (strcmp(argv[2], "signature") == 0) {
			ChangeSignature(&pe);
		}

		else if (strcmp(argv[2], "sections") == 0) {
			ChangeNumberOfSections(&pe);
		}

		else if (strcmp(argv[2], "timestamp") == 0) {
			ChangeTimeStamp(&pe);
		}

		else if (strcmp(argv[2], "opthead") == 0) {
			ChangeSizeOfOptionalHeader(&pe);
		}

		else if (strcmp(argv[2], "characteristics") == 0) {
			ChangeCharacteristics(&pe);
		}

		else if (strcmp(argv[2], "magic") == 0) {
			ChangeMagic(&pe);
		}

		else if (strcmp(argv[2], "entry") == 0) {
			ChangeAddressEntryPoint(&pe);
		}

		else if (strcmp(argv[2], "imagebase") == 0) {
			ChangeImageBase(&pe);
		}

		else if (strcmp(argv[2], "secalig") == 0) {
			ChangeSectionAlignment(&pe);
		}

		else if (strcmp(argv[2], "filealig") == 0) {
			ChangeFileAlignment(&pe);
		}

		else if (strcmp(argv[2], "sizeofimage") == 0) {
			ChangeSizeOfImage(&pe);
		}

		else if (strcmp(argv[2], "sizeofheaders") == 0) {
			ChangeSizeOfHeaders(&pe);
		}

		else if (strcmp(argv[2], "subsystem") == 0) {
			ChangeSubsystem(&pe);
		}

		else if (strcmp(argv[2], "rvas") == 0) {
			ChangeNumberOfRvaAndSizes(&pe);
		}


		else if (strcmp(argv[2], "sections_interactive") == 0) {
			EditTableSection(&pe);
		}

		else if (strcmp(argv[2], "data_directory_interactive") == 0) {
			EditDataDirectory(&pe);
		}

		else if (strcmp(argv[2], "reloc_interactive1") == 0) {
			EditRelocs(&pe);
		}

		else if (strcmp(argv[2], "reloc_interactive2") == 0) {
			EditRelocs2(&pe);
		}

		else if (strcmp(argv[2], "reloc_interactive3") == 0) {
			EditRelocs3(&pe);
		}

		else if (strcmp(argv[2], "reloc_interactive3header") == 0) {
			EditRelocs3NewBlock(&pe);
		}

		else if (strcmp(argv[2], "import_interactive") == 0) {
			EditImportTable(&pe);
		}

		else if (strcmp(argv[2], "import_interactive2") == 0) {
			EditImportTable2(&pe);
		}

		else if (strcmp(argv[2], "import_interactive2_header") == 0) {
			EditImportTable2Header(&pe);
		}

		/*else if (strcmp(argv[2], "import_interactive3") == 0) {
			EditImportTable3(&pe);
		}*/

		else if (strcmp(argv[2], "export_interactive") == 0) {
			EditExportTable(&pe);
		}

		else if (strcmp(argv[2], "export_interactive2") == 0) {
			EditExportTable2(&pe);
		}

		else if (strcmp(argv[2], "extend_file_size_interactive") == 0) {
			ExtendFileSize(&pe);
		}

		else if (strcmp(argv[2], "extend_file_size_non_interactive") == 0) {
			ExtendFileSizeCreatingNewSection(&pe);
		}

		UnmapViewOfFile(pe.mem);
		CloseHandle(pe.fd);
		CloseHandle(pe.mapd);
	}
	else {
		usage(argv[0]);
	}

	return 0;
}