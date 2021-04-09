#include "editor.h"

BOOL LoadPeFile(char* filename, PeHeaders* pe) {
	pe->filename = filename;

	// открываем файл (получаем файловый дескриптор)
	pe->fd = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (pe->fd == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	pe->filesize = GetFileSize(pe->fd, NULL);

	// создаем проекцию файла в память
	pe->mapd = CreateFileMapping(pe->fd, NULL, PAGE_READWRITE, 0, pe->filesize, NULL);
	if (pe->mapd == NULL) {
		CloseHandle(pe->fd);
		printf("Error create file map\n");
		return FALSE;
	}

	// отображаем проекцию в память
	pe->mem = (PBYTE)MapViewOfFile(pe->mapd, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pe->mem == NULL) {
		CloseHandle(pe->fd);
		CloseHandle(pe->mapd);
		printf("Error mapping file\n");
		return FALSE;
	}

	// указатель на заголовок PE
	pe->doshead = (IMAGE_DOS_HEADER*)pe->mem;

	if (pe->doshead->e_magic != IMAGE_DOS_SIGNATURE) {
		UnmapViewOfFile(pe->mem);
		CloseHandle(pe->fd);
		CloseHandle(pe->mapd);
		printf("Error DOS signature\n");
		return FALSE;
	}

	// указатель на NT заголовок
	pe->nthead = (IMAGE_NT_HEADERS*)((unsigned int)pe->mem + pe->doshead->e_lfanew);

	if (pe->nthead->Signature != IMAGE_NT_SIGNATURE) {
		UnmapViewOfFile(pe->mem);
		CloseHandle(pe->fd);
		CloseHandle(pe->mapd);
		printf("Error NT signature\n");
		return FALSE;
	}

	// получаем информацию о секциях
	pe->sections = (IMAGE_SECTION_HEADER*)((unsigned int)&(pe->nthead->OptionalHeader) + pe->nthead->FileHeader.SizeOfOptionalHeader);
	pe->countSec = pe->nthead->FileHeader.NumberOfSections;

	if (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
		pe->expdir = (IMAGE_EXPORT_DIRECTORY*)
			(pe->mem + RvaToOffset(pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, pe));
		pe->sizeExpdir = pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	else {
		pe->expdir = 0;
		pe->sizeExpdir = 0;
	}

	if (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
		pe->impdir = (IMAGE_IMPORT_DESCRIPTOR*)
			(pe->mem + RvaToOffset(pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pe));
		pe->sizeImpdir = pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	}
	else {
		pe->impdir = 0;
		pe->sizeImpdir = 0;
	}

	if (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
		pe->relocs_directory = (IMAGE_BASE_RELOCATION*)(pe->mem + RvaToOffset(pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, pe));
		pe->reloc_directory_size = pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	}
	else {
		pe->relocs_directory = 0;
		pe->reloc_directory_size = 0;
	}

	if (pe->nthead->OptionalHeader.Magic == 0x10b) {
		pe->pe32plus = 0;
	}
	else if (pe->nthead->OptionalHeader.Magic == 0x20b) {
		pe->pe32plus = 1;
	}
	else {
		return FALSE;
	}

	return TRUE;
}

ULONG_PTR RvaToOffset(ULONG_PTR rva, PeHeaders* pe) {
	DWORD i;
	IMAGE_SECTION_HEADER* sections = pe->sections;
	DWORD NumberSection = pe->countSec;

	if (rva > pe->nthead->OptionalHeader.SizeOfImage) {
		return 0;
	}

	//проходим по всем секциям и ищем
	//в какую попадает RVA
	for (i = 0; i < NumberSection; ++i) {
		if ((rva >= sections[i].VirtualAddress) && (rva <= sections[i].VirtualAddress + sections[i].Misc.VirtualSize)) {
			return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
		}
	}

	return 0;
}

void ChangeSignature(PeHeaders* pe) {
	printf("New value (2 bytes): ");
	WORD new_magic;
	scanf("%hd", &new_magic);
	//sprintf((char*)&pe->doshead->e_magic, "%s", (char*)&new_magic); //sprintf Меняем на memcpy , кроме строк
	memcpy((char*)&pe->doshead->e_magic, (char*)&new_magic, sizeof(WORD));
}

void ChangeNumberOfSections(PeHeaders* pe) {
	printf("New value (2 bytes): ");
	WORD new_number;
	scanf("%hd", &new_number);
	//sprintf((char*)&pe->nthead->FileHeader.NumberOfSections, "%s", (char*)&new_number);
	memcpy((char*)&pe->nthead->FileHeader.NumberOfSections, (char*)&new_number, sizeof(WORD));
}

void ChangeTimeStamp(PeHeaders* pe) {
	printf("New value (4 bytes): ");
	DWORD new_time;
	scanf("%d", &new_time);
	//sprintf((char*)&pe->nthead->FileHeader.TimeDateStamp, "%s", (char*)&new_time);
	memcpy((char*)&pe->nthead->FileHeader.TimeDateStamp, (char*)&new_time, sizeof(DWORD));

}

void ChangeSizeOfOptionalHeader(PeHeaders* pe) {
	printf("New value (2 bytes): ");
	WORD new_size;
	scanf("%hd", &new_size);
	//sprintf((char*)&pe->nthead->FileHeader.SizeOfOptionalHeader, "%s", (char*)&new_size);
	memcpy((char*)&pe->nthead->FileHeader.SizeOfOptionalHeader, (char*)&new_size, sizeof(WORD));

}

void ChangeCharacteristics(PeHeaders* pe) {
	printf("New value (2 bytes): ");
	WORD new_ch;
	scanf("%hd", &new_ch);
	//sprintf((char*)&pe->nthead->FileHeader.Characteristics, "%s", (char*)&new_ch);
	memcpy((char*)&pe->nthead->FileHeader.Characteristics, (char*)&new_ch, sizeof(WORD));

}

void ChangeMagic(PeHeaders* pe) {
	printf("New value (2 bytes): ");
	WORD new_magic;
	scanf("%hd", &new_magic);
	//sprintf((char*)&pe->nthead->OptionalHeader.Magic, "%s", (char*)&new_magic);
	memcpy((char*)&pe->nthead->OptionalHeader.Magic, (char*)&new_magic, sizeof(WORD));

}

void ChangeAddressEntryPoint(PeHeaders* pe) {
	printf("New value (4 bytes): ");
	DWORD new_address;
	scanf("%d", &new_address);
	//sprintf((char*)&pe->nthead->OptionalHeader.AddressOfEntryPoint, "%s", (char*)&new_address);
	memcpy((char*)&pe->nthead->OptionalHeader.AddressOfEntryPoint, (char*)&new_address, sizeof(WORD));

}

void ChangeImageBase(PeHeaders* pe) {
	printf("New value (4 bytes): ");
	DWORD new_imagebase;
	scanf("%d", &new_imagebase);
	//sprintf((char*)&pe->nthead->OptionalHeader.ImageBase, "%s", (char*)&new_imagebase);
	memcpy((char*)&pe->nthead->OptionalHeader.ImageBase, (char*)&new_imagebase, sizeof(DWORD));

}

void ChangeSectionAlignment(PeHeaders* pe) {
	printf("New value (4 bytes): ");
	DWORD new_secalig;
	scanf("%d", &new_secalig);
	//sprintf((char*)&pe->nthead->OptionalHeader.SectionAlignment, "%s", (char*)&new_secalig);
	memcpy((char*)&pe->nthead->OptionalHeader.SectionAlignment, (char*)&new_secalig, sizeof(DWORD));

}

void ChangeFileAlignment(PeHeaders* pe) {
	printf("New value (4 bytes): ");
	DWORD new_filealig;
	scanf("%d", &new_filealig);
	//sprintf((char*)&pe->nthead->OptionalHeader.FileAlignment, "%s", (char*)&new_filealig);
	memcpy((char*)&pe->nthead->OptionalHeader.FileAlignment, (char*)&new_filealig, sizeof(DWORD));

}

void ChangeSizeOfImage(PeHeaders* pe) {
	printf("New value (4 bytes): ");
	DWORD new_size;
	scanf("%d", &new_size);
	//sprintf((char*)&pe->nthead->OptionalHeader.SizeOfImage, "%s", (char*)&new_size);
	memcpy((char*)&pe->nthead->OptionalHeader.SizeOfImage, (char*)&new_size, sizeof(DWORD));

}

void ChangeSizeOfHeaders(PeHeaders* pe) {
	printf("New value (4 bytes): ");
	DWORD new_size;
	scanf("%d", &new_size);
	//sprintf((char*)&pe->nthead->OptionalHeader.SizeOfHeaders, "%s", (char*)&new_size);
	memcpy((char*)&pe->nthead->OptionalHeader.SizeOfHeaders, (char*)&new_size, sizeof(DWORD));

}

void ChangeSubsystem(PeHeaders* pe) {
	printf("New value (2 bytes): ");
	WORD new_ss;
	scanf("%hd", &new_ss);
	//sprintf((char*)&pe->nthead->OptionalHeader.Subsystem, "%s", (char*)&new_ss);
	memcpy((char*)&pe->nthead->OptionalHeader.Subsystem, (char*)&new_ss, sizeof(WORD));

}

void ChangeNumberOfRvaAndSizes(PeHeaders* pe) {
	printf("New value (4 bytes): ");
	DWORD new_value;
	scanf("%d", &new_value);
	//sprintf((char*)&pe->nthead->OptionalHeader.NumberOfRvaAndSizes, "%s", (char*)&new_value);
	memcpy((char*)&pe->nthead->OptionalHeader.NumberOfRvaAndSizes, (char*)&new_value, sizeof(DWORD));

}

void EditTableSection(PeHeaders* peh) {
	DWORD i = 0, ch, secnum;
	WORD value;

	//вывод всех секций
	printf("There are 0x%x sections\n", peh->nthead->FileHeader.NumberOfSections);
	for (i = 0; i < peh->nthead->FileHeader.NumberOfSections; i++) {
		printf("0x%x section named %s\n", i, peh->sections[i].Name);
	}

	//Вводим номер нужной секции и вводим че надо поменять
	printf("Enter section number: ");
	scanf("%d", &secnum);
	printf("1. Name: %s\n", peh->sections[secnum].Name);
	printf("2. VA: 0x%x\n", peh->sections[secnum].VirtualAddress);
	printf("3. SizeOfRawData: 0x%x\n", peh->sections[secnum].SizeOfRawData);
	printf("4. PointerToRawData: 0x%x\n", peh->sections[secnum].PointerToRawData);
	printf("5. PointerToRelocations: 0x%x\n", peh->sections[secnum].PointerToRelocations);
	printf("6. PointerLineNumbers: 0x%x\n", peh->sections[secnum].PointerToLinenumbers);
	printf("7. NumberOfRelocations: 0x%x\n", peh->sections[secnum].NumberOfRelocations);
	printf("8. NumberOfLinenumbers: 0x%x\n", peh->sections[secnum].NumberOfLinenumbers);
	printf("9. Characteristics: 0x%x\n", peh->sections[secnum].Characteristics);
	printf("10. PhysicalAddress: 0x%x\n", peh->sections[secnum].Misc.PhysicalAddress);
	printf("11. VirtualSize: 0x%x\n", peh->sections[secnum].Misc.VirtualSize);

	printf("What to change: ");
	scanf("%d", &ch);
	if (ch == 1) {
		BYTE new_name[IMAGE_SIZEOF_SHORT_NAME];
		scanf("%s", &new_name);
		sprintf((char*)&peh->sections[secnum].Name, "%s", new_name); //здесь не трогать
	}
	else if (ch == 2) {
		scanf("%d", &ch);
		//sprintf((char*)&peh->sections[secnum].VirtualAddress, "%s", (char*)&ch);	//TODO: ЗАТИРАЕТ НУЖНЫЕ ЗНАЧЕНИЯ \0 В КОНЦЕ. ИСПРАВИТЬ
		memcpy((char*)&peh->sections[secnum].VirtualAddress, (char*)&ch, sizeof(DWORD));
	}
	else if (ch == 3) {
		scanf("%d", &ch);
		//sprintf((char*)&peh->sections[secnum].SizeOfRawData, "%s", (char*)&ch);
		memcpy((char*)&peh->sections[secnum].SizeOfRawData, (char*)&ch, sizeof(DWORD));

	}
	else if (ch == 4) {
		scanf("%d", &ch);
		//sprintf((char*)&peh->sections[secnum].PointerToRawData, "%s", (char*)&ch);
		memcpy((char*)&peh->sections[secnum].PointerToRawData, (char*)&ch, sizeof(DWORD));

	}
	else if (ch == 5) {
		scanf("%d", &ch);
		//sprintf((char*)&peh->sections[secnum].PointerToRelocations, "%s", (char*)&ch);
		memcpy((char*)&peh->sections[secnum].PointerToRelocations, (char*)&ch, sizeof(DWORD));

	}
	else if (ch == 6) {
		scanf("%d", &ch);
		//sprintf((char*)&peh->sections[secnum].PointerToLinenumbers, "%s", (char*)&ch);
		memcpy((char*)&peh->sections[secnum].PointerToLinenumbers, (char*)&ch, sizeof(DWORD));

	}
	else if (ch == 7) {
		scanf("%hd", &value);
		//sprintf((char*)&peh->sections[secnum].NumberOfRelocations, "%s", (char*)&value);
		memcpy((char*)&peh->sections[secnum].NumberOfRelocations, (char*)&value, sizeof(WORD));

	}
	else if (ch == 8) {
		scanf("%hd", &value);
		//sprintf((char*)&peh->sections[secnum].NumberOfLinenumbers, "%s", (char*)&value);
		memcpy((char*)&peh->sections[secnum].NumberOfLinenumbers, (char*)&value, sizeof(WORD));

	}
	else if (ch == 9) {
		scanf("%d", &ch);
		//sprintf((char*)&peh->sections[secnum].Characteristics, "%s", (char*)&ch);
		memcpy((char*)&peh->sections[secnum].Characteristics, (char*)&ch, sizeof(DWORD));

	}
	else if (ch == 10) {
		scanf("%d", &ch);
		//sprintf((char*)&peh->sections[secnum].Misc.PhysicalAddress, "%s", (char*)&ch);
		memcpy((char*)&peh->sections[secnum].Misc.PhysicalAddress, (char*)&ch, sizeof(DWORD));

	}
	else if (ch == 11) {
		scanf("%d", &ch);
		//sprintf((char*)&peh->sections[secnum].Misc.VirtualSize, "%s", (char*)&ch);
		memcpy((char*)&peh->sections[secnum].Misc.VirtualSize, (char*)&ch, sizeof(DWORD));

	}
}

void EditDataDirectory(PeHeaders* peh) {
	DWORD i = 0;

	for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		printf("%d. Size: %d. VA: %d\n", i, peh->nthead->OptionalHeader.DataDirectory[i].Size, peh->nthead->OptionalHeader.DataDirectory[i].VirtualAddress);
	}

	printf("What to reset: ");
	scanf("%d", &i);
	peh->nthead->OptionalHeader.DataDirectory[i].Size = 0;
	peh->nthead->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
}

void EditRelocs(PeHeaders* pe) {
	BYTE ch = 0, byte_value;
	DWORD offset = 0, value1, value2, old_size, old_va, i;
	WORD* base_reloc_offset;
	IMAGE_BASE_RELOCATION* reloc = pe->relocs_directory;

	while (offset < pe->reloc_directory_size) {
		printf("Size: 0x%x. VA: 0x%x\n", reloc->SizeOfBlock, reloc->VirtualAddress);
		printf("Modify? (Y/N): ");
		scanf(" %c", &ch);
		old_size = reloc->SizeOfBlock;
		old_va = reloc->VirtualAddress;
		if (ch == 'Y' || ch == 'y') {
			printf("New size: ");
			scanf("%x", &value1);
			reloc->SizeOfBlock = value1;

			printf("New VA: ");
			getchar();
			scanf("%x", &value2);
			reloc->VirtualAddress = value2;
		}
		base_reloc_offset = (WORD*)((DWORD)reloc + sizeof(IMAGE_BASE_RELOCATION));
		puts("Block data");
		for (i = 0; i < (old_size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i++) {
			printf("%d. Type: 0x%x. Offset: 0x%x\n", i, base_reloc_offset[i] >> 12, base_reloc_offset[i] & 0x0FFF);
		}
		printf("Modify any? (Y/N): ");
		scanf(" %c", &ch);
		while (ch == 'Y' || ch == 'y') {
			WORD tmp, tmp2;
			printf("Number to modify: ");
			scanf(" %d", &value1);

			printf("New type (4 bits): ");
			scanf(" %c", &byte_value);
			byte_value = byte_value << 4;
			tmp = base_reloc_offset[value1] & 0x0F;
			byte_value = byte_value + tmp;
			memset(&base_reloc_offset[value1], byte_value, 1);

			printf("New offset (12 bits): ");
			scanf(" %hi", &tmp);
			tmp = tmp & 0x0FFF;
			tmp2 = (base_reloc_offset[value1] & 0xF0) << 8;
			tmp = tmp + tmp2;
			memcpy(&base_reloc_offset[value1], &tmp, 2);
			
			printf("Modify more? (Y/N): ");
			scanf(" %c", &ch);
		}

		offset += old_size;
		reloc = (IMAGE_BASE_RELOCATION*)((DWORD)reloc + old_size);
	}

	//stackoverflow.com/questions/17436668/how-are-pe-base-relocations-build-up
}

void EditRelocs2(PeHeaders* pe) {
	DWORD offset = 0, value, i, *offset_value;
	WORD* base_reloc_offset;
	DWORD* tmp;
	IMAGE_BASE_RELOCATION* reloc = pe->relocs_directory;

	puts("Enter number to add: ");
	scanf("%d", &value);

	while (offset < pe->reloc_directory_size) {
		base_reloc_offset = (WORD*)((DWORD)reloc + sizeof(IMAGE_BASE_RELOCATION));
		offset_value = (DWORD*)(pe->mem + RvaToOffset(reloc->VirtualAddress, pe));
		for (i = 0; i < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i++) {
			tmp = (DWORD)offset_value + (DWORD)(base_reloc_offset[i] & 0x0FFF);
			*tmp = (DWORD)*tmp + value;

		}

		offset += reloc->SizeOfBlock;
		reloc = (IMAGE_BASE_RELOCATION*)((DWORD)reloc + reloc->SizeOfBlock);
	}

	pe->nthead->OptionalHeader.ImageBase = pe->nthead->OptionalHeader.ImageBase + value;

}

DWORD _GetSectionNumber(PeHeaders* pe) {
	DWORD sections = 0, offset = 0;
	IMAGE_BASE_RELOCATION* reloc = pe->relocs_directory;
	while (offset < pe->reloc_directory_size) {
		sections++;
		offset += reloc->SizeOfBlock;
		reloc = (IMAGE_BASE_RELOCATION*)((DWORD)reloc + reloc->SizeOfBlock);
	}
	return sections;
}

void _FillBlockElementsCounters(PeHeaders* pe, DWORD* arr, const DWORD len) {
	DWORD current_section = 0, i = 0, cntr = 0;
	IMAGE_BASE_RELOCATION* reloc = pe->relocs_directory;
	WORD* base_reloc_offset;

	while (cntr < len) {
		DWORD free_cntr = 0;
		base_reloc_offset = (WORD*)((DWORD)reloc + sizeof(IMAGE_BASE_RELOCATION));
		for (i = 0; i < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i++) {
			if (!(base_reloc_offset[i] >> 12)) {
				free_cntr++;
			}
		}

		arr[cntr++] = free_cntr;

		reloc = (IMAGE_BASE_RELOCATION*)((DWORD)reloc + reloc->SizeOfBlock);
	}
}

BOOL _PrintRelocSectionsAndCheckForFree(const DWORD* arr, const DWORD len) {
	DWORD i = 0;
	BOOL res = 0;
	for (i = 0; i < len; i++) {
		printf("Section %d has %d free relocs\n", i, arr[i]);
		if (arr[i]) {
			res = 1;
		}
	}

	return res;
}

void EditRelocs3(PeHeaders* pe) {
	BYTE ch = 0, byte_value, there_is_free_reloc = 0;
	DWORD offset = 0, i;
	WORD* base_reloc_offset;
	IMAGE_BASE_RELOCATION* reloc = pe->relocs_directory;
	DWORD current_section = 0;
	DWORD* free_relocs;

	DWORD sections = _GetSectionNumber(pe);
	free_relocs = (DWORD*)malloc(sections * sizeof(DWORD));
	_FillBlockElementsCounters(pe, free_relocs, sections);
	there_is_free_reloc = _PrintRelocSectionsAndCheckForFree(free_relocs, sections);

	if (there_is_free_reloc) {
		printf("Edit any free reloc or insert new? (F - for free/N - for new): ");
		scanf("%c", &ch);
		if (ch == 'F' || ch == 'f') {
			DWORD secnum;
			do {
				printf("Enter section number: ");
				scanf("%d", &secnum);
			} while (!free_relocs[secnum]);

			current_section = 0;
			while (offset < pe->reloc_directory_size) {
				base_reloc_offset = (WORD*)((DWORD)reloc + sizeof(IMAGE_BASE_RELOCATION));
				if (current_section == secnum) {
					for (i = 0; i < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i++) {
						if (!(base_reloc_offset[i] >> 12)) {
							WORD tmp, tmp2;
							printf("New type (4 bits): ");
							scanf(" %c", &byte_value);
							byte_value = byte_value << 4;
							tmp = base_reloc_offset[i] & 0x0F;
							byte_value = byte_value + tmp;
							memset(&base_reloc_offset[i], byte_value, 1);

							printf("New offset (12 bits): ");
							getchar();
							scanf(" %hd", &tmp);
							tmp = tmp & 0x0FFF;
							tmp2 = (base_reloc_offset[i] & 0xF0) << 8;
							tmp = tmp + tmp2;
							memcpy(&base_reloc_offset[i], &tmp, 2);

							free_relocs[secnum]--;
							break;
						}
					}
				}

				offset += reloc->SizeOfBlock;
				reloc = (IMAGE_BASE_RELOCATION*)((DWORD)reloc + reloc->SizeOfBlock);
				current_section++;
			}
		}
		else if (ch == 'N' || ch == 'n') {
			DWORD secnum, cntr = 0, size, last_va = 0;
			printf("Enter section number where to insert: ");
			scanf("%d", &secnum);
			while (offset < pe->reloc_directory_size) {
				base_reloc_offset = (WORD*)((DWORD)reloc + sizeof(IMAGE_BASE_RELOCATION));
				if (secnum == cntr) {

					DWORD write_here;
					IMAGE_BASE_RELOCATION new_reloc;

					ExtendFileSizeCreatingNewSectionNeededSize(pe, pe->reloc_directory_size + sizeof(WORD));
					write_here = pe->mem + RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe);

					memcpy(write_here, (DWORD*)pe->relocs_directory, offset);
					size = reloc->SizeOfBlock;
					reloc->SizeOfBlock += sizeof(WORD);
					memcpy(write_here + offset, (DWORD*)reloc, size);

					WORD insert, tmp;
					DWORD where_to_place = 0;
					printf("New type (4 bits): ");
					scanf(" %hd", &tmp);
					insert = tmp << 12;
					printf("New offset (12 bits): ");
					scanf(" %hd", &tmp);
					insert = insert + (tmp & 0x0FFF);
					memcpy(write_here + offset + size, &insert, sizeof(WORD));

					memcpy(write_here + offset + reloc->SizeOfBlock, (DWORD)reloc + size, pe->reloc_directory_size - offset - size);

					pe->reloc_directory_size += sizeof(WORD);
					pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += sizeof(WORD);
					pe->relocs_directory = write_here;
					pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = pe->sections[pe->countSec - 1].VirtualAddress;
					break;
				}

				cntr++;
				offset += reloc->SizeOfBlock;
				last_va = reloc->VirtualAddress;
				reloc = (IMAGE_BASE_RELOCATION*)((DWORD)reloc + reloc->SizeOfBlock);
			}
		}
	}

	free(free_relocs);
}

void EditRelocs3NewBlock(PeHeaders* pe) {
	DWORD offset = 0, size, last_va = 0;
	IMAGE_BASE_RELOCATION* reloc = pe->relocs_directory;
	WORD* base_reloc_offset;

	printf("Enter new header size: ");
	scanf("%d", &size);
	while (offset < pe->reloc_directory_size) {
		offset += reloc->SizeOfBlock;
		last_va = reloc->VirtualAddress;
		reloc = (IMAGE_BASE_RELOCATION*)((DWORD)reloc + reloc->SizeOfBlock);
	}

	int flag = 1;
	base_reloc_offset = (WORD*)((DWORD)reloc);
	for (int i = 0; i < size; i++) {
		if (base_reloc_offset[i] == 0 || base_reloc_offset[i] == NULL) {
			continue;
		}
		else {
			flag = 0;
			break;
		}
	}
	if (flag == 1) {
		IMAGE_BASE_RELOCATION new_reloc;
		new_reloc.SizeOfBlock = size;
		new_reloc.VirtualAddress = last_va + pe->nthead->OptionalHeader.SectionAlignment;
		memcpy(reloc, &new_reloc, sizeof(new_reloc));
		pe->reloc_directory_size += size;
		pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += size;
	}
	else {
		DWORD write_here;
		IMAGE_BASE_RELOCATION new_reloc;
		
		ExtendFileSizeCreatingNewSectionNeededSize(pe, pe->reloc_directory_size + size);
		write_here = pe->mem + RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe);
		
		memcpy(write_here, (DWORD*)pe->relocs_directory, pe->reloc_directory_size);
		
		new_reloc.SizeOfBlock = size;
		new_reloc.VirtualAddress = last_va + pe->nthead->OptionalHeader.SectionAlignment;
		memcpy(write_here + pe->reloc_directory_size, &new_reloc, sizeof(new_reloc));
		
		pe->reloc_directory_size += size;
		pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += size;
		pe->relocs_directory = write_here;
		pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = pe->sections[pe->countSec - 1].VirtualAddress;

	}
}

void EditImportTable(PeHeaders* pe) {
	if (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
		IMAGE_IMPORT_DESCRIPTOR* imp = pe->impdir;
		DWORD j, write_here;
		BYTE ch;

		while (imp->FirstThunk || imp->Characteristics || imp->ForwarderChain || imp->Name || imp->OriginalFirstThunk || imp->TimeDateStamp) {
			LONG_PTR* iat;
			printf("Name: %s\n", pe->mem + RvaToOffset(imp->Name, pe));
			printf("New name? (Y/N): ");
			scanf(" %c", &ch);
			if (ch == 'y' || ch == 'Y') {
				WORD len = strlen(pe->mem + RvaToOffset(imp->Name, pe));
				char* new_name = (char*)calloc(100, sizeof(char));
				printf("New name (100 bytes max.): ");
				scanf("%s", new_name);
				if (strlen(new_name) > len) {
					ExtendFileSizeCreatingNewSection(pe);
					write_here = RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe);
					memcpy(pe->mem + write_here, new_name, 100);
					imp->Name = pe->sections[pe->countSec - 1].VirtualAddress;
				}
				else {
					sprintf((char*)pe->mem + RvaToOffset(imp->Name, pe), "%s", new_name);
				}

				free(new_name);
			}
			printf("TimeDateStamp: 0x%x\n", imp->TimeDateStamp);
			printf("Edit? (Y/N): ");
			scanf(" %c", &ch);
			if (ch == 'y' || ch == 'Y') {
				DWORD new_value;
				printf("New timestamp: ");
				scanf(" %d", &new_value);
				imp->TimeDateStamp = new_value;
			}
			printf("Characteristics: 0x%x\n", imp->Characteristics);
			printf("Edit? (Y/N): ");
			scanf(" %c", &ch);
			if (ch == 'y' || ch == 'Y') {
				DWORD new_value;
				printf("New characteristics: ");
				scanf(" %x", &new_value);
				imp->Characteristics = new_value;
			}
			if (imp->OriginalFirstThunk) {
				iat = (LONG_PTR*)(pe->mem + RvaToOffset(imp->OriginalFirstThunk, pe));
			}
			else {
				iat = (LONG_PTR*)(pe->mem + RvaToOffset(imp->FirstThunk, pe));
			}
			printf("Forwarded chain: %d\n", pe->mem + RvaToOffset(imp->ForwarderChain, pe));
			for (j = 0; iat[j]; ++j) {
				if (pe->pe32plus) {
					if (iat[j] & 0x8000000000000000) {
						printf("%d. Ordinal: %d\n", j, iat[j] & 0x000000000000FFFF);
					}
					else {
						printf("%d. Name: %s\n", j, (char*)(pe->mem + RvaToOffset(iat[j], pe) + 2));
					}
				}
				else {
					if (iat[j] & 0x80000000) {
						printf("%d. Ordinal: %d\n", j, iat[j] & 0x0000FFFF);
					}
					else {
						printf("%d. Name: %s\n", j, (char*)(pe->mem + RvaToOffset(iat[j], pe) + 2));
					}
				}

			}

			printf("Modify any? (Y/N): ");
			scanf(" %c", &ch);
			if (ch == 'y' || ch == 'Y') {
				WORD lib_number, len;
				printf("Enter number to modify (0 - %d): ", j - 1);
				scanf("%hd", &lib_number);

				char* new_name = (char*)calloc(100, sizeof(char));
				printf("New name (100 bytes max.): ");
				scanf("%s", new_name);

				len = strlen(pe->mem + RvaToOffset(iat[lib_number], pe) + 2);

				if (strlen(new_name) > len) {
					ExtendFileSizeCreatingNewSection(pe);
					write_here = RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe) + 2;
					memcpy(pe->mem + write_here, new_name, strlen(new_name));
					iat[lib_number] = pe->sections[pe->countSec - 1].VirtualAddress + 2;
				}
				else {
					memcpy(pe->mem + RvaToOffset(iat[lib_number], pe) + 2, new_name, len);
				}

				free(new_name);
			}

			imp++;
		}
	}
}

void EditImportTable2(PeHeaders* pe) {
	if (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
		IMAGE_IMPORT_DESCRIPTOR* imp = pe->impdir;
		DWORD j;
		BYTE ch, got_this_from_original_first_thunk;

		while (imp->FirstThunk || imp->Characteristics || imp->ForwarderChain || imp->Name || imp->OriginalFirstThunk || imp->TimeDateStamp) {
			LONG_PTR* iat;
			if (imp->OriginalFirstThunk) {
				iat = (LONG_PTR*)(pe->mem + RvaToOffset(imp->OriginalFirstThunk, pe));
				got_this_from_original_first_thunk = 1;
			}
			else {
				iat = (LONG_PTR*)(pe->mem + RvaToOffset(imp->FirstThunk, pe));
				got_this_from_original_first_thunk = 0;
			}
			printf("%s\n", pe->mem + RvaToOffset(imp->Name, pe));
			printf("Add function? (Y/N): ");
			scanf(" %c", &ch);
			if (ch == 'y' || ch == 'Y') {
				WORD new_hint;
				DWORD write_here, new_iat;
				DWORD tmp;
				for (j = 0; iat[j]; ++j) {
					if (iat[j] & 0x80000000) {
						printf("%d. Ordinal: %d\n", j, iat[j] & 0x0000FFFF);
					}
					else {
						printf("%d. Name: %s\n", j, (char*)(pe->mem + RvaToOffset(iat[j], pe) + 2));
					}
				}
				char* new_name = (char*)calloc(1024, sizeof(char));
				printf("New name: ");
				scanf("%s", new_name);
				printf("New hint: ");
				scanf("%hd", &new_hint);

				ExtendFileSizeCreatingNewSectionNeededSize(pe, (j + 2) * sizeof(LONG_PTR*) + strlen(new_name) + 2);
				write_here = RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe);
				new_iat = pe->sections[pe->countSec - 1].VirtualAddress;
				memcpy(pe->mem + write_here, iat, j * sizeof(LONG_PTR*));

				memcpy(pe->mem + write_here + (j + 2) * sizeof(LONG_PTR*), &new_hint, sizeof(LONG_PTR*));
				memcpy(pe->mem + write_here + (j + 2) * sizeof(LONG_PTR*) + 2, new_name, strlen(new_name));
				tmp = pe->sections[pe->countSec - 1].VirtualAddress + (j + 2) * sizeof(LONG_PTR*);
				memcpy(pe->mem + write_here + j * sizeof(LONG_PTR*), &tmp, sizeof(LONG_PTR*));
				free(new_name);

				if (got_this_from_original_first_thunk) {
					memcpy(&pe->impdir->OriginalFirstThunk, &new_iat, sizeof(DWORD));
				}
				else {
					memcpy(&pe->impdir->OriginalFirstThunk, &new_iat, sizeof(DWORD));
				}
			}
			imp++;
		}
	}
}

void EditImportTable2Header(PeHeaders* pe) {
	if (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
		DWORD write_here;
		IMAGE_IMPORT_DESCRIPTOR* imp = NULL;
		DWORD new_chars, old_size;
		BYTE ch;

		ExtendFileSizeCreatingNewSectionNeededSize(pe, pe->sizeImpdir + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		write_here = RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe);
		old_size = pe->sizeImpdir;
		memcpy(pe->mem + write_here, pe->impdir, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pe->sections[pe->countSec - 1].VirtualAddress;
		pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		imp = (IMAGE_IMPORT_DESCRIPTOR*)(pe->mem + write_here + old_size);
		printf("You need to set a non-null value to the Characteristics field to consider the new import desc. is not the last: ");
		scanf("%d", &new_chars);
		if (new_chars == 0) {
			imp->Characteristics = 1;
		}
		else {
			imp->Characteristics = new_chars;
		}
		printf("Do you want to initialize other fields? (Y/N): ");
		scanf(" %c", &ch);
		if (ch == 'y' || ch == 'Y') {
			DWORD value;
			BYTE* new_name = (BYTE*)(pe->mem + RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe) + pe->sizeImpdir + sizeof(IMAGE_IMPORT_DESCRIPTOR) + 4);
			printf("TimeDateStamp: ");
			scanf("%d", &value);
			imp->TimeDateStamp = value;
			printf("Forwarded chain: ");
			scanf("%d", &value);
			imp->ForwarderChain = value;
			printf("FirstThunk: ");
			scanf("%d", &value);
			imp->FirstThunk = value;
			printf("Name: ");
			scanf("%s", new_name);
			imp->Name = pe->sections[pe->countSec - 1].VirtualAddress + pe->sizeImpdir + sizeof(IMAGE_IMPORT_DESCRIPTOR) + 4;
		}
	}
}

void EditImportTable3(PeHeaders* pe) {
	if (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
		IMAGE_BOUND_IMPORT_DESCRIPTOR ibid;
		pe->impdir->TimeDateStamp = -1;
		pe->impdir->ForwarderChain = -1;
		ExtendFileSizeCreatingNewSectionNeededSize(pe, sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR));
		pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = pe->sections[pe->countSec - 1].VirtualAddress;
		pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);
		//перенести куда-то секции?

	}

}

void EditExportTable(PeHeaders* pe) {
	if (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
		IMAGE_EXPORT_DIRECTORY* exp = pe->expdir;
		BYTE ch;
		DWORD* functionsArray;
		DWORD* namesArray;
		WORD* nameOrdinalsArray;
		DWORD i;

		printf("%s\n", pe->mem + RvaToOffset(exp->Name, pe));
		printf("New name? (Y/N): ");
		scanf(" %c", &ch);
		if (ch == 'y' || ch == 'Y') {
			WORD len = strlen(pe->mem + RvaToOffset(exp->Name, pe));
			char* new_name = (char*)calloc(100, sizeof(char));
			printf("New name (100 bytes max.): ");
			scanf("%s", new_name);
			if (strlen(new_name) > len) {
				DWORD write_here;
				ExtendFileSizeCreatingNewSection(pe);
				write_here = RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe);
				memcpy(pe->mem + write_here, new_name, 100);
				exp->Name = pe->sections[pe->countSec - 1].VirtualAddress;
			}
			else {
				sprintf((char*)&pe->nthead->OptionalHeader.FileAlignment, "%s", (char*)&new_name);
			}

			free(new_name);
		}

		functionsArray = (DWORD*)(pe->mem + RvaToOffset(exp->AddressOfFunctions, pe));

		namesArray = (DWORD*)(pe->mem + RvaToOffset(exp->AddressOfNames, pe));

		nameOrdinalsArray = (WORD*)(pe->mem + RvaToOffset(exp->AddressOfNameOrdinals, pe));

		for (i = 0; i < exp->NumberOfNames; ++i) {
			printf("%d. ", i);
			printf("%s\t", pe->mem + RvaToOffset(namesArray[i], pe));
			printf("0x%x\n", functionsArray[nameOrdinalsArray[i]]);
		}
		printf("Modify function name? (Y/N): ");
		scanf(" %c", &ch);
		if (ch == 'y' || ch == 'Y') {
			DWORD write_here;
			WORD len, number;
			char* new_name = (char*)calloc(100, sizeof(char));
			printf("Number to modify: ");
			scanf("%hd", &number);
			len = strlen(pe->mem + RvaToOffset(namesArray[number], pe));
			printf("New name (100 bytes max.): ");
			scanf("%s", new_name);
			if (strlen(new_name) > len) {
				ExtendFileSizeCreatingNewSection(pe);
				write_here = RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe);
				memcpy(pe->mem + write_here, new_name, 100);
				memcpy(&namesArray[number], &pe->sections[pe->countSec - 1].VirtualAddress, sizeof(DWORD));
			}
			else {
				DWORD tmp = RvaToOffset(namesArray[number], pe);
				sprintf(tmp + pe->mem, "%s", new_name);
			}
		}

		printf("Modify address name? (Y/N): ");
		scanf(" %c", &ch);
		if (ch == 'y' || ch == 'Y') {
			WORD number;
			DWORD new_address;
			printf("Number to modify: ");
			scanf("%hd", &number);
			printf("New address: ");
			scanf("%d", &new_address);
			memcpy(&functionsArray[nameOrdinalsArray[number]], &new_address, sizeof(DWORD));
		}
	}
}

void EditExportTable2(PeHeaders* pe) {
	if (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
		IMAGE_EXPORT_DIRECTORY* exp;
		DWORD* namesArray;
		DWORD i;
		BYTE ch;

		exp = pe->expdir;

		// указатель на массив адресов имён функций
		DWORD offset_to_address_of_names = RvaToOffset(exp->AddressOfNames, pe);
		namesArray = (DWORD*)(pe->mem + offset_to_address_of_names);

		DWORD size_of_names_array = 0;
		DWORD* addresses_of_funcs = (DWORD*)malloc(sizeof(DWORD) * exp->NumberOfNames); //смещения до имен

		for (i = 0; i < exp->NumberOfNames; ++i) {
			DWORD offset = RvaToOffset(namesArray[i], pe); //получили смещение
			printf("%d. %s\n", i, pe->mem + offset);
			size_of_names_array = size_of_names_array + strlen(pe->mem + offset) + 1; //размер + \0
			addresses_of_funcs[i] = offset; //записали
		}

		printf("Add function? (Y/N): ");
		scanf("%c", &ch);
		if (ch == 'y' || ch == 'Y') {
			const DWORD max_bytes = 100;
			char* new_name = (char*)calloc(max_bytes, sizeof(char));
			//На размер имен + на новое имя + на массив указателей на имена
			ExtendFileSizeCreatingNewSectionNeededSize(pe, size_of_names_array + max_bytes + exp->NumberOfNames * sizeof(DWORD));
			DWORD write_here = RvaToOffset(pe->sections[pe->countSec - 1].VirtualAddress, pe);
			DWORD offset = 0;
			printf("New name (100 bytes max.): ");
			scanf("%s", new_name);
			size_of_names_array = size_of_names_array + strlen(new_name) + 1;
			//Перемещаем имена
			DWORD tmp = 0;
			for (i = 0; i < exp->NumberOfNames; i++) {
				DWORD len = strlen(pe->mem + addresses_of_funcs[i]);
				tmp = offset + pe->sections[pe->countSec - 1].VirtualAddress;
				memcpy(pe->mem + write_here + offset, pe->mem + addresses_of_funcs[i], len);
				memcpy(pe->mem + write_here + size_of_names_array + i * sizeof(DWORD), &tmp, sizeof(DWORD));
				offset = offset + len + 1;
			}

			tmp = offset + pe->sections[pe->countSec - 1].VirtualAddress;
			memcpy(pe->mem + write_here + offset, new_name, strlen(new_name));
			memcpy(pe->mem + write_here + size_of_names_array + i * sizeof(DWORD), &tmp, sizeof(DWORD));

			exp->NumberOfNames++;

			tmp = size_of_names_array + pe->sections[pe->countSec - 1].VirtualAddress;
			memcpy(&pe->expdir->AddressOfNames, &tmp, sizeof(DWORD));

			free(new_name);
		}

		free(addresses_of_funcs);
	}
}

DWORD _RoundUpToNumber(DWORD round_this, const DWORD border) {
	DWORD num = round_this + (border - 1);
	return num - (num % border);
}

DWORD _CalculateNewVA(PeHeaders* pe, const DWORD border) {
	DWORD last_addr, last_size;
	if (pe->countSec > 2) {
		last_addr = pe->sections[pe->nthead->FileHeader.NumberOfSections - 2].VirtualAddress;
		last_size = pe->sections[pe->nthead->FileHeader.NumberOfSections - 2].Misc.VirtualSize;
	}
	else {
		last_addr = 0;
		last_size = 0;
	}

	return _RoundUpToNumber(last_addr + last_size, border);
}

DWORD _CalculateNewRawAddress(PeHeaders* pe, const DWORD border) {
	DWORD last_addr, last_size;
	if (pe->countSec > 2) {
		last_addr = pe->sections[pe->nthead->FileHeader.NumberOfSections - 2].PointerToRawData;
		last_size = pe->sections[pe->nthead->FileHeader.NumberOfSections - 2].SizeOfRawData;
	}
	else {
		last_addr = 0;
		last_size = 0;
	}

	return _RoundUpToNumber(last_addr + last_size, border);
}

DWORD ExtendFileSizeCreatingNewSection(PeHeaders* pe) {
	const char* new_name = ".custom";
	const DWORD raw_size = pe->nthead->OptionalHeader.FileAlignment;
	const DWORD virtual_size = pe->nthead->OptionalHeader.SectionAlignment;

	pe->nthead->FileHeader.NumberOfSections++;
	pe->countSec++;
	memcpy(pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].Name, new_name, sizeof(new_name));

	pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].Misc.VirtualSize = raw_size;
	//pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].Misc.VirtualSize = virtual_size;
	pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].VirtualAddress = _CalculateNewVA(pe, virtual_size);

	pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].SizeOfRawData = raw_size;
	pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].PointerToRawData = _CalculateNewRawAddress(pe, raw_size);

	pe->nthead->OptionalHeader.SizeOfImage = _RoundUpToNumber(pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].VirtualAddress + virtual_size, pe->nthead->OptionalHeader.SectionAlignment);
	pe->filesize = pe->filesize + raw_size;
	pe->mapd = CreateFileMapping(pe->fd, NULL, PAGE_READWRITE, 0, pe->filesize, NULL);
	pe->mem = (PBYTE)MapViewOfFile(pe->mapd, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	return raw_size;
}

DWORD ExtendFileSizeCreatingNewSectionNeededSize(PeHeaders* pe, const DWORD size) {
	char* new_name = ".custom";
	DWORD raw_size = pe->nthead->OptionalHeader.FileAlignment;
	DWORD virtual_size = pe->nthead->OptionalHeader.SectionAlignment, i = 1;

	do {
		raw_size = raw_size * i;
		i++;
	} while (raw_size < size);

	pe->nthead->FileHeader.NumberOfSections++;
	pe->countSec++;
	memcpy(pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].Name, new_name, sizeof(new_name));

	pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].Misc.VirtualSize = raw_size;
	//pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].Misc.VirtualSize = virtual_size;
	pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].VirtualAddress = _CalculateNewVA(pe, virtual_size);

	pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].SizeOfRawData = raw_size;
	pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].PointerToRawData = _CalculateNewRawAddress(pe, raw_size);

	pe->nthead->OptionalHeader.SizeOfImage = _RoundUpToNumber(pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].VirtualAddress + virtual_size, pe->nthead->OptionalHeader.SectionAlignment);
	pe->filesize = pe->filesize + raw_size;
	pe->mapd = CreateFileMapping(pe->fd, NULL, PAGE_READWRITE, 0, pe->filesize, NULL);
	pe->mem = (PBYTE)MapViewOfFile(pe->mapd, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	return raw_size;
}

void ExtendFileSize(PeHeaders* pe) {
	char new_name[8] = {0};
	DWORD raw_size, virtual_size, i;

	printf("Enter new section name (8 bytes): ");
	scanf("%s", &new_name);

	printf("FileAligment: 0x%x\n", pe->nthead->OptionalHeader.FileAlignment);
	puts("Enter new raw size. It must be divisible by FileAligment");
	printf("For example: %d\n", pe->nthead->OptionalHeader.FileAlignment * (1 + rand() % 4));

	do {
		printf("-> ");
		scanf("%d", &raw_size);
	} while (raw_size % pe->nthead->OptionalHeader.FileAlignment != 0);

	printf("SectionAlignment: 0x%x\n", pe->nthead->OptionalHeader.SectionAlignment);
	puts("Enter new virtual size. It must be divisible by SectionAlignment");
	printf("For example: %d\n", pe->nthead->OptionalHeader.SectionAlignment * (1 + rand() % 4));

	do {
		printf("-> ");
		scanf("%d", &virtual_size);
	} while (virtual_size % pe->nthead->OptionalHeader.FileAlignment != 0);

	printf("name      VirtAddr  VirtSize  RawAddr   RawSize   Character\n");
	for (i = 0; i < pe->countSec; ++i) {
		printf("%-8s  ", &pe->sections[i].Name);
		printf("%p  ", pe->sections[i].VirtualAddress);
		printf("%p  ", pe->sections[i].Misc.VirtualSize);
		printf("%p  ", pe->sections[i].PointerToRawData);
		printf("%p  ", pe->sections[i].SizeOfRawData);
		printf("%p\n", pe->sections[i].Characteristics);
	}
	printf("\n");

	pe->nthead->FileHeader.NumberOfSections++;
	pe->countSec++;
	memcpy(pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].Name, new_name, sizeof(new_name));

	pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].Misc.VirtualSize = raw_size;
	//pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].Misc.VirtualSize = virtual_size;
	pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].VirtualAddress = _CalculateNewVA(pe, virtual_size);

	pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].SizeOfRawData = raw_size;
	pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].PointerToRawData = _CalculateNewRawAddress(pe, raw_size);

	pe->nthead->OptionalHeader.SizeOfImage = _RoundUpToNumber(pe->sections[pe->nthead->FileHeader.NumberOfSections - 1].VirtualAddress + virtual_size, pe->nthead->OptionalHeader.SectionAlignment);
	pe->filesize = pe->filesize + raw_size;
	pe->mapd = CreateFileMapping(pe->fd, NULL, PAGE_READWRITE, 0, pe->filesize, NULL);
	pe->mem = (PBYTE)MapViewOfFile(pe->mapd, FILE_MAP_ALL_ACCESS, 0, 0, 0);
}
