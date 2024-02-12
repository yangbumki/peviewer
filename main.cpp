#include <Windows.h>
#include <iostream>

#define BUFSIZE		1024

char* FILE_PATH = (char*)"C:\\Users\\ybeom\\OneDrive\\바탕 화면\\messageboxA.exe";

#define YES					1
#define NO					2

#define DOS_HEADER			1
#define FILE_HEADER			2
#define OPTIONAL_HEADER		3
#define SECTION_HEADERS		4

#define SELECT_MIN			1
#define SELECT_MAX			4

#define IMAGE_OPTIONALHEADER IMAGE_OPTIONAL_HEADER32

void ConvetEndian(char* endi, int size);
void PrintingDosHeader(IMAGE_DOS_HEADER* idh);
void PrintingFileHeader(IMAGE_FILE_HEADER* ifh);
void PrintingOptionalHeader(IMAGE_OPTIONALHEADER* ioh);
void PrintingSectionHeader(IMAGE_SECTION_HEADER* ish);

using namespace std;

int main(int argc, char* argv[]) {
	if (argc > 1) {
		FILE_PATH = argv[1];
		/*int cmp = strcmp(argv[2], "32");
		if (cmp == 0) typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONALHEADER;
		else {
			cmp = strcmp(argv[2], "64");
			if (cmp != 0) {
				printf("Argument Error : %s", argv[2]);
				exit(1);
			};
			typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONALHEADER;
		};*/
	};

	OFSTRUCT of;
	HFILE fileHandle = NULL;
	char fileReadBuf[BUFSIZE] = { 0, };
	bool errorStat = false;
	int startAddr = 0;
	IMAGE_DOS_HEADER		idh;
	IMAGE_FILE_HEADER		ifh;
	IMAGE_OPTIONALHEADER	ioh;
	IMAGE_SECTION_HEADER	ish;

	const int dosHeaderSize = sizeof(IMAGE_DOS_HEADER);
	const int fileHeaderSize = sizeof(IMAGE_FILE_HEADER);
	const int optionalHeaderSize = sizeof(IMAGE_OPTIONALHEADER);
	const int sectionHeaderSize = sizeof(IMAGE_SECTION_HEADER);


	int input = 0;

	memset(&of, 0, sizeof(OFSTRUCT));

	fileHandle = OpenFile(FILE_PATH, &of, OF_READ);
	if (fileHandle == NULL) {
		cout << "File Open Failed" << endl;
		exit(1);
	};

	memset(fileReadBuf, 0, BUFSIZE);
	if (!ReadFile((HANDLE)fileHandle, fileReadBuf, BUFSIZE, NULL, NULL)) {
		cout << "ReadFile Failed" << endl;
		exit(1);
	};

	memset(&idh, 0, dosHeaderSize);
	memset(&ifh, 0, fileHeaderSize);
	memset(&ioh, 0, optionalHeaderSize);
	memset(&ish, 0, sectionHeaderSize);

	while (1) {
		cout << "[SELECT HEADER]" << endl << endl;
		cout << "1. DOS_HEADER" << endl;
		cout << "2. FILE_HEADER" << endl;
		cout << "3. OPTIONAL_HEADER" << endl;
		cout << "4. SECTION_HEADERS" << endl;
		cout << "입력 : ";  cin >> input;
		printf("\n");
		if (input < SELECT_MIN || input > SELECT_MAX) {
			cout << "Wrong Select" << endl; cout << "Re Select?" << endl;
			cout << "1. Y 2. N " << endl; cin >> input;
			if (input == NO) {
				cout << "okay goodbye" << endl;
				break;
			}
			else if (input == YES) continue;
		};

		switch (input) {
		case DOS_HEADER:
			memset(&idh, 0, dosHeaderSize);
			memcpy_s(&idh, dosHeaderSize, fileReadBuf, dosHeaderSize);
			PrintingDosHeader(&idh);

			break;

		case FILE_HEADER:
			if (idh.e_lfanew == NULL) {
				memset(&idh, 0, dosHeaderSize);
				memcpy_s(&idh, dosHeaderSize, fileReadBuf, dosHeaderSize);
			}
			startAddr = idh.e_lfanew + sizeof(IMAGE_NT_HEADERS::Signature);
			memset(&ifh, 0, fileHeaderSize);
			memcpy_s(&ifh, fileHeaderSize, fileReadBuf + startAddr, fileHeaderSize);
			PrintingFileHeader(&ifh);
			break;

		case OPTIONAL_HEADER:
			if (idh.e_lfanew == NULL) {
				memset(&idh, 0, dosHeaderSize);
				memcpy_s(&idh, dosHeaderSize, fileReadBuf, dosHeaderSize);
			}
			startAddr = idh.e_lfanew + sizeof(IMAGE_NT_HEADERS::Signature) + fileHeaderSize;
			memset(&ioh, 0, optionalHeaderSize);
			memcpy_s(&ioh, optionalHeaderSize, fileReadBuf + startAddr, optionalHeaderSize);
			PrintingOptionalHeader(&ioh);
			break;

		case SECTION_HEADERS:
			if (ifh.NumberOfSections == NULL) {
				if (idh.e_lfanew == NULL) {
					memset(&idh, 0, dosHeaderSize);
					memcpy_s(&idh, dosHeaderSize, fileReadBuf, dosHeaderSize);
				};
				startAddr = idh.e_lfanew + sizeof(IMAGE_NT_HEADERS::Signature);
				memset(&ifh, 0, fileHeaderSize);
				memcpy_s(&ifh, fileHeaderSize, fileReadBuf + startAddr, fileHeaderSize);
			};
			cout << "Section total Number : " << ifh.NumberOfSections<<endl;
			cout << "입력 : "; cin >> input;
			if (input > ifh.NumberOfSections) {
				cout << "Wrong Select "; 
				break;
			};
			input--;
			startAddr = idh.e_lfanew + sizeof(IMAGE_NT_HEADERS::Signature) + fileHeaderSize + optionalHeaderSize + (sectionHeaderSize* input);
			memset(&ish, 0, sectionHeaderSize);
			memcpy_s(&ish, sectionHeaderSize, fileReadBuf + startAddr, sectionHeaderSize);

			PrintingSectionHeader(&ish);
			break;

		default:
			break;
		};
		printf_s("\n");
		if (errorStat == true) break;
	};
	CloseHandle((HANDLE)fileHandle);
	return 0;
};

void ConvetEndian(char* endi, int size) {
	char* temp = new char[size];

	for (int i = 0; i < size; i++) temp[i] = endi[size - 1 - i];

	memcpy_s(endi, size, temp, size);
};

void PrintingDosHeader(IMAGE_DOS_HEADER* idh) {
	ConvetEndian((char*)&idh->e_magic, sizeof(idh->e_magic));;
	//ConvetEndian((char*)&idh->e_lfanew, sizeof(idh->e_lfanew));
	cout << "[DOS_HEADER]" << endl;
	printf_s("MAGIC: %x\n", idh->e_magic);
	printf_s("NT_HEADER: %x\n", idh->e_lfanew);
};

void PrintingFileHeader(IMAGE_FILE_HEADER* ifh) {
	ConvetEndian((char*)&ifh->Characteristics, sizeof(ifh->Characteristics));
	//ConvetEndian((char*)&ifh->Machine, sizeof(ifh->Machine));
	//ConvetEndian((char*)&ifh->NumberOfSections, sizeof(ifh->NumberOfSections));
	//ConvetEndian((char*)&ifh->SizeOfOptionalHeader, sizeof(ifh->SizeOfOptionalHeader));

	cout << "[FILE_HEADER]" << endl;
	printf_s("MACHINE : %x\n", ifh->Machine);
	printf_s("Characteristics : %x\n", ifh->Characteristics);
	printf_s("NumberOfSections : %x\n", ifh->NumberOfSections);
	printf_s("SizeOfOptionalHeader: %x\n", ifh->SizeOfOptionalHeader);
};

void PrintingOptionalHeader(IMAGE_OPTIONALHEADER* ioh) {
	//#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
	//#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
	//#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
	//#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
	//#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
	//#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
	//#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
	//	//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
	//#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
	//#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
	//#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
	//#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
	//#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
	//#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
	//#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
	//#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
		//ConvetEndian((char*)&ioh->ImageBase, sizeof(ioh->ImageBase));
		//ConvetEndian((char*)&ioh->AddressOfEntryPoint, sizeof(ioh->AddressOfEntryPoint));
		//ConvetEndian((char*)&ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sizeof(ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
		//ConvetEndian((char*)&ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, sizeof(ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

	cout << "[OPTIONAL_HEADER]" << endl;
	printf_s("EP : %p \n", ioh->AddressOfEntryPoint);
	printf_s("DLLCharacteristics : %p \n", ioh->DllCharacteristics);
	printf_s("ImageBase : %p \n", ioh->ImageBase);
	printf_s("EAT-VA : %p \n", ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	printf_s("IAT-VA : %p \n", ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	printf_s("reloc VA : %p \n", ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
};

void PrintingSectionHeader(IMAGE_SECTION_HEADER* ish) {
	/*typedef struct _IMAGE_SECTION_HEADER {
		BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
		union {
			DWORD   PhysicalAddress;
			DWORD   VirtualSize;
		} Misc;
		DWORD   VirtualAddress;
		DWORD   SizeOfRawData;
		DWORD   PointerToRawData;
		DWORD   PointerToRelocations;
		DWORD   PointerToLinenumbers;
		WORD    NumberOfRelocations;
		WORD    NumberOfLinenumbers;
		DWORD   Characteristics;
	} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;*/

	cout << "[SECTION_HEADER]" << endl;
	printf_s("Name : %s \n", ish->Name);
	printf_s("Misc : %p \n", ish->Misc);
	printf_s("VirtualAddress : %p \n", ish->VirtualAddress);
	printf_s("SizeOfRawData : %p \n", ish->SizeOfRawData);
	printf_s("PointerToRawData : %p \n", ish->PointerToRawData);
	printf_s("PointerToRelocations : %p \n", ish->PointerToRelocations);
	printf_s("PointerToLinenumbers : %p \n", ish->PointerToLinenumbers);
	printf_s("NumberOfRelocations : %p \n", ish->NumberOfRelocations);
	printf_s("NumberOfLinenumbers : %p \n", ish->NumberOfRelocations);
	printf_s("Characteristics : %p \n", ish->Characteristics);
};