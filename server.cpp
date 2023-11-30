#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <aclapi.h>
#include <stdio.h>
#include <locale.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#pragma warning(disable: 4996)

#define WIN32_LEAN_AND_MEAN
#include <sddl.h> // for ConvertToString SID

HCRYPTPROV hProv = 0;
HCRYPTKEY publicKey = 0;
HCRYPTKEY sessionKey = 0;
HCRYPTKEY Key = 0;
DWORD SessionKeyLength = 0;
DWORD publicKeyLength = 0;


void HandleError(TCHAR const error[])
{
	wprintf(L"%s\n", error);
	exit(1);
}

// get a handle to the default PROV_RSA_FULL provider
void CreateKeyContainer(void){
	//Для получения дескриптора контейнера ключей
	if (CryptAcquireContextW(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, NULL))
		printf("Cryptographic provider initialized\n");
	else
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			//Контейнер по умолчанию не найден, gопытка создать его
			if (CryptAcquireContextW(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
				printf("New Cryptographic container created\n");
			else
				HandleError(TEXT("ERROR: CreateKeyContainer"));
		}
}

void version(char* buf)
{
	DWORD bufsize = 100;
	WCHAR buf_os[100];
	HKEY hKey;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
	{
		RegQueryValueEx(hKey, L"ProductName", NULL, NULL, (LPBYTE)buf_os, &bufsize);
		sprintf(buf, "%ls\n", buf_os);
	}
}

void cur_time(char* buf)
{
	//в SYSTEMTIME и по элементам структуры определить время
	SYSTEMTIME sm;
	GetSystemTime(&sm);

	//день
	(sm.wDay > 9) ? sprintf(buf, "%d.", sm.wDay) : sprintf(buf, "0%lu.", sm.wDay);
	//месяц
	(sm.wMonth > 9) ? sprintf(buf + strlen(buf), "%lu.", sm.wMonth) : sprintf(buf + strlen(buf), "0%lu.", sm.wMonth);
	//год
	sprintf(buf + strlen(buf), "%lu ", sm.wYear);

	//из-за UTC (на 3 часа меньше)
	((sm.wHour + 3) % 24 > 9) ? sprintf(buf + strlen(buf), "%d:", (sm.wHour + 3) % 24) : sprintf(buf + strlen(buf), "0%d:", (sm.wHour + 3) % 24);
	(sm.wMinute > 9) ? sprintf(buf + strlen(buf), "%d:", sm.wMinute) : sprintf(buf + strlen(buf), "0%d:", sm.wMinute);
	(sm.wSecond > 9) ? sprintf(buf + strlen(buf), "%d\n", sm.wSecond) : sprintf(buf + strlen(buf), "0%d\n", sm.wSecond);
}

void boot_time(char* buf)
{
	//по формулам клиент находит время
	int day, hour, min, sec, msec = GetTickCount();
	hour = msec / (1000 * 60 * 60);
	min = msec / (1000 * 60) - hour * 60;
	sec = (msec / 1000) - (hour * 60 * 60) - min * 60;
	day = hour / 24;
	hour %= 24;

	sprintf(buf, "%d days ", day);
	(hour > 9) ? sprintf(buf + strlen(buf), "%d:", hour) : sprintf(buf + strlen(buf), "0%d:", hour);
	(min > 9) ? sprintf(buf + strlen(buf), "%d:", min) : sprintf(buf + strlen(buf), "0%d:", min);
	(sec > 9) ? sprintf(buf + strlen(buf), "%d\n", sec) : sprintf(buf + strlen(buf), "0%d\n", sec);
}
void memory(char* buf)
{
	//информация об используемой памяти
	MEMORYSTATUSEX state;
	state.dwLength = sizeof(state);
	GlobalMemoryStatusEx(&state);
	sprintf(buf, "%d %% of memory in use.\n", state.dwMemoryLoad);
	sprintf(buf + strlen(buf), "%f total MB of physical memory.\n", (double)state.ullTotalPhys / 1024.0 / 1024.0);
	sprintf(buf + strlen(buf), "%f free MB of physical memory.\n", (double)state.ullAvailPhys / 1024.0 / 1024.0);
	sprintf(buf + strlen(buf), "%f total MB of paging file.\n", (double)state.ullTotalPageFile / 1024.0 / 1024.0);
	sprintf(buf + strlen(buf), "%f free MB of paging file.\n", (double)state.ullAvailPageFile / 1024.0 / 1024.0);
	sprintf(buf + strlen(buf), "%f total MB of virtual memory.\n", (double)state.ullTotalVirtual / 1024.0 / 1024.0);
	sprintf(buf + strlen(buf), "%f free MB of virtual memory.\n", (double)state.ullAvailVirtual / 1024.0 / 1024.0);
	//stat.dwMemoryLoad - загрузка памяти в процентах
	//stat.dwTotalPhys - максимальное количество физической памяти в байтах
	//stat.dwAvailPhys - свободное количество физической памяти в байтах
	//stat.dwTotalPageFile - максимальное количество памяти для программ в байтах
	//stat.dwAvailPageFile - свободное количество памяти для программ в байтах
	//stat.dwTotalVirtual - максимальное количество виртуальной памяти в байтах
	//stat.dwAvailVirtual - свободное количество виртуальной памяти в байтах
}
void storage(CHAR* buf)
{
	//тип подключенных дисков
	//26 - максимальное количество лок дисков
	DWORD dr = GetLogicalDrives();
	WCHAR disks[26][4] = { 0 };
	WCHAR FileSystem[10];
	DWORD s, b, f, c; //сектора в кластере, байты в секторе, свобоные кластеры, кластеры
	int count = 0;

	for (int i = 0; i < 26; i++)
	{
		if ((dr & (1 << i)))
		{
			disks[count][0] = WCHAR(65 + i);
			disks[count][1] = ':';
			disks[count][2] = '\\';
			count++;
		}

	}
	for (int i = 0; i < count; i++)
	{
		for (int j = 0; j < 3; j++)
			sprintf(buf + strlen(buf), "%lc", disks[i][j]);

		switch (GetDriveTypeW((LPWSTR)disks[i]))
		{
		case 0:
			sprintf(buf + strlen(buf), ": unknown type; ");
			break;
		case 1:
			sprintf(buf + strlen(buf), ": root path is invalid; ");
			break;
		case 2:
			sprintf(buf + strlen(buf), ":  removable; ");
			break;
		case 3:
			sprintf(buf + strlen(buf), ": hard disk drive; ");
			break;
		case 4:
			sprintf(buf + strlen(buf), ": remote (network) drive; ");
			break;
		case 5:
			sprintf(buf + strlen(buf), ": CD-ROM drive; ");
			break;
		case 6:
			sprintf(buf + strlen(buf), ": RAM disk; ");
			break;
		default:
			break;
		}
		//файловая система
		GetVolumeInformation((LPWSTR)disks[i], NULL, NULL, NULL, NULL, NULL, FileSystem, 10);
		if (!wcscmp(FileSystem, L"NTFS"))
			sprintf(buf + strlen(buf), " NTFS; ");
		if (!wcscmp(FileSystem, L"FAT"))
			sprintf(buf + strlen(buf), " FAT; ");
		if (!wcscmp(FileSystem, L"CDFS"))
			sprintf(buf + strlen(buf), " CDFS; ");
		//свободное место
		GetDiskFreeSpaceW((LPWSTR)disks[i], &s, &b, &f, &c);
		sprintf(buf + strlen(buf), "free space %f GB\n\n", (double)f * (double)s * (double)b / 1024.0 / 1024.0 / 1024.0);
	}
}
void access_rights(char* char_path, char* char_buf)
{
	wchar_t* path = (wchar_t*)malloc(sizeof(strlen(char_path) + 1));
	size_t convertedChars = 0;
	mbstowcs_s(&convertedChars, path, strlen(char_path) + 1, char_path, _TRUNCATE);

	PACL pDACL = NULL; // ACL structure (ptr)
	PSECURITY_DESCRIPTOR pSD; // security descriptor (ptr)
	wchar_t* subkey = NULL; // buf for key path
	WCHAR buf[4096] = { 0 };

	bool key = false;
	char* root = strtok(char_path, "\\");
	if (!strcmp(root, "HKEY_CLASSES_ROOT"))
		key = TRUE;
	else if (!strcmp(root, "HKEY_CURRENT_USER"))
		key = TRUE;
	else if (!strcmp(root, "HKEY_LOCAL_MACHINE"))
		key = TRUE;
	else if (!strcmp(root, "HKEY_USERS"))
		key = TRUE;
	else if (!strcmp(root, "HKEY_CURRENT_CONFIG"))
		key = TRUE;
	else
	{
		key = FALSE;
	}

	if (!key) // processing file/folder
	{
		if (GetNamedSecurityInfo(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD) != ERROR_SUCCESS)
		{
			swprintf(buf + wcslen(buf), L"Path entered incorrectly\n");
			return;
		}
	}
	else if (key) // processing registry key
	{
		HKEY res;

		//открывает указанный ключ
		wchar_t* root = wcstok(path, L"\\", &subkey);
		if (!wcscmp(root, L"HKEY_CLASSES_ROOT"))
			RegOpenKey(HKEY_CLASSES_ROOT, subkey, &res);
		else if (!wcscmp(root, L"HKEY_CURRENT_USER"))
			RegOpenKey(HKEY_CURRENT_USER, subkey, &res);
		else if (!wcscmp(root, L"HKEY_LOCAL_MACHINE"))
			RegOpenKey(HKEY_LOCAL_MACHINE, subkey, &res);
		else if (!wcscmp(root, L"HKEY_USERS"))
			RegOpenKey(HKEY_USERS, subkey, &res);
		else if (!wcscmp(root, L"HKEY_CURRENT_CONFIG"))
			RegOpenKey(HKEY_CURRENT_CONFIG, subkey, &res);
		else
		{
			swprintf(buf + wcslen(buf), L"RegOpenKey Error\n");
			return;
		}

		if (GetSecurityInfo(res, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD) != ERROR_SUCCESS)
		{
			swprintf(buf + wcslen(buf), L"Get security information error\n");
			return;
		}
	}

	if (pDACL == NULL)
	{
		swprintf(buf + wcslen(buf), L"ACL list is empty\n");
		return;
	}

	ACL_SIZE_INFORMATION aclInfo; // class needed information from ACL
	if (!GetAclInformation(pDACL, &aclInfo, sizeof(aclInfo), AclSizeInformation))
	{
		swprintf(buf + wcslen(buf), L"Can't get ACL info\n");
		return;
	}

	// Цикл перебора всех ACL-записей
	for (DWORD i = 0; i < aclInfo.AceCount; i++)
	{
		wchar_t name[500] = { 0 }, Domain[500] = { 0 };
		int len = 500; // lenght of username and domain
		//pACE->Header.AceType(BYTE); name; pACE->SidStart(DWORD); pACE->Mask(DWORD)
		LPVOID AceInfo;
		// Получить текущую запись
		if (GetAce(pDACL, i, &AceInfo))
		{
			PSID* pSID = (PSID*)&((ACCESS_ALLOWED_ACE*)AceInfo)->SidStart;
			SID_NAME_USE sid_nu; // struct that determine type of write
			if (LookupAccountSid(NULL, pSID, (LPWSTR)name, (LPDWORD)&len, (LPWSTR)Domain, (LPDWORD)&len, &sid_nu))
			{
				LPWSTR StringSid;
				ConvertSidToStringSid(pSID, &StringSid);
				swprintf(buf + wcslen(buf), L" SID: %ls  ", StringSid);
				swprintf(buf + wcslen(buf), L"Account: %ls", name);

				if (((ACCESS_ALLOWED_ACE*)AceInfo)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
					swprintf(buf + wcslen(buf), L"   Allowed ACE; ");
				if (((ACCESS_ALLOWED_ACE*)AceInfo)->Header.AceType == ACCESS_DENIED_ACE_TYPE)
					swprintf(buf + wcslen(buf), L" Denied ACE; ");
				if (((ACCESS_ALLOWED_ACE*)AceInfo)->Header.AceType == SYSTEM_ALARM_ACE_TYPE)
					swprintf(buf + wcslen(buf), L" System Alarm ACE; ");
				if (((ACCESS_ALLOWED_ACE*)AceInfo)->Header.AceType == SYSTEM_AUDIT_ACE_TYPE)
					swprintf(buf + wcslen(buf), L" System Audit ACE; ");

				if ((((ACCESS_ALLOWED_ACE*)AceInfo)->Mask & WRITE_OWNER) == WRITE_OWNER)
					swprintf(buf + wcslen(buf), L" Change Owner; ");
				if ((((ACCESS_ALLOWED_ACE*)AceInfo)->Mask & WRITE_DAC) == WRITE_DAC)
					swprintf(buf + wcslen(buf), L" Write DAC; ");
				if ((((ACCESS_ALLOWED_ACE*)AceInfo)->Mask & DELETE) == DELETE)
					swprintf(buf + wcslen(buf), L" Delete; ");
				if ((((ACCESS_ALLOWED_ACE*)AceInfo)->Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ)
					swprintf(buf + wcslen(buf), L" Read; ");
				if ((((ACCESS_ALLOWED_ACE*)AceInfo)->Mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE)
					swprintf(buf + wcslen(buf), L" Write; ");
				if ((((ACCESS_ALLOWED_ACE*)AceInfo)->Mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE)
					swprintf(buf + wcslen(buf), L" Execute; ");
				if ((((ACCESS_ALLOWED_ACE*)AceInfo)->Mask & SYNCHRONIZE) == SYNCHRONIZE)
					swprintf(buf + wcslen(buf), L" Synchronize; ");
				if ((((ACCESS_ALLOWED_ACE*)AceInfo)->Mask & READ_CONTROL) == READ_CONTROL)
					swprintf(buf + wcslen(buf), L" Read control;");
				swprintf(buf + wcslen(buf), L"\n");
			}
		}
	}
	wcstombs(char_buf, buf, wcslen(buf));
	path = NULL;
	free(path);
}
void owner(char* char_path, char* char_buf)
{
	wchar_t* path = (wchar_t*)malloc(sizeof(strlen(char_path) + 1));
	size_t convertedChars = 0;
	mbstowcs_s(&convertedChars, path, strlen(char_path) + 1, char_path, _TRUNCATE);

	PSID pOwnerSid = NULL; // SID of file/folder/key
	PSECURITY_DESCRIPTOR pSD = NULL; // security descriptor (ptr)
	wchar_t* subkey = NULL; // buf for key path

	WCHAR buf[4096] = { 0 };

	char* root = strtok(char_path, "\\");
	bool key = false;
	if (!strcmp(root, "HKEY_CLASSES_ROOT"))
		key = TRUE;
	else if (!strcmp(root, "HKEY_CURRENT_USER"))
		key = TRUE;
	else if (!strcmp(root, "HKEY_LOCAL_MACHINE"))
		key = TRUE;
	else if (!strcmp(root, "HKEY_USERS"))
		key = TRUE;
	else if (!strcmp(root, "HKEY_CURRENT_CONFIG"))
		key = TRUE;
	else
	{
		key = FALSE;
	}

	if (!key) // processing file/folder
	{
		if (GetNamedSecurityInfo(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
		{
			swprintf(buf + wcslen(buf), L"Get security information error\n");
			return;
		}
	}
	else if (key) // processing registry key
	{
		HKEY res;

		wchar_t* root = wcstok(path, L"\\", &subkey); // store type of key
		if (!wcscmp(root, L"HKEY_CLASSES_ROOT"))
			RegOpenKey(HKEY_CLASSES_ROOT, subkey, &res);
		else if (!wcscmp(root, L"HKEY_CURRENT_USER"))
			RegOpenKey(HKEY_CURRENT_USER, subkey, &res);
		else if (!wcscmp(root, L"HKEY_LOCAL_MACHINE"))
			RegOpenKey(HKEY_LOCAL_MACHINE, subkey, &res);
		else if (!wcscmp(root, L"HKEY_USERS"))
			RegOpenKey(HKEY_USERS, subkey, &res);
		else if (!wcscmp(root, L"HKEY_CURRENT_CONFIG"))
			RegOpenKey(HKEY_CURRENT_CONFIG, subkey, &res);
		else
		{
			swprintf(buf + wcslen(buf), L"RegOpenKey Error\n");
			return;
		}

		if (GetSecurityInfo(res, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
		{
			swprintf(buf + wcslen(buf), L"Get security information error\n");
			return;
		}
	}

	if (pSD == NULL)
	{
		swprintf(buf + wcslen(buf), L"Security descriptor is empty\n");
		return;
	}

	wchar_t name[500] = { 0 }, Domain[500] = { 0 };
	int len = 500; // lenght of username and domain
	SID_NAME_USE SidName; // struct that determine type of write
	LookupAccountSid(NULL, pOwnerSid, name, (LPDWORD)&len, Domain, (LPDWORD)&len, &SidName);

	LPWSTR StringSid;
	ConvertSidToStringSid(pOwnerSid, &StringSid);
	swprintf(buf + wcslen(buf), L" SID: %ls  ", StringSid);
	swprintf(buf + wcslen(buf), L"Account: %ls\n", name);

	wcstombs(char_buf, buf, wcslen(buf));
	path = NULL;
	free(path);
}
void send_info(const char* request, int cs) {
	char recv_buf[4096] = { 0 }, path[4096] = { 0 };
	int bytes_send = 0, bytes_recv=0;
	DWORD len;
	if(!strncmp("version", request, strlen("version")))
		version(recv_buf);
	if (!strncmp("cur_time", request, strlen("cur_time")))
		cur_time(recv_buf);
	if (!strncmp("boot_time", request, strlen("boot_time")))
		boot_time(recv_buf);
	if (!strncmp("memory", request, strlen("memory")))
		memory(recv_buf);
	if (!strncmp("storage", request, strlen("storage")))
		storage(recv_buf);
	if (!strncmp("version", request, strlen("version"))) {
		bytes_recv = recv(cs, path, sizeof(path), 0);
		len = sizeof(path);
		if (!CryptDecrypt(sessionKey, NULL, TRUE, NULL, (BYTE*)path, &len))
			printf("Error: Decryption failed\n");
		access_rights(path, recv_buf);
	}
	if (!strncmp("owner", request, strlen("owner"))) {
		bytes_recv = recv(cs, path, sizeof(path), 0);
		len = sizeof(path);
		if (!CryptDecrypt(sessionKey, NULL, TRUE, NULL, (BYTE*)path, &len))
			printf("Error: Decryption failed\n");
		owner(path, recv_buf);
	}
	len = strlen(recv_buf) + 1;
	if (!CryptEncrypt(sessionKey, NULL, TRUE, NULL, (BYTE*)recv_buf, &len, sizeof(recv_buf)))
		printf("Error: Encryption failed\n");
	else bytes_send = send(cs, recv_buf, sizeof(recv_buf), 0);
}
void Crypt(int cs) {
	char buf[1000] = { 0 };

	//Получение public key len
	int bytes_recv = recv(cs, buf, sizeof(buf), 0);
	memcpy(&publicKeyLength, buf, bytes_recv);
	publicKeyLength = ntohl(publicKeyLength);

	//Получение public key
	memset(buf, 0, sizeof(buf));
	bytes_recv = recv(cs, buf, sizeof(buf), 0);

	CreateKeyContainer();

	// get a symmetrical session key
	if (!CryptGenKey(hProv, CALG_RC4, CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT, &sessionKey))
		HandleError(TEXT("ERROR: CryptGenKey"));

	// import public key
	if (!CryptImportKey(hProv, (BYTE*)buf, publicKeyLength, NULL, NULL, &publicKey))
		HandleError(TEXT("ERROR: CryptImportKey"));

	memset(buf, NULL, sizeof(buf));

	// export session key
	if (!CryptExportKey(sessionKey, publicKey, SIMPLEBLOB, NULL, NULL, &SessionKeyLength))
		HandleError(TEXT("ERROR: CryptExportKey"));

	// send session key length
	int sesKeyLen = htonl(SessionKeyLength);
	memcpy(buf, &sesKeyLen, sizeof(buf));
	int bytes_send = send(cs, buf, sizeof(buf), 0);
	memset(buf, 0, sizeof(buf));

	if (!CryptExportKey(sessionKey, publicKey, SIMPLEBLOB, NULL, (BYTE*)buf, &SessionKeyLength))
		HandleError(TEXT("ERROR: CryptExportKey"));

	// send session key
	bytes_send = send(cs, buf, SessionKeyLength, 0);
}
int main(){
	setlocale(LC_ALL, "Rus");
	WSADATA wsa_data;

	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0) printf("WSAStartup ok\n");
	else printf("WSAStartup error\n");
	struct sockaddr_in addr;
	// Создание сокета прослушивания
	SOCKET Socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	// Создание порта завершения
	HANDLE g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == g_io_port){
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return 0;
	}
	// Обнуление структуры данных для хранения входящих соединени
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(9000);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(Socket, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(Socket, 1) < 0){
		printf("Error bind() or listen()\n");
		return 0;
	}
	printf("Listening: %d\n", ntohs(addr.sin_port));
	// Присоединение существующего сокета Socket к порту io_port.
	// В качестве ключа для прослушивающего сокета используется 0
	if (NULL == CreateIoCompletionPort((HANDLE)Socket, g_io_port, 0, 0)){
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return 0;
	}

	// Принятие очередного подключившегося клиента 
	int addrlen = sizeof(addr);
	int cs = accept(Socket, (struct sockaddr*)&addr, &addrlen);
	unsigned ip = ntohl(addr.sin_addr.s_addr);
	//printf("New connection created, IP: %u.%u.%u.%u\n", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip) & 0xff);

	char buf[1000] = { 0 };
	Crypt(cs);
	char request[20] = { 0 };
	DWORD len;
	int bytes_send=0, bytes_recv=0;
	while (1){
		bytes_recv = recv(cs, request, sizeof(request), 0);
		len = sizeof(request);
		if (!CryptDecrypt(sessionKey, NULL, TRUE, NULL, (BYTE*)request, &len))
			printf("Error: Decryption failed\n");
		else{
			if (!strncmp("quit", request, strlen("quit"))){
				closesocket(cs);
				closesocket(Socket);
				WSACleanup();
				printf("Connection closed\n");
				return 0;
			}
			send_info(request, cs);
		}
	}
	return 0;
}
