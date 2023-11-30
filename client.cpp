#define WIN32_LEAN_AND_MEAN 
#include <windows.h> 
#include <winsock2.h> 
#include <ws2tcpip.h> // Директива линковщику: использовать библиотеку сокетов 
#pragma comment(lib, "ws2_32.lib") 
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <io.h>
#include <wincrypt.h>
#include<string.h>
#include <conio.h>
#include <locale.h>
#pragma warning(disable : 4996)

HCRYPTPROV DescCSP;
HCRYPTKEY Key;
HCRYPTKEY publicKey;
HCRYPTKEY privateKey;
HCRYPTKEY sessionKey;

DWORD size_of_public = 0;
SOCKET SocketClient;

void HandleError(TCHAR const error[]){
	wprintf(L"%s\n", error);
	exit(1);
}

void menu(){
	printf("\tSelect the command:\n");
	printf("version \t - type and version OS\n");
	printf("cur_time \t - present time\n");
	printf("boot_time \t - time has passed since the launch of the OS\n");
	printf("memory \t - info about storage\n");
	printf("storage \t - types of attached disks\n");
	printf("access_right \t - permissions to the specified directory\n");
	printf("owner \t - owner of the specified directory\n");
	printf("help \t - list of command\n");
	printf("quit \t - close the client\n");
}

void Crypt(int s, sockaddr_in addr){
	// для создания контейнера ключей с определенным CSP
	//phProv – указатель а дескриптор CSP, pszContainer – имя контейнера ключей, pszProvider – имя CSP, dwProvType – тип CSP, dwFlags – флаги
	if (!CryptAcquireContextW(&DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
		HandleError(TEXT("ERROR: CreateKeyContainer"));

	//для генерации сеансового ключа
	//hProv– дескриптор CSP, Algid – идентификатор алгоритма, dwFlags – флаги, phKey – указатель на дескриптор ключа
	if (!CryptGenKey(DescCSP, AT_KEYEXCHANGE, 1024 << 16, &Key))
		HandleError(TEXT("ERROR: CreateSessionKey"));

	//публичный ключ
	if (!CryptGetUserKey(DescCSP, AT_KEYEXCHANGE, &publicKey))
		HandleError(TEXT("Error: GetPublicKey()"));

	//приватный ключ
	if (!CryptGetUserKey(DescCSP, AT_KEYEXCHANGE, &privateKey))
		HandleError(TEXT("Error: GetPrivateKey()"));
	//hKey – дескриптор экспортируемого ключа, hExpKey – ключ, с помощью которого будет зашифрован hKey при экспорте, dwBlobType – тип экспорта.
	//dwFlags – флаги, pbData – буфер для экспорта.Будет содержать зашифрованный hKey с помощью hExpKey, 
	//pdwDataLen – длина буфера на вход.На выходе – количество значащих байт.
	//функция экспорта ключа для его передачи по каналам информации
	if (!CryptExportKey(publicKey, 0, PUBLICKEYBLOB, 0, NULL, &size_of_public))
		HandleError(TEXT("Error: ExportPublicKey()"));

	BYTE* public_key = (BYTE*)malloc(sizeof(BYTE) * size_of_public);
	memset(public_key, NULL, size_of_public * sizeof(BYTE));

	if (!CryptExportKey(publicKey, 0, PUBLICKEYBLOB, 0, public_key, &size_of_public))
		HandleError(TEXT("Error: ExportPublicKey()"));

	// send length of public key
	char buffer[1000] = { 0 };
	int pkl = htonl(size_of_public);
	memcpy(buffer, &pkl, 4);
	int bytes_send = send(s, buffer, sizeof(buffer), 0);

	// send public key
	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer, public_key, size_of_public);
	bytes_send = send(s, buffer, sizeof(buffer), 0);

	// recv length of session key
	memset(buffer, 0, sizeof(buffer));
	int bytes_recv = recv(s, buffer, sizeof(buffer), 0);

	DWORD SessionKeyLenght;
	memcpy(&pkl, buffer, bytes_recv);
	SessionKeyLenght = ntohl(pkl);
	memset(buffer, 0, sizeof(buffer));

	bytes_recv = recv(s, buffer, sizeof(buffer), 0);

	//Функция предназначена для получения из каналов информации значения ключа
	//получаем сеансовый ключ
	//hProv – дескриптор CSP, pbData – импортируемый ключ представленный в виде массива байт, dwDataLen –длина данных в pbData.
	//hPubKey - дескриптор ключа, который расшифрует ключ содержащийся в pbData, dwFlags - флаги, phKey – указатель на дескриптор ключа.Будет указывать на импортированный ключ.
	if (!CryptImportKey(DescCSP, (BYTE*)buffer, SessionKeyLenght, privateKey, NULL, &sessionKey))
		HandleError(TEXT("Error: ImportSessionKey()"));

	free(public_key);
}
struct sockaddr_in get_ip_port(char* ip_port) {
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	char* ip = strtok(ip_port, ":");
	addr.sin_addr.s_addr = inet_addr(ip);
	ip = strtok(NULL, "");
	int port = atoi(ip);
	addr.sin_port = htons((u_short)port);
	return addr;
}
void get_request(const char* request) {
	char buf_send[4096] = { 0 };
	int bytes_send = 0, bytes_recv = 0;
	DWORD len;
	len = strlen(request) + 1;
	//Основная базовая функция шифрования данных
	//hKey – дескриптор ключа, которым будем шифровать, hHash – дескриптор хеш - объекта.Нужен, если мы хотим зашифровать и найти хеш одновременно.
	//Final – TRUE, если это последний блок на расшифровку и FALSE, если нет, dwFlags – флаги, pbData – буфер с открытым текстом.
	//pdwDataLen– вход – длина открытого текста, выход – длина шифртекста, dwBufLen – длина буфера.
	if (CryptEncrypt(sessionKey, NULL, TRUE, NULL, (BYTE*)request, &len, sizeof(request))) {
		bytes_send = send(SocketClient, request, sizeof(request), 0);
		memset(buf_send, 0, sizeof(buf_send));
		if (!strncmp("owner", request, strlen("owner")) || !strncmp("access_right", request, strlen("access_right"))) {
			printf("Enter path: ");
			scanf("%s", buf_send);
			CryptEncrypt(sessionKey, NULL, TRUE, NULL, (BYTE*)buf_send, &len, sizeof(buf_send));
			bytes_send = send(SocketClient, buf_send, sizeof(buf_send), 0);
		}
		memset(buf_send, 0, sizeof(buf_send));
		bytes_recv = recv(SocketClient, buf_send, sizeof(buf_send), 0);
		DWORD pdDataLen = sizeof(buf_send);
		//Основная базовая функция расшифровывания данных
		if (CryptDecrypt(sessionKey, NULL, TRUE, NULL, (BYTE*)buf_send, &pdDataLen))
			printf("%s\n", buf_send);
		else
			HandleError(TEXT("Error: Decryption()"));
	}
	else {
		int err=GetLastError();
		HandleError(TEXT("Error: Encryption()"));

	}
}
int main(){
	char ip_port[21] = { 0 };
	setlocale(LC_ALL, "Rus");
	printf("Session started\n\n");
	printf("Enter address \"IP_addr:port\"\n");

	fgets(ip_port, 21, stdin);

	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0) printf("WSAStartup ok\n");
	else printf("WSAStartup error\n");

	// Создание TCP-сокета 
	int SocketClient = socket(AF_INET, SOCK_STREAM, 0);
	if (SocketClient < 0){
		int err;
		err = WSAGetLastError();
		fprintf(stderr, "Socket error: %d\n", err);
		return -1;
	}
	//Структура SOCKADDR_IN задает транспортный адрес и порт для семейства адресов AF_INET.
	struct sockaddr_in addr = get_ip_port(ip_port);

	//Подключение к клиенту
	if (connect(SocketClient, (struct sockaddr*)&addr, sizeof(addr)) != 0){
		closesocket(SocketClient);
		HandleError(TEXT("Error: connect()"));
	}
	Crypt(SocketClient, addr);
	printf("Client successfully connected to server\n");

	menu();

	// Отправка запроса на удаленный сервер 
	char request[20] = { 0 };
	while (1){
		scanf("%s", &request);

		if (!strncmp("version", request, strlen("version")))
			get_request("version");
		else if (!strncmp("cur_time", request, strlen("cur_time")))
			get_request("cur_time");
		else if (!strncmp("boot_time", request, strlen("boot_time")))
			get_request("boot_time");
		else if (!strncmp("memory", request, strlen("memory")))
			get_request("memory");
		else if (!strncmp("storage", request, strlen("storage")))
			get_request("storage");
		else if (!strncmp("access_right", request, strlen("access_right")))
			get_request("access_right");
		else if (!strncmp("owner", request, strlen("owner")))
			get_request("owner");
		else if (!strncmp("quit", request, strlen("quit")))
			get_request("quit");
		else if (!strncmp("help", request, strlen("help")))
			menu();
		else
			printf("Unknown request, enter 'help' for display list of command\n");
	}
	// Закрытие соединения 
	closesocket(SocketClient);
	// Для Windows следует вызвать WSACleanup в конце работы 
	WSACleanup();
	return 0;
}
