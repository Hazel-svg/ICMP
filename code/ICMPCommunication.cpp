#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "iphdr.h"
#include "utils.h"
#include "zmem.h"
#include <time.h>
#include <Wtsapi32.h>
#include<string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib,"Shlwapi.lib")
#pragma comment(lib,"Winmm.lib")

constexpr int MTU = 1500;	// Avoid fragment
constexpr int MAXSIZE = MTU - sizeof(IPV4_HDR) - sizeof(ICMP_HDR);
constexpr int MINSIZE = 32;
constexpr unsigned short IPIDSEED = 12345;
constexpr unsigned short ICMPIDSEED = 54321;

// 分段机制使用ICMP协议的ID号和序列号，仿照IP进行设计
// ID表示数据块的标识，序列号最高位表示后续是否有分片，低15位表示自己的序列号
// 若序列号最高位为1，则期待收到的下一个序列号为自己的序列号加1


unsigned short gICMPID = 0x0100;
unsigned short gICMPSequence = 0x1000;

typedef struct _ICMPPACKET {
	char srcAddr[INET_ADDRSTRLEN];
	char dstAddr[INET_ADDRSTRLEN];
	unsigned char type;
	unsigned char code;
	unsigned short ip_id;
	unsigned short  icmp_id;
	unsigned short  icmp_sequence;
	char* payload;
	unsigned short payloadSize;
} ICMPPacket, * PICMPPacket;

unsigned short calcChecksum(unsigned short* addr, int len)
{
	int nleft = len;
	unsigned int sum = 0;
	unsigned short* w = addr;
	unsigned short answer = 0;

	// Adding 16 bits sequentially in sum
	while (nleft > 1) {
		sum += *w;
		nleft -= 2;
		w++;
	}

	// If an odd byte is left
	if (nleft == 1) {
		*(unsigned char*)(&answer) = *(unsigned char*)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return answer;
}

__int64 CommandHash(__in ULONG uProtoCmd, __in LPBYTE pMessage, __in ULONG uMessageLen, __out LPBYTE* pOutBuff)
{
	//命令号+数据(wchar)
	WCHAR wszSid[64] = L"516551615161556167641169731138768330808226873204613781363045608";
	DWORD dwOutLen = 0;
	DWORD dwIndex = 0;

	DWORD dwSize = 74 + uMessageLen + sizeof(ULONG) + 1;
	LPBYTE pOutTmp = (LPBYTE)zalloc(dwSize); //4+64+3+3

	__try {
		memcpy(pOutTmp, "s=", 2);
		dwIndex += 2;
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		LogW(L"%d", GetLastError());
	}

	char* szSid = WcharToChar(wszSid);
	memcpy(pOutTmp + dwIndex, szSid, strlen(szSid));
	dwIndex += strlen(szSid);
	zfree(szSid);

	memcpy(pOutTmp + dwIndex, "&c=", 3);
	dwIndex += 3;

	memcpy(pOutTmp + dwIndex, (LPBYTE)&uProtoCmd, sizeof(ULONG));
	dwIndex += sizeof(ULONG);

	memcpy(pOutTmp + dwIndex, "&d=", 3);
	dwIndex += 3;

	memcpy(pOutTmp + dwIndex, pMessage, uMessageLen);
	dwIndex += uMessageLen;

	dwOutLen += dwIndex;

	*pOutBuff = pOutTmp+75;

	return dwOutLen;
}

SOCKET CreateICMPSocket()
{
	SOCKET sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock_fd == INVALID_SOCKET) {
		printf("socket failed: %d\n", GetLastError());
		return INVALID_SOCKET;
	}

	int on = 1;
	if (SOCKET_ERROR == setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof(on))) {
		printf("setsockopt failed: %d\n", GetLastError());
		return INVALID_SOCKET;
	}

	return sock_fd;
}

void PrepareHeaders(IPV4_HDR* ipHdr, unsigned short* pIpID)
{
	ipHdr->ip_verlen = 0x45;
	ipHdr->ip_tos = 0;
	// ipHdr->ip_totallength由调用该函数调用者填写
	while ((*pIpID) == 0) {	// 只有在第一次握手时，ipHdr->ip_id才随机生成，之后直接使用(*pIpID)的值
		srand((IPIDSEED + (unsigned short)time(NULL)) & 0xffff);
		*pIpID = LOWORD(rand());
	}
	ipHdr->ip_id = htons(*pIpID);
	ipHdr->ip_offset = 0;
	ipHdr->ip_ttl = 128;
	ipHdr->ip_protocol = IPPROTO_ICMP;
	// ipHdr->ip_checksum, ip_srcaddr, ip_destaddr由该函数调用者填写
}

BOOL SendICMPPacket(SOCKET sock, PICMPPacket pPacket, unsigned short icmpID, unsigned short icmpSequence, unsigned short* pIpID)
{
	IN_ADDR srcAddr;
	IN_ADDR dstAddr;

	inet_pton(AF_INET, pPacket->srcAddr, &srcAddr);
	inet_pton(AF_INET, pPacket->dstAddr, &dstAddr);

	unsigned short packetSize = sizeof(IPV4_HDR) + sizeof(ICMP_HDR) + pPacket->payloadSize;

	char* packet = (char*)calloc(packetSize, sizeof(UINT8));
	if (packet == nullptr) {
		printf("No memory to allocate.\n");
		closesocket(sock);
		return FALSE;
	}

	IPV4_HDR* ipHdr = (PIPV4_HDR)packet;
	ICMP_HDR* icmpHdr = (PICMP_HDR)(packet + sizeof(IPV4_HDR));
	char* icmpPayload = (char*)(packet + sizeof(IPV4_HDR) + sizeof(ICMP_HDR));

	PrepareHeaders(ipHdr, pIpID);

	ipHdr->ip_totallength = htons(packetSize);
	ipHdr->ip_srcaddr = srcAddr.S_un.S_addr;
	ipHdr->ip_destaddr = dstAddr.S_un.S_addr;

	icmpHdr->icmp_type = pPacket->type;
	icmpHdr->icmp_code = pPacket->code;		// type和code字段由该函数调用者决定
	if (icmpHdr->icmp_type == ICMPV4_ECHO_REQUEST_TYPE) {
		icmpHdr->icmp_id = htons(icmpID);
		icmpHdr->icmp_sequence = htons(icmpSequence);
		pPacket->ip_id = *pIpID;
		pPacket->icmp_id = icmpHdr->icmp_id;
		pPacket->icmp_sequence = icmpHdr->icmp_sequence;
	}
	else if (icmpHdr->icmp_type == ICMPV4_ECHO_REPLY_TYPE) {
		icmpHdr->icmp_id = pPacket->icmp_id;
		icmpHdr->icmp_sequence = pPacket->icmp_sequence;
	}
	else {
		printf("Unsupported icmp type!\n");
		return FALSE;
	}

	// 必须先将内容填好，否则checksum算出来是错的
	memcpy(icmpPayload, pPacket->payload, pPacket->payloadSize);
	icmpHdr->icmp_checksum = calcChecksum((unsigned short*)icmpHdr, sizeof(ICMP_HDR) + pPacket->payloadSize);

	struct sockaddr_in targetAddr;
	ZeroMemory(&targetAddr, sizeof(struct sockaddr_in));
	targetAddr.sin_family = AF_INET;
	targetAddr.sin_addr.S_un.S_addr = dstAddr.S_un.S_addr;

	// 并非已连接套接字，不能调用send函数，应使用sendto函数
	int iResult = sendto(sock, packet, packetSize, 0, (struct sockaddr*) & targetAddr, sizeof(struct sockaddr));
	if (iResult == SOCKET_ERROR) {
		printf("sendto error: %d\n", WSAGetLastError());
		return FALSE;
	}

	ipHdr = nullptr;
	icmpHdr = nullptr;
	icmpPayload = nullptr;
	free(packet);

	return TRUE;
}

BOOL RecvICMPPacket(SOCKET sock, PICMPPacket pPacket)
{
	int ipDatagramLen = MTU; 
	char* packet = (char*)calloc(ipDatagramLen, sizeof(UINT8));
	if (packet == nullptr) {
		printf("No memory to allocate.\n");
		return FALSE;
	}

	// call recvfrom() to receive packet
	int srcAddrSize = sizeof(struct sockaddr_in);
	struct sockaddr_in srcAddr;
	ZeroMemory(&srcAddr, sizeof(struct sockaddr_in));
	int packetSize = recvfrom(sock, packet, ipDatagramLen, 0, (sockaddr*)&srcAddr, &srcAddrSize);
	if (packetSize == SOCKET_ERROR) {
		printf("recvfrom error: %d\n", WSAGetLastError());
		free(packet);
		return FALSE;
	}

	IPV4_HDR* ipHdr = (PIPV4_HDR)packet;
	ICMP_HDR* icmpHdr = (PICMP_HDR)(packet + sizeof(IPV4_HDR));
	char* icmpPayload = (char*)(packet + sizeof(IPV4_HDR) + sizeof(ICMP_HDR));

	// fill up pPacket
	inet_ntop(AF_INET, &(ipHdr->ip_srcaddr), pPacket->srcAddr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ipHdr->ip_destaddr), pPacket->dstAddr, INET_ADDRSTRLEN);

	pPacket->ip_id = ntohs(ipHdr->ip_id);
	pPacket->type = icmpHdr->icmp_type;
	pPacket->code = icmpHdr->icmp_code;
	pPacket->icmp_id = ntohs(icmpHdr->icmp_id);
	pPacket->icmp_sequence = ntohs(icmpHdr->icmp_sequence);

	pPacket->payloadSize = packetSize - sizeof(IPV4_HDR) - sizeof(ICMP_HDR);
	pPacket->payload = (char*)calloc(pPacket->payloadSize, sizeof(UINT8));
	if (pPacket->payload == nullptr) {
		printf("No memory to allocate!\n");
		closesocket(sock);
		return FALSE;
	}

	memcpy(pPacket->payload, icmpPayload, pPacket->payloadSize);

	ipHdr = nullptr;
	icmpHdr = nullptr;
	icmpPayload = nullptr;
	free(packet);

	return TRUE;
}

// Method: Not to query the local computer at all,
//		but rather to ask the computer the program is talking to
//		what it sees this computer's IP address
BOOL ObtainWorkingIP(char* szIPAddr)
{
	char szServAddr[] = "223.5.5.5";
	char szPayload[] = "abcdefghijklmnopqrstuvwabcdefghi";
	int payloadSize = strlen(szPayload);

	SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET) {
		printf("socket error: %d\n", WSAGetLastError());
		return FALSE;
	}

	struct sockaddr_in servAddr;
	ZeroMemory(&servAddr, sizeof(struct sockaddr_in));
	servAddr.sin_family = AF_INET;
	inet_pton(AF_INET, szServAddr, &servAddr.sin_addr.S_un.S_addr);

	BOOL ret = connect(sock, (struct sockaddr*) & servAddr, sizeof(servAddr));
	if (ret == SOCKET_ERROR) {
		printf("connect error: %d\n", WSAGetLastError());
		return FALSE;
	}

	int icmpPacketSize = sizeof(ICMP_HDR) + payloadSize;
	char* icmpPacket = (char*)calloc(icmpPacketSize, sizeof(UINT8));
	if (icmpPacket == nullptr) {
		printf("no memory to allocate!\n");
		return FALSE;
	}

	ICMP_HDR* icmpHdr = (PICMP_HDR)icmpPacket;
	char* icmpPayload = (char*)(icmpPacket + sizeof(ICMP_HDR));

	icmpHdr->icmp_code = ICMPV4_ECHO_REQUEST_CODE;
	icmpHdr->icmp_type = ICMPV4_ECHO_REQUEST_TYPE;
	icmpHdr->icmp_id = gICMPID;
	icmpHdr->icmp_sequence = gICMPSequence;
	gICMPSequence += 0x0100;
	memcpy(icmpPayload, szPayload, payloadSize);
	icmpHdr->icmp_checksum = calcChecksum((unsigned short*)icmpHdr, sizeof(ICMP_HDR) + payloadSize);

	if (SOCKET_ERROR == sendto(sock, icmpPacket, icmpPacketSize, 0, (struct sockaddr*) & servAddr, sizeof(struct sockaddr))) {
		printf("sendto error: %d\n", WSAGetLastError());
		free(icmpPacket);
		return FALSE;
	}
	printf("Local IP probe packet has been written into kernel.\n");
	free(icmpPacket);
	icmpHdr = nullptr;
	icmpPayload = nullptr;

	int ipDatagramLen = MTU;
	char* packet = (char*)calloc(ipDatagramLen, sizeof(UINT8));
	if (packet == nullptr) {
		printf("No memory to allocate.\n");
		return FALSE;
	}

	int srcAddrSize = sizeof(struct sockaddr_in);
	struct sockaddr_in srcAddr;
	ZeroMemory(&srcAddr, sizeof(struct sockaddr_in));

	printf("[*] Receiving ICMP echo reply packet...\n");

	fd_set rset;
	TIMEVAL timeVal;

	BOOL bRecv = FALSE;
	for (int i = 0; i < 3; i++) {
		FD_ZERO(&rset);
		FD_SET(sock, &rset);

		timeVal.tv_sec = 1;
		timeVal.tv_usec = 0;

		int retStatus = select(0, &rset, nullptr, nullptr, &timeVal);
		if (retStatus == SOCKET_ERROR) {
			printf("select error: %d\n", WSAGetLastError());
			free(packet);
			return FALSE;
		}
		else if (retStatus == 0) {
			printf("Timeout...\n");
			continue;
		}
		else if (FD_ISSET(sock, &rset)) {
			int packetSize = recvfrom(sock, packet, ipDatagramLen, 0, (sockaddr*)&srcAddr, &srcAddrSize);
			if (packetSize == SOCKET_ERROR) {
				printf("recvfrom error: %d\n", WSAGetLastError());
				free(packet);
				return FALSE;
			}
			printf("[Success] ICMP echo reply packet received successfully!\n");
			bRecv = TRUE;
			break;
		}
	}

	if (bRecv == FALSE) {
		printf("Cannot receive icmp echo reply packet.\n");
		free(packet);
		return FALSE;
	}

	IPV4_HDR* ipHdr = (PIPV4_HDR)packet;
	icmpHdr = (PICMP_HDR)(packet + sizeof(IPV4_HDR));
	icmpPayload = (char*)(packet + sizeof(IPV4_HDR) + sizeof(ICMP_HDR));

	if (NULL == inet_ntop(AF_INET, &(ipHdr->ip_destaddr), szIPAddr, INET_ADDRSTRLEN)) {
		printf("inet_ntop error: %d\n", WSAGetLastError());
		free(packet);
		return FALSE;
	}

	free(packet);
	return TRUE;
}

BOOL SendData(char* szData, const char* szSrcAddr, const char* szDstAddr, __int64 dataLen,double *sendRate )
{
	if (dataLen <= 0) {
		printf("No data to be sent...\n");
		return TRUE;
	}

	BOOL ret = FALSE;
	char szHandshakePayload[] = "abcdefghijklmnopqrstuvwabcdefghi";

	// 创建套接字
	SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET) {
		printf("socket failed: %d\n", GetLastError());
		return 1;
	}

	int on = 1;
	if (SOCKET_ERROR == setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof(on))) {
		printf("setsockopt failed: %d\n", GetLastError());
		return INVALID_SOCKET;
	}

	struct sockaddr_in servAddr;
	ZeroMemory(&servAddr, sizeof(struct sockaddr_in));
	servAddr.sin_family = AF_INET;
	inet_pton(AF_INET, szDstAddr, &servAddr.sin_addr.S_un.S_addr);

	if (SOCKET_ERROR == connect(sock, (struct sockaddr*) & servAddr, sizeof(servAddr))) {
		printf("connect error: %d\n", WSAGetLastError());
		return FALSE;
	}
	LARGE_INTEGER large_interger;
	double dff;
	__int64 start, end;
	QueryPerformanceFrequency(&large_interger);
	dff = large_interger.QuadPart;
	QueryPerformanceCounter(&large_interger);
	start = large_interger.QuadPart;
	//clock_t start, end;
	//start = clock();

	// 第1次握手
	ICMPPacket icmpSendPacket;
	ZeroMemory(&icmpSendPacket, sizeof(ICMPPacket));

	strncpy_s(icmpSendPacket.srcAddr, szSrcAddr, strlen(szSrcAddr) + 1);
	strncpy_s(icmpSendPacket.dstAddr, szDstAddr, strlen(szDstAddr) + 1);

	icmpSendPacket.type = ICMPV4_ECHO_REQUEST_TYPE;
	icmpSendPacket.code = ICMPV4_FIRST_HANDSHAKE_CODE;

	icmpSendPacket.payload = szHandshakePayload;
	icmpSendPacket.payloadSize = strlen(szHandshakePayload);

	unsigned short ipID = 0;
	srand((ICMPIDSEED + (unsigned short)time(NULL)) & 0xffff);
	unsigned short icmpID = LOWORD(rand());
	unsigned short icmpSequence = 0x0000;

	ret = SendICMPPacket(sock, &icmpSendPacket, icmpID, icmpSequence, &ipID);
	if (!ret) {
		printf("SendICMPPacket Failed.\n");
		return FALSE;
	}

	// 接收第2次握手
	fd_set rset;
	TIMEVAL timeVal;
	int timeoutCount = 0;

	while (1) {
		/*if (timeoutCount > 2) {
			printf("Bad connection...\n");
			break;
		}*/

		FD_ZERO(&rset);
		FD_SET(sock, &rset);

		timeVal.tv_sec = 1;
		timeVal.tv_usec = 0;

		int retStatus = select(0, &rset, nullptr, nullptr, &timeVal);
		if (retStatus == SOCKET_ERROR) {
			printf("select error: %d\n", WSAGetLastError());
			break;
		}
		if (retStatus == 0) {
			printf("Timeout...\n");
			timeoutCount++;
			continue;
		}
		if (FD_ISSET(sock, &rset)) {
			ICMPPacket icmpRecvPacket;
			ZeroMemory(&icmpRecvPacket, sizeof(ICMPPacket));
			ret = RecvICMPPacket(sock, &icmpRecvPacket);
			if (!ret) {
				printf("RecvICMPPacket Failed!\n");
				break;
			}
			if ((icmpRecvPacket.ip_id != ipID) ||
				(icmpRecvPacket.type != ICMPV4_ECHO_REPLY_TYPE) ||
				(icmpRecvPacket.code != ICMPV4_SECOND_HANDSHAKE_CODE) ||
				(icmpRecvPacket.icmp_id != icmpID) ||
				(icmpRecvPacket.icmp_sequence != icmpSequence)) {
				// 不是期待的第2次握手包
				continue;
			}
			printf("Second Handshake Received!\n");
			free(icmpRecvPacket.payload);
			break;
		}
	}
	if (!ret) {
		printf("Failed to handshake.\n");
		return FALSE;
	}

	// 能进行到这里，说明前两次握手已顺利完成
	// 下面进行第3次握手，声明自己的数据类型和数据块总大小
	ZeroMemory(&icmpSendPacket, sizeof(ICMPPacket));	// 使用第1次握手的icmpSendPacket结构体即可
	strncpy_s(icmpSendPacket.srcAddr, szSrcAddr, strlen(szSrcAddr) + 1);
	strncpy_s(icmpSendPacket.dstAddr, szDstAddr, strlen(szDstAddr) + 1);

	icmpSendPacket.type = ICMPV4_ECHO_REQUEST_TYPE;
	icmpSendPacket.code = ICMPV4_THIRD_HANDSHAKE_CODE_DATA;		// 表示传输的是普通数据，而不是文件

	char szDataLen[MINSIZE] = { 0 };
	memcpy_s(szDataLen, MINSIZE, &dataLen, 8);	// 要发送的数据总长度
	icmpSendPacket.payload = szDataLen;
	icmpSendPacket.payloadSize = MINSIZE;

	ret = SendICMPPacket(sock, &icmpSendPacket, icmpID, icmpSequence, &ipID);
	if (!ret) {
		printf("SendICMPPacket Failed.\n");
		return FALSE;
	}

	// 接收第3次握手包的确认，否则重传
	timeoutCount = 0;
	int retransmitCount = 0;

	while (1) {
		FD_ZERO(&rset);
		FD_SET(sock, &rset);

		timeVal.tv_sec = 1;
		timeVal.tv_usec = 0;

		int retStatus = select(0, &rset, nullptr, nullptr, &timeVal);
		if (retStatus == SOCKET_ERROR) {
			printf("select error: %d\n", WSAGetLastError());
			break;
		}
		if (retStatus == 0) {
			printf("Timeout...\n");
			timeoutCount++;
			continue;
		}
		if (FD_ISSET(sock, &rset)) {
			ICMPPacket icmpRecvPacket;
			ZeroMemory(&icmpRecvPacket, sizeof(ICMPPacket));
			ret = RecvICMPPacket(sock, &icmpRecvPacket);
			if (!ret) {
				printf("RecvICMPPacket Failed!\n");
				break;
			}
			if ((icmpRecvPacket.ip_id != ipID) ||
				(icmpRecvPacket.type != ICMPV4_ECHO_REPLY_TYPE) ||
				(icmpRecvPacket.code != ICMPV4_FOURTH_HANDSHAKE_CODE) ||
				(icmpRecvPacket.icmp_id != icmpID) ||
				(icmpRecvPacket.icmp_sequence != icmpSequence)) {
				// 不是期待的第4次握手包
				continue;
			}
			printf("Fourth Handshake Received!\n");
			free(icmpRecvPacket.payload);
			break;
		}
	}
	if (!ret) {
		printf("Failed to handshake.\n");
		return FALSE;
	}

	// 四次握手结束，接下来发送数据
	__int64 leftBytes = dataLen;
	char* curData = szData;
	icmpSequence = 0x00;

	icmpSendPacket.type = ICMPV4_ECHO_REQUEST_TYPE;
	icmpSendPacket.code = ICMPV4_ECHO_REQUEST_CODE;

	while (1) {
		if (leftBytes <= MAXSIZE && leftBytes > 0) {
			icmpSequence &= 0x7fff;	// 最高位置0

			icmpSendPacket.payload = curData;
			icmpSendPacket.payloadSize = leftBytes;

			ret = SendICMPPacket(sock, &icmpSendPacket, icmpID, icmpSequence, &ipID);
			if (!ret) {
				printf("SendICMPPacket Failed!\n");
				return FALSE;
			}
			break;
		}
		else if (leftBytes > MAXSIZE) {
			icmpSequence |= 0x8000;	// 最高位置1

			icmpSendPacket.payload = curData;
			icmpSendPacket.payloadSize = MAXSIZE;
			curData += MAXSIZE;
			leftBytes -= MAXSIZE;

			ret = SendICMPPacket(sock, &icmpSendPacket, icmpID, icmpSequence, &ipID);
			if (!ret) {
				printf("SendICMPPacket Failed!\n");
				return FALSE;
			}

			icmpSequence = (((icmpSequence + 0x0001) % (32 * 1024)) | 0x8000);	// 最高位置1，表示后面还有分片，低15位取模
		}
	}
	QueryPerformanceCounter(&large_interger);
	end = large_interger.QuadPart;
	double duration;
	duration = (double)(end - start)/dff;
	*sendRate = (double) (dataLen * 8) / duration;
	
	return TRUE;
}

//BOOL SendFileByHandle(SOCKET sock, HANDLE hFile, const char* szSrcAddr, const char* szDstAddr)
//{
//	SYSTEM_INFO sysInfo = { 0 };
//	GetSystemInfo(&sysInfo);
//
//	DWORD dwFileSizeHigh = 0;
//	__int64 qwFileSize = GetFileSize(hFile, &dwFileSizeHigh);
//	qwFileSize += (((__int64)dwFileSizeHigh) << 32);		// support a file that larger than 4GB
//
//	char buf[MAXSIZE] = { 0 };
//	BOOL ret = FALSE;
//
//	ICMPPacket icmpSendPacket;
//	ZeroMemory(&icmpSendPacket, sizeof(ICMPPacket));
//
//	strncpy_s(icmpSendPacket.srcAddr, szSrcAddr, strlen(szSrcAddr) + 1);
//	strncpy_s(icmpSendPacket.dstAddr, szDstAddr, strlen(szDstAddr) + 1);
//
//	icmpSendPacket.type = ICMPV4_ECHO_REQUEST_TYPE;
//
//	// Read the file using memory file mapping theory
//	HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
//	if (hFileMapping == NULL) {
//		printf("CreateFileMapping Error: %d\n", GetLastError());
//		return FALSE;
//	}
//
//	// Read the file based on system allocation granularity
//	DWORD dwBytesInBlock = sysInfo.dwAllocationGranularity;
//	__int64 qwFileOffset = 0;
//	while (qwFileSize > 0) {
//		if (qwFileSize < dwBytesInBlock) {
//			dwBytesInBlock = qwFileSize;
//		}
//
//		LPVOID lpFilePtr = MapViewOfFile(hFileMapping, FILE_MAP_READ,
//			(DWORD)(qwFileOffset >> 32),
//			(DWORD)(qwFileOffset & 0xffffffff),
//			dwBytesInBlock);
//		if (lpFilePtr == NULL) {
//			printf("MapViewOfFile Error: %d\n", GetLastError());
//			CloseHandle(hFileMapping);
//			return FALSE;
//		}
//
//		// process the data
//		char* szSendBuf = (char*)lpFilePtr;
//		ret = SendData(sock, szSendBuf, szSrcAddr, szDstAddr, dwBytesInBlock);
//		if (!ret) {
//			printf("SendData Failed.\n");
//			UnmapViewOfFile(lpFilePtr);
//			return FALSE;
//		}
//		
//		UnmapViewOfFile(lpFilePtr);
//
//		// Continue to map view of file
//		qwFileOffset += dwBytesInBlock;
//		qwFileSize -= dwBytesInBlock;
//	}
//
//	return TRUE;
//}

BOOL ReceiveData()
{
	return TRUE;
}

BOOL WinICMPSendData(LPBYTE pSendBuf, ULONG uCommand, DWORD dwDataLen, int DataType, const char* szServerAddr, int* dwErrorNumber)
{
	if (DataType == 1) {	// 传输文件
		// TODO
	}
	
	char szSrcAddr[16] = { 0 };

	BOOL ret;

	ret = ObtainWorkingIP(szSrcAddr);
	if (ret == FALSE) {
		printf("ObtainWorkingIP Failed.\n");
		*dwErrorNumber = WSAGetLastError();
		return FALSE;
	}
	printf("Local IP address: %s\n", szSrcAddr);
	__int64 totalLen = CommandHash(uCommand, pSendBuf, dwDataLen, &pSendBuf);
	double *Winsendrate;
	Winsendrate = (double*)calloc(1,sizeof(double));
	ret = SendData((char*)pSendBuf, szSrcAddr, szServerAddr, totalLen,Winsendrate);
	if (!ret) {
		printf("SendData Failed.\n");
		*dwErrorNumber = GetLastError();
		return FALSE;
	}
	printf("The transmission has finished,and the sendrate is:%.6f b/s\n",*Winsendrate);


	return TRUE;
}

// To be research:
//		Path MTU Discovery
//		MTU is set 1500 as a constant but it may change during the communication process
//		Currently, we ignore the problem because MTU is usually 1500 in reality
int main()
{
	char ipaddress[16];
	int ip[4];
	while (1) {
		printf("please input the IP you want to send message:");
		scanf_s("%s", ipaddress, 15);
		getchar();
		sscanf_s(ipaddress, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
		if (ip[0] > 255 || ip[1] > 255 || ip[2] > 255 || ip[3] > 255)
		{
			puts("wrong ip! please input a new ip!\n");
			memset(ipaddress, 0, sizeof(ipaddress));
			continue;
		}
		else if (ip[0] < 1 || ip[1] < 0 || ip[2] < 0 || ip[3] < 1)
		{
			puts("wrong ip! please input a new ip!\n");
			memset(ipaddress, 0, sizeof(ipaddress));
			continue;
		}
		else
			break;

	}
	fflush(stdin);
	const char *szServerAddr = ipaddress;
	
	BOOL ret;

	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return -1;
	}

	SOCKET sendSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sendSock == INVALID_SOCKET) {
		printf("socket failed: %d\n", GetLastError());
		return 1;
	}

	int on = 1;
	if (SOCKET_ERROR == setsockopt(sendSock, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof(on))) {
		printf("setsockopt failed: %d\n", GetLastError());
		return INVALID_SOCKET;
	}

	struct sockaddr_in servAddr;
	ZeroMemory(&servAddr, sizeof(struct sockaddr_in));
	servAddr.sin_family = AF_INET;
	inet_pton(AF_INET, szServerAddr, &servAddr.sin_addr.S_un.S_addr);

	// 和TCP的connect不同，这里调用connect用以指定只接收目标IP地址的原始数据包
	ret = connect(sendSock, (struct sockaddr*) & servAddr, sizeof(servAddr));
	if (ret == SOCKET_ERROR) {
		printf("connect error: %d\n", WSAGetLastError());
		system("pause");
		return 2;
	}

	/*char szData[MAXSIZE];
	printf("please input the message you want send:");
	scanf_s("%s",szData,MAXSIZE-1);
	char szPayload[MAXSIZE] = { 0 };
	char szBlockData1[MAXSIZE] = "1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\n";
	char szBlockData2[MAXSIZE] = "2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\n";
	char szBlockData3[MAXSIZE] = "3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\n";
	char szBlockData4[MAXSIZE] = "4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\n";
	char szBlockData5[MAXSIZE] = "5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\n";
	char szHelloWorld[50] = { 0 };
	lstrcpyA(szHelloWorld, "This is a test!\n");
	char szPayload[5*MAXSIZE+50] = { 0 };
	char* pPayload = szPayload;
	//memcpy_s(pPayload, MAXSIZE, szData, MAXSIZE);

	for (auto i = 0; i < 5; i++) {
		if (i == 0) {
			memcpy_s(pPayload + i * MAXSIZE, MAXSIZE, szBlockData1, MAXSIZE);
		}
		else if (i == 1) {
			memcpy_s(pPayload + i * MAXSIZE, MAXSIZE, szBlockData2, MAXSIZE);
		}
		else if (i == 2) {
			memcpy_s(pPayload + i * MAXSIZE, MAXSIZE, szBlockData3, MAXSIZE);
		}
		else if (i == 3) {
			memcpy_s(pPayload + i * MAXSIZE, MAXSIZE, szBlockData4, MAXSIZE);
		}
		else if (i == 4) {
			memcpy_s(pPayload + i * MAXSIZE, MAXSIZE, szBlockData5, MAXSIZE);
		}
		// memcpy_s(pPayload + i * MAXSIZE, MAXSIZE, szBlockData, MAXSIZE);
	}
	memcpy_s(pPayload + 5 * MAXSIZE, 50, szHelloWorld, sizeof("This is a test!"));*/
	while (1) {
		printf("please choose you want to send file(f) or message(m) or quit(q):");
		char sendType;
		scanf_s("%c",&sendType, 1);
		getchar();
		if (sendType == 'f') {
			FILE *fp;
			errno_t err;
			char fname[100];
			char fileData1[MAXSIZE];
			char fileData2[MAXSIZE];
			printf("please input the filename:");
			scanf_s("%s", fname, 100);
			err = fopen_s(&fp, fname, "rb");
			unsigned int current_read_position = ftell(fp);
			long  file_size;
			fseek(fp, 0, SEEK_END);
			file_size = ftell(fp);
			fseek(fp, current_read_position, SEEK_SET);
			DWORD dwDataLen = file_size;
			LPBYTE pSendBuf = (LPBYTE)zalloc(dwDataLen);
			if (pSendBuf == NULL) {
				printf("zalloc error.\n");
				system("pause");
				return -1;
			}
			char *szPayload = (char*)calloc(dwDataLen, sizeof(char));
			if (szPayload == NULL) {
				printf("zalloc error.\n");
				system("pause");
				return -1;
			}
			if (err == 0) {
				printf("open the file successfully!\n");
				DWORD datalen = dwDataLen;
				for (int i = 0; i <= (datalen / MAXSIZE); i++) {
					if (datalen < MAXSIZE) {
						char *fileData = (char*)calloc(datalen, sizeof(char));
						fread(fileData,1, datalen,fp);
						memcpy_s(szPayload+ i*MAXSIZE, datalen,fileData, datalen);
						free(fileData);
					}
					else{
						char *fileData = (char*)calloc(MAXSIZE, sizeof(char));
						fread(fileData, 1, MAXSIZE, fp);
						memcpy_s(szPayload + i * MAXSIZE, MAXSIZE, fileData, MAXSIZE);
						free(fileData);
						datalen -= MAXSIZE;
					}
				}
				fclose(fp);

				memcpy_s(pSendBuf, dwDataLen, szPayload, dwDataLen);

				int dwOut = 0;
				ret = WinICMPSendData(pSendBuf, 0, dwDataLen, 0, szServerAddr, &dwOut);
				if (!ret) {
					printf("WinICMPSendData Failed. Error information: %d\n", dwOut);
					system("pause");
					return -1;
				}
			}
			else
				printf("open the file failed!\n");
		}
		else if (sendType == 'm') {
			char mesData[MAXSIZE];
			printf("please input the message:");
			gets_s(mesData, MAXSIZE);
			DWORD dwDataLen = strlen(mesData);
			LPBYTE pSendBuf = (LPBYTE)zalloc(dwDataLen);
			if (pSendBuf == NULL) {
				printf("zalloc error.\n");
				system("pause");
				return -1;
			}
			char szPayload[MAXSIZE] = { 0 };
			memcpy_s(szPayload, dwDataLen, mesData, dwDataLen);
			memcpy_s(pSendBuf, dwDataLen, szPayload, dwDataLen);

			int dwOut = 0;
			ret = WinICMPSendData(pSendBuf, 0, dwDataLen, 0, szServerAddr, &dwOut);
			if (!ret) {
				printf("WinICMPSendData Failed. Error information: %d\n", dwOut);
				system("pause");
				return -1;
			}
		}
		else if (sendType == 'q')
			break;
		else 
			printf("wrong choice!\n");
		
		/*DWORD dwDataLen = 5 * MAXSIZE + 50;
		LPBYTE pSendBuf = (LPBYTE)zalloc(dwDataLen);
		if (pSendBuf == NULL) {
			printf("zalloc error.\n");
			system("pause");
			return -1;
		}

		memcpy_s(pSendBuf, dwDataLen, szPayload, dwDataLen);

		int dwOut = 0;
		ret = WinICMPSendData(pSendBuf, 0, dwDataLen, 0, szServerAddr, &dwOut);
		if (!ret) {
			printf("WinICMPSendData Failed. Error information: %d\n", dwOut);
			system("pause");
			return -1;
		}*/


		/*fd_set rset;
		TIMEVAL timeVal;

		int timeoutCount = 0;

		while (1) {
			if (timeoutCount > 2) {
				break;
			}

			FD_ZERO(&rset);
			FD_SET(sendSock, &rset);

			timeVal.tv_sec = 1;
			timeVal.tv_usec = 0;

			int retStatus = select(0, &rset, nullptr, nullptr, &timeVal);
			if (retStatus == SOCKET_ERROR) {
				printf("select error: %d\n", WSAGetLastError());
				break;
			}
			if (retStatus == 0) {
				printf("Timeout...\n");
				timeoutCount++;
				continue;
			}
			if (FD_ISSET(sendSock, &rset)) {
				ICMPPacket icmpRecvPacket;
				ZeroMemory(&icmpRecvPacket, sizeof(ICMPPacket));
				ret = RecvICMPPacket(sendSock, &icmpRecvPacket);
				if (!ret) {
					printf("RecvICMPPacket Failed!\n");
					system("pause");
					return 3;
				}
				printf("[sendSock] An ICMP echo reply packet from %s received.\n", icmpRecvPacket.srcAddr);
				printf("IP ID: 0x%x\n", icmpRecvPacket.ip_id);
				printf("ICMP Identifier: 0x%x\n", icmpRecvPacket.icmp_id);
				printf("ICMP Sequence: 0x%x\n", icmpRecvPacket.icmp_sequence);
				printf("payload size: %d\n", icmpRecvPacket.payloadSize);
				printf("%.*s\n", icmpRecvPacket.payloadSize, icmpRecvPacket.payload);
				free(icmpRecvPacket.payload);
			}
		}*/
		getchar();
	}
	system("pause");
	return 0;
}
