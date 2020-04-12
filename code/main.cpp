#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "iphdr.h"
#include <time.h>
#include <functional>
#include <pthread.h>
#include <map>
#include <queue>
#include <iostream>

constexpr int MTU = 1500;
constexpr int MAXSIZE = MTU - sizeof(ip_hdr) - sizeof(icmp_hdr);	// �������ݰ����ݲ�����󳤶�
constexpr unsigned short IPIDSEED = 12345;
constexpr unsigned short ICMPIDSEED = 54321;
constexpr int MAXTHREAD = 256;

typedef struct icmp_packet {
	char src_addr[INET_ADDRSTRLEN];
	char dst_addr[INET_ADDRSTRLEN];
	unsigned char type;
	unsigned char code;
	unsigned short ip_id;
	unsigned short  icmp_identifier;
	unsigned short  icmp_sequence;
	char* payload;
	unsigned short payload_size;
} icmp_packet, * picmp_packet;

typedef struct big_packet {
	char src_addr[INET_ADDRSTRLEN];
	char dst_addr[INET_ADDRSTRLEN];
	unsigned char type;
	unsigned char code;
	unsigned short ip_id;
	unsigned short  icmp_identifier;
	unsigned short  icmp_sequence;
	char* payload;
	unsigned long payload_size;
} big_packet, * pbig_packet;

typedef struct icmp_frag {
	icmp_packet packet;
	icmp_frag* next;
} icmp_frag;

// ��¼�ѷ�����̵߳ķ�Ƭ���к�
int queue_record[MAXTHREAD] = { 0 };

// ��Ƭ���е�����
std::queue<icmp_packet> icmp_packet_queue[MAXTHREAD];

// ���ݰ����еĹ�ϣ�洢����ײ����
typedef struct packet_abstract {
	pthread_t tid;
	unsigned short icmp_identifier;
	unsigned short ip_id;
	char src_addr[INET_ADDRSTRLEN];
	char dst_addr[INET_ADDRSTRLEN];
	packet_abstract* next;
} packet_abstract;

packet_abstract* hash_array[MAXTHREAD] = { NULL };
//std::map<std::size_t, pthread_t> id_thread_map;
std::map<pthread_t, int> tid_index_map;

// ������
pthread_mutex_t mutex;

// ���߳̽������ݰ�����
void* data_receive_func(void* ptr);

// ���������ݰ��ľ��崦����
void process_whole_packet(big_packet packet);

icmp_frag* create_icmp_frag()
{
	icmp_frag* head = (icmp_frag*)malloc(sizeof(icmp_frag));
	if (head == NULL) {
		printf("malloc error: %d\n", errno);
		return NULL;
	}

	icmp_packet p;
	memset(&p, 0, sizeof(icmp_packet));
	head->packet = p;
	head->next = NULL;

	return head;
}

bool insert_icmp_frag(icmp_frag* head, icmp_packet packet)
{
	icmp_frag* picmp_frag = (icmp_frag*)malloc(sizeof(icmp_frag));
	if (picmp_frag == NULL) {
		printf("malloc error:%d\n", errno);
		return false;
	}

	memcpy(&picmp_frag->packet, &packet, sizeof(icmp_packet));
	strcpy(picmp_frag->packet.src_addr, packet.src_addr);
	strcpy(picmp_frag->packet.dst_addr, packet.dst_addr);
	picmp_frag->packet.payload = (char*)malloc(picmp_frag->packet.payload_size);
	memcpy(picmp_frag->packet.payload, packet.payload, picmp_frag->packet.payload_size);
	picmp_frag->next = NULL;

	printf("\nSource IP: %s\n", picmp_frag->packet.src_addr);
	printf("IP Identifier: 0x%x\n", picmp_frag->packet.ip_id);
	printf("ICMP Identifier: 0x%x\n", picmp_frag->packet.icmp_identifier);
	printf("ICMP Sequence: 0x%x\n", picmp_frag->packet.icmp_sequence);
	printf("Data length: %d\n", picmp_frag->packet.payload_size);
	//printf("playload:%.*s\n", picmp_frag->packet.payload_size, picmp_frag->packet.payload);

	if (head->next == NULL) {
		head->next = picmp_frag;
		return true;
	}

	icmp_frag* cur = head->next;
	icmp_frag* prev = head;
	while (cur != NULL) {
		if (packet.icmp_sequence > cur->packet.icmp_sequence) {
			if (cur->next == NULL) {		// �Ѿ�����β
				cur->next = picmp_frag;
				return true;
			}
			else {
				cur = cur->next;
				prev = prev->next;
			}
		}
		else {
			picmp_frag->next = cur;
			prev->next = picmp_frag;
			return true;
		}
	}
}

bool reassembly_icmp_frag(icmp_frag* head, big_packet* ppacket)
{
	if ((head == NULL) || (head->next == NULL)) {
		printf("Empty fragment link list.\n");
		return false;
	}

	ppacket->payload = (char*)malloc(ppacket->payload_size * sizeof(char));
	if (ppacket->payload == NULL) {
		printf("malloc error.\n");
		return false;
	}

	char* cur_payload = ppacket->payload;

	icmp_frag* cur = head;
	while (cur->next != NULL) {
		memcpy(cur_payload, cur->next->packet.payload, cur->next->packet.payload_size);
		cur_payload += cur->next->packet.payload_size;
		cur = cur->next;
	}

	return true;
}

unsigned short calc_checksum(unsigned short* data, int len)
{
	int nleft = len;
	unsigned int sum = 0;
	unsigned short* w = data;
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

int my_hash(unsigned short ip_id, unsigned short icmp_identifier)
{
	std::size_t h1 = std::hash<unsigned short>{}(ip_id);
	std::size_t h2 = std::hash<unsigned short>{}(icmp_identifier);

	return (h1 ^ (h2 << 1)) % MAXTHREAD;
}

void prepare_headers(ip_hdr* ipHdr, unsigned short* pIpID)
{
	ipHdr->ip_verlen = 0x45;
	ipHdr->ip_tos = 0;
	// ipHdr->ip_totallength�ɵ��øú�����������д
	while ((*pIpID) == 0) {	// �Է��������ԣ�ͨ����������ѭ������Ϊ�����pIpID���Ǵӿͻ��������ȡ��
		srand((IPIDSEED + (unsigned short)time(NULL)) & 0xffff);
		*pIpID = (rand() & 0xffff);
	}
	ipHdr->ip_id = htons(*pIpID);
	ipHdr->ip_offset = 0;
	ipHdr->ip_ttl = 128;
	ipHdr->ip_protocol = IPPROTO_ICMP;
	// ipHdr->ip_checksum, ip_srcaddr, ip_destaddr�ɸú�����������д
}

bool recv_icmp_packet(int sock_fd, icmp_packet* icmpPacket)
{
	int ip_datagram_len = MTU;
	char* packet = (char *)calloc(ip_datagram_len, sizeof(uint8_t));
	if (packet == nullptr) {
		printf("No memory to allocate.\n");
		return false;
	}

	socklen_t src_addr_size = sizeof(struct sockaddr_in);
	struct sockaddr_in src_addr;
	memset(&src_addr, 0, src_addr_size);

	ssize_t packet_size = recvfrom(sock_fd, packet, ip_datagram_len, 0, (sockaddr*)&src_addr, &src_addr_size);
	if (packet_size == -1) {
		printf("recvfrom error: %d\n", errno);
		free(packet);
		return false;
	}

	ip_hdr* ipHdr = (ip_hdr*)packet;
	icmp_hdr* icmpHdr = (icmp_hdr*)(packet + sizeof(ip_hdr));
	char* icmp_payload = (char*)(packet + sizeof(ip_hdr) + sizeof(icmp_hdr));

	inet_ntop(AF_INET, &(ipHdr->ip_srcaddr), icmpPacket->src_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ipHdr->ip_destaddr), icmpPacket->dst_addr, INET_ADDRSTRLEN);

	icmpPacket->ip_id = ntohs(ipHdr->ip_id);
	icmpPacket->type = icmpHdr->icmp_type;
	icmpPacket->code = icmpHdr->icmp_code;
	icmpPacket->icmp_identifier = ntohs(icmpHdr->icmp_identifier);
	icmpPacket->icmp_sequence = ntohs(icmpHdr->icmp_sequence);
	
	icmpPacket->payload_size = packet_size - sizeof(ip_hdr) - sizeof(icmp_hdr);
	icmpPacket->payload = (char*)calloc(icmpPacket->payload_size, sizeof(uint8_t));
	if (icmpPacket->payload == nullptr) {
		printf("No memory to allocate.\n");
		ipHdr = nullptr;
		icmpHdr = nullptr;
		icmp_payload = nullptr;
		free(packet);
		return false;
	}
	
	memcpy(icmpPacket->payload, icmp_payload, icmpPacket->payload_size);

	ipHdr = nullptr;
	icmpHdr = nullptr;
	icmp_payload = nullptr;
	free(packet);

	return true;
}

bool send_icmp_packet(int sock_fd, icmp_packet* icmpPacket)
{
	in_addr src_addr;
	in_addr dst_addr;

	inet_pton(AF_INET, icmpPacket->src_addr, &src_addr);
	inet_pton(AF_INET, icmpPacket->dst_addr, &dst_addr);

	unsigned short packet_size = sizeof(ip_hdr) + sizeof(icmp_hdr) + icmpPacket->payload_size;
	char* packet = (char*)calloc(packet_size, sizeof(char));
	if (packet == nullptr) {
		printf("No memory to allocate.\n");
		return false;
	}

	ip_hdr* ipHdr = (ip_hdr*)packet;
	icmp_hdr* icmpHdr = (icmp_hdr*)(packet + sizeof(ip_hdr));
	char* icmp_payload = (char*)(packet + sizeof(ip_hdr) + sizeof(icmp_hdr));

	prepare_headers(ipHdr, &(icmpPacket->ip_id));

	ipHdr->ip_totallength = htons(packet_size);
	ipHdr->ip_srcaddr = src_addr.s_addr;
	ipHdr->ip_destaddr = dst_addr.s_addr;

	icmpHdr->icmp_type = icmpPacket->type;
	icmpHdr->icmp_code = icmpPacket->code;
	icmpHdr->icmp_identifier = htons(icmpPacket->icmp_identifier);
	icmpHdr->icmp_sequence = htons(icmpPacket->icmp_sequence);

	// �����Ƚ�������ã�����checksum������Ǵ��
	memcpy(icmp_payload, icmpPacket->payload, icmpPacket->payload_size);

	icmpHdr->icmp_checksum = calc_checksum((unsigned short*)icmpHdr, sizeof(icmp_hdr) + icmpPacket->payload_size);

	struct sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(struct sockaddr_in));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = dst_addr.s_addr;

	// ����sendto��������
	ssize_t ret_size = sendto(sock_fd, packet, packet_size, 0, (const sockaddr*)&client_addr, sizeof(struct sockaddr_in));
	if (ret_size == -1) {
		printf("sendto error: %d\n", errno);
		return false;
	}

	ipHdr = nullptr;
	icmpHdr = nullptr;
	icmp_payload = nullptr;
	free(packet);

	return true;
}

// ����ICMP��ͨ��Э�飺
//		1. �ͻ��˷������֣���1�����֣���ָ��type�ֶ�ΪICMPV4_ECHO_REQUEST_TYPE��code�ֶ�Ϊ1
//		2. ����������Ӧ���ְ�����2�����֣���ָ��type�ֶ�ΪICMPV4_ECHO_REPLY_TYPE��code�ֶ�Ϊ2��
//			icmp_identifier��icmp_sequenceӦ�͵�1�����ְ���ͬ
//		3. �ͻ��˶Է����������ְ�����2�����֣�������Ӧ����3�����֣���ָ��type�ֶ�ΪICMPV4_ECHO_REQUEST_TYPE��
//			code�ֶ�Ϊ3��ʾ��ͨ���ݣ�code�ֶ�Ϊ4��ʾ�ļ������ݲ��ֵ�ǰ8�ֽڱ�ʾ���ݿ���ܴ�С��
//			�������˶Ե�3�����ְ�����ȷ�ϣ���4�����֣�����ȷ�����߳��յ��ĵ�һ����һ���ǵ�3�����ְ���
//			ָ��type�ֶ�ΪICMPV4_ECHO_REPLY_TYPE��code�ֶ�Ϊ4
//		4. �ͻ��˽������ݴ��䣬ָ��type�ֶ�ΪICMPV4_ECHO_REQUEST_TYPE��code�ֶ�Ϊ0
//		5. ����������δ�յ��ڴ������ݰ����кţ���ָ��type�ֶ�ΪICMPV4_ECHO_REPLY_TYPE��code�ֶ�Ϊ127��
//			���ݲ���ǰ2���ֽڵĵ�15λ��ʾδ�յ������к����ݰ������λʼ��Ϊ0
//		6. �ͻ���Ӧ���ѷ������ݰ�����ź�ָ����ӳ�䴦�����ر������ݣ����е�5�������ݴ������ʱ�ɽ����ش�
//		7. ���ó�ʱ�ش�����

// ���߳����̣�
//		1. ����ѭ������ICMP���ݰ�
//		2. �������յ������ݰ����ж����ݰ����ͣ�
//			2.1 ��Ϊ��1�����ְ����򴴽����̣߳���������ݰ���(ip_id, icmp_id)��Ԫ���hash��
//				 ����hash�����߳�tid��ӳ�䣬������ӳ����뵽�����У�
//				 ������һ��������Ӧ������2�����ְ���
//			2.2 ���������ְ�����������ݰ���ip_id�����Ҷ�Ӧ�����߳�tid��
//				2.2.1 ���ҵ���Ӧ�����߳�tid�������ݰ��������̴߳���
//				2.2.2 ��δ�ҵ���Ӧ�����߳�tid���򷵻�һ���������ݰ����ÿͻ������·�
//		3. �������̵߳Ľ���֪ͨ
int main()
{
	//std::map<std::size_t, pthread_t> id_thread_map;
	//std::map<pthread_t, int> tid_index_map;
	if (pthread_mutex_init(&mutex, NULL) != 0) {
		printf("initialize mutex error: %d\n", errno);
		return -1;
	}

	int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock_fd == -1) {
		printf("socket error: %d\n", errno);
		int c = getchar();
		return -1;
	}

	int on = 1;
	if (-1 == setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))) {
		printf("setsockopt error: %d\n", errno);
		int c = getchar();
		return -1;
	}

	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(struct sockaddr_in));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (-1 == bind(sock_fd, (const sockaddr*)&serv_addr, sizeof(struct sockaddr_in))) {
		printf("bind error: %d\n", errno);
		int c = getchar();
		return -1;
	}

	// ��ѭ��
	bool ret = false;
	while (true) {
		icmp_packet icmp_recv_packet;
		memset(&icmp_recv_packet, 0, sizeof(icmp_packet));

		ret = recv_icmp_packet(sock_fd, &icmp_recv_packet);
		if (!ret) {
			printf("recv_icmp_packet failed.\n");
			break;
		}

		if ((icmp_recv_packet.type == ICMPV4_ECHO_REQUEST_TYPE) &&
			(icmp_recv_packet.code == ICMPV4_FIRST_HANDSHAKE_CODE)) {
			// �յ���1�����ְ�
			printf("An ICMP 1st handshake packet received!\n");
			printf("Source IP: %s\n", icmp_recv_packet.src_addr);
			printf("IP Identifier: 0x%x\n", icmp_recv_packet.ip_id);
			printf("ICMP Identifier: 0x%x\n", icmp_recv_packet.icmp_identifier);
			printf("ICMP Sequence: 0x%x\n", icmp_recv_packet.icmp_sequence);
			printf("%.*s\n", icmp_recv_packet.payload_size, icmp_recv_packet.payload);

			// Ȼ�󴴽����̣߳���������id��hashֵ
			unsigned short ip_id = icmp_recv_packet.ip_id;
			unsigned short icmp_identifier = icmp_recv_packet.icmp_identifier;
			int id_hash = my_hash(ip_id, icmp_identifier);
			printf("id hash: %d\n", id_hash);

			// �����������ݣ�Ϊ���̷߳������ݶ���
			int i = 0;
			for (i = 0; i < MAXTHREAD; i++) {
				
				if (queue_record[i] == 0) {
					pthread_mutex_lock(&mutex);

					printf("allocated index: %d\n", i);
					queue_record[i] = 1;	// ��λ����֤��һ�����̲���ʹ��
					// ��ʼ��icmp_packet_queue[i]
					while (!icmp_packet_queue[i].empty()) {	// ȷ�϶��б����
						icmp_packet_queue[i].pop();
					}

					// create subthread������icmp_packet_queue[i]��������߳�
					printf("Creating new thread...\n");
					pthread_t tid = 0;
					int ret = pthread_create(&tid, nullptr, data_receive_func, (void*)&i);
					if (ret != 0) {
						printf("pthread_create error: %d\n", ret);	// ����ֵ��������Ϣ
						i = MAXTHREAD;
						break;
					}
					printf("Create new thread successfully! Thread id: %ld\n", tid);

					packet_abstract* cur;
					if (hash_array[id_hash] == NULL) {
						hash_array[id_hash] = (packet_abstract*)malloc(sizeof(packet_abstract));
						if (hash_array[id_hash] == NULL) {
							printf("malloc error.\n");
							break;
						}

						memset(hash_array[id_hash], 0, sizeof(packet_abstract));
						hash_array[id_hash]->ip_id = ip_id;
						hash_array[id_hash]->icmp_identifier = icmp_identifier;
						strcpy(hash_array[id_hash]->src_addr, icmp_recv_packet.src_addr);
						strcpy(hash_array[id_hash]->dst_addr, icmp_recv_packet.dst_addr);
						hash_array[id_hash]->next = NULL;
						cur = hash_array[id_hash];
					}
					else {
						if (hash_array[id_hash]->ip_id == ip_id &&
							hash_array[id_hash]->icmp_identifier == icmp_identifier &&
							!strcmp(hash_array[id_hash]->src_addr, icmp_recv_packet.src_addr) &&
							!strcmp(hash_array[id_hash]->dst_addr, icmp_recv_packet.dst_addr)) {
							// �ظ���ǡ��ip_id��icmp_id����ͻ�����ְ�
							// ֱ�Ӷ������ͻ��˼�ⳬʱ��������ip_id��icmp_id
							continue;
						}
						else {
							// ��չ������hash��ײ
							cur = hash_array[id_hash];
							while (cur->next != NULL) {
								cur = cur->next;
							}

							cur->next = (packet_abstract*)malloc(sizeof(packet_abstract));
							if (cur->next == NULL) {
								printf("malloc error.\n");
								break;
							}

							cur = cur->next;
							memset(cur, 0, sizeof(packet_abstract));
							cur->ip_id = ip_id;
							cur->icmp_identifier = icmp_identifier;
							strcpy(cur->src_addr, icmp_recv_packet.src_addr);
							strcpy(cur->dst_addr, icmp_recv_packet.dst_addr);
							cur->next = NULL;
						}
					}

					// ���hashֵ��tid��ӳ��
					cur->tid = tid;

					//id_thread_map[id_hash] = tid;
					tid_index_map[tid] = i;
					
					pthread_mutex_unlock(&mutex);
					// ���̲߳��صȴ����߳̽����������������߳����

					break;
				}
			}
			if (i == MAXTHREAD) {
				printf("Cannot create new thread.\n");
				// ���ر������ݰ�

				break;
			}

			// ���͵�2�����ְ�
			printf("Sending the second handshake packet...\n");
			icmp_packet icmp_send_packet;
			memset(&icmp_send_packet, 0, sizeof(icmp_packet));

			strcpy(icmp_send_packet.src_addr, icmp_recv_packet.dst_addr);
			strcpy(icmp_send_packet.dst_addr, icmp_recv_packet.src_addr);

			icmp_send_packet.ip_id = icmp_recv_packet.ip_id;
			icmp_send_packet.type = ICMPV4_ECHO_REPLY_TYPE;
			icmp_send_packet.code = ICMPV4_SECOND_HANDSHAKE_CODE;
			icmp_send_packet.icmp_identifier = icmp_recv_packet.icmp_identifier;
			icmp_send_packet.icmp_sequence = icmp_recv_packet.icmp_sequence;
			icmp_send_packet.payload_size = icmp_recv_packet.payload_size;
			icmp_send_packet.payload = (char*)malloc(icmp_send_packet.payload_size);
			if (icmp_send_packet.payload == NULL) {
				printf("malloc error.\n");
				break;
			}
			memcpy(icmp_send_packet.payload, icmp_recv_packet.payload, icmp_send_packet.payload_size);

			send_icmp_packet(sock_fd, &icmp_send_packet);
			continue;
		}

		if ((icmp_recv_packet.type == ICMPV4_ECHO_REQUEST_TYPE) &&
			(icmp_recv_packet.code == ICMPV4_THIRD_HANDSHAKE_CODE_DATA)) {
			// �յ���3�����ְ�
			printf("An ICMP 3rd handshake packet received! Prepare to receive raw data.\n");
			printf("Source IP: %s\n", icmp_recv_packet.src_addr);
			printf("IP Identifier: 0x%x\n", icmp_recv_packet.ip_id);
			printf("ICMP Identifier: 0x%x\n", icmp_recv_packet.icmp_identifier);
			printf("ICMP Sequence: 0x%x\n", icmp_recv_packet.icmp_sequence);
			//printf("%.*s\n", icmp_recv_packet.payload_size, icmp_recv_packet.payload);
			
			pthread_t tid = 0;
			unsigned short ip_id = icmp_recv_packet.ip_id;
			unsigned short icmp_identifier = icmp_recv_packet.icmp_identifier;
			int id_hash = my_hash(ip_id, icmp_identifier);
			printf("id hash: %d\n", id_hash);

			pthread_mutex_lock(&mutex);

			packet_abstract* cur = hash_array[id_hash];
			while (cur != NULL) {
				if (cur->ip_id == ip_id &&
					cur->icmp_identifier == icmp_identifier &&
					!strcmp(cur->src_addr, icmp_recv_packet.src_addr) &&
					!strcmp(cur->dst_addr, icmp_recv_packet.dst_addr)) {
					tid = cur->tid;
					break;
				}
				else {
					cur = cur->next;
				}
			}
			if (cur == NULL) {
				// û�е�һ�����ְ��ĵ��������ְ���ֱ�Ӷ���
				continue;
			}

			/*auto it = id_thread_map.find(id_hash);
			if (it != id_thread_map.end()) {
				tid = (*it).second;
			}
			else {
				printf("No tid found.\n");
			}*/

			int index = tid_index_map[tid];

			icmp_packet_queue[index].push(icmp_recv_packet);

			pthread_mutex_unlock(&mutex);

			// ���ͶԵ�3�����ְ���ȷ�ϣ��ͻ����յ�ȷ�Ϻ�Ÿҷ����ݣ���ȷ�����߳��յ��ĵ�һ�����ݰ�һ���ǵ�3�����ְ�
			icmp_packet icmp_send_packet;
			memset(&icmp_send_packet, 0, sizeof(icmp_packet));

			strcpy(icmp_send_packet.src_addr, icmp_recv_packet.dst_addr);
			strcpy(icmp_send_packet.dst_addr, icmp_recv_packet.src_addr);

			icmp_send_packet.ip_id = icmp_recv_packet.ip_id;
			icmp_send_packet.type = ICMPV4_ECHO_REPLY_TYPE;
			icmp_send_packet.code = ICMPV4_FOURTH_HANDSHAKE_CODE;	// ��4������
			icmp_send_packet.icmp_identifier = icmp_recv_packet.icmp_identifier;
			icmp_send_packet.icmp_sequence = icmp_recv_packet.icmp_sequence;
			icmp_send_packet.payload_size = icmp_recv_packet.payload_size;
			icmp_send_packet.payload = (char*)malloc(icmp_send_packet.payload_size);
			if (icmp_send_packet.payload == NULL) {
				printf("malloc error.\n");
				break;
			}
			memcpy(icmp_send_packet.payload, icmp_recv_packet.payload, icmp_send_packet.payload_size);

			send_icmp_packet(sock_fd, &icmp_send_packet);
			continue;
		}
		
		if ((icmp_recv_packet.type == ICMPV4_ECHO_REQUEST_TYPE) &&
			(icmp_recv_packet.code == ICMPV4_THIRD_HANDSHAKE_CODE_FILE)) {
			printf("An ICMP 3rd handshake packet received! Prepare to receive a file.\n");
		}
		
		if ((icmp_recv_packet.type == ICMPV4_ECHO_REQUEST_TYPE) &&
			(icmp_recv_packet.code == ICMPV4_ECHO_REQUEST_CODE)) {
			// �յ���ͨ���ݰ����ļ����ݰ�
			printf("An ICMP content packet received!\n");
			pthread_t tid = 0;
			unsigned short ip_id = icmp_recv_packet.ip_id;
			unsigned short icmp_identifier = icmp_recv_packet.icmp_identifier;
			int id_hash = my_hash(ip_id, icmp_identifier);
			printf("id hash: %d\n", id_hash);

			packet_abstract* cur = hash_array[id_hash];
			while (cur != NULL) {
				if (cur->ip_id == ip_id &&
					cur->icmp_identifier == icmp_identifier &&
					!strcmp(cur->src_addr, icmp_recv_packet.src_addr) &&
					!strcmp(cur->dst_addr, icmp_recv_packet.dst_addr)) {
					tid = cur->tid;
					break;
				}
				else {
					cur = cur->next;
				}
			}
			if (cur == NULL) {
				// û�е�һ�����ְ�����ͨ���ݰ���ֱ�Ӷ���
				continue;
			}

			/*auto it = id_thread_map.find(id_hash);
			if (it != id_thread_map.end()) {
				tid = (*it).second;
			}
			else {
				printf("No tid found.\n");
				break;
			}*/

			printf("Find tid: %ld\n", tid);
			int index = tid_index_map[tid];
			printf("index: %d\n", index);

			pthread_mutex_lock(&mutex);

			icmp_packet_queue[index].push(icmp_recv_packet);

			pthread_mutex_unlock(&mutex);

			/*printf("Source IP: %s\n", icmp_recv_packet.src_addr);
			printf("IP Identifier: 0x%x\n", icmp_recv_packet.ip_id);
			printf("ICMP Identifier: 0x%x\n", icmp_recv_packet.icmp_identifier);
			printf("ICMP Sequence: 0x%x\n", icmp_recv_packet.icmp_sequence);
			printf("Payload: %.*s\n", icmp_recv_packet.payload_size, icmp_recv_packet.payload);*/
		}
		
		if (icmp_recv_packet.type != ICMPV4_ECHO_REQUEST_TYPE) {
			printf("An ICMP packet received! Type code: %d\n", icmp_recv_packet.type);
		}
	}

    printf("hello from ICMPCommunicationServer!\n");
	int c = getchar();
    return 0;
}

// ���߳����̣�
//		1. ����ѭ���ȴ��������ݰ�
//		2. �������ݰ����õ�ICMPͷ�����ֺ����ݲ���
//		3. ��Ϊ��3�����ְ�����ȡ�����������ֶΣ��ļ�����ͨ���ݣ��������ܳ����ֶΣ�������
//		4. ���ó�ʼ�ڴ�����һ�����кŵĵ�15λΪ0
//		5. �ж�ICMPͷ����icmp_sequence�����λ�Ƿ�Ϊ1����Ϊ1����鿴��15λ�Ƿ�Ϊ�ڴ�����һ�����кŵĵ�15λ
//		6. ���յ������ݰ����к����ڴ�����һ�����ݰ����кŲ�ƥ�䣬�򽫵�ǰ���յ������ݰ����л���
// ������
//		*ptr��ʾvector����ţ���ʾ���߳�Ӧ�ô�������ݰ�����
// �����Ƭʱ��Ҫ��¼�����ݣ�
//		Ҫ�������ݵ��ܳ���
//		�ѽ��յ������ܳ���
//		�Ƿ��Ѿ����յ��˵�һ����
//		�Ƿ��Ѿ����յ������һ����
//		�ѽ��յ�icmp_sequence���ж���Ҫ�ش������ݰ���
void* data_receive_func(void* ptr)
{
	pthread_detach(pthread_self());	// ʹ�߳��������̣߳��˳����Զ��ͷŶ�̬�ڴ�ռ�

	int queue_id = *(int*)ptr;
	unsigned short expect_sequence = (unsigned short)0x0000;

	icmp_frag* icmp_frag_link_list_head = create_icmp_frag();
	if (icmp_frag_link_list_head == NULL) {
		printf("create_icmp_frag error.\n");
		// ֪ͨ���߳��������
		// �������������ʱ�������������ʱ����
		pthread_exit(NULL);
	}

	while (icmp_packet_queue[queue_id].empty()) {
		continue;	// quit circle if icmp_packet_queue[queue_id] not empty
	}

	// ���յ�3�����ְ�����Э��Ϳͻ��˴�������֤�����е�1����һ���ǵ�3�����ְ���
	pthread_mutex_lock(&mutex);
	icmp_packet third_packet = icmp_packet_queue[queue_id].front();
	icmp_packet_queue[queue_id].pop();
	pthread_mutex_unlock(&mutex);

	// ȡ�������ܳ����ֶ�
	unsigned long total_len = 0;
	memcpy(&total_len, third_packet.payload, 8);
	printf("\nTotal data length: %ld\n", total_len);

	// ����Ҫ�������ݰ�������
	unsigned long total_packet;
	if (total_len % MAXSIZE == 0) {
		total_packet = total_len / MAXSIZE;
	}
	else {
		total_packet = total_len / MAXSIZE + 1;
	}
	printf("Total packet number: %ld\n", total_packet);

	// ��¼���ݰ��Ľ���״̬��ÿ���±��Ӧicmp_sequence��ȫ����ʼ��Ϊ0����ʾ��û���յ�
	std::vector<int> recv_record(total_packet, 0);
	unsigned long recv_len = 0;
	unsigned long recv_packet_count = 0;

	// ѭ���������ݰ�
	bool status = false;
	int sleep_count = 0;
	while (true) {
		if (icmp_packet_queue[queue_id].empty()) {
			if (sleep_count > 2) {
				// ���ͱ����
				// TODO
				break;
			}
			sleep_count++;
			sleep(1);
			continue;
		}

		sleep_count = 0;

		pthread_mutex_lock(&mutex);
		icmp_packet packet = icmp_packet_queue[queue_id].front();

		//pthread_mutex_lock(&mutex);
		icmp_packet_queue[queue_id].pop();
		pthread_mutex_unlock(&mutex);

		if ((packet.type == ICMPV4_ECHO_REQUEST_TYPE) &&
			(packet.code == ICMPV4_THIRD_HANDSHAKE_CODE_DATA)) {
			printf("repeated third handshake packet.\n");
			continue;
		}

		/*printf("\nSource IP: %s\n", packet.src_addr);
		printf("IP Identifier: %d\n", packet.ip_id);
		printf("ICMP Identifier: %d\n", packet.icmp_identifier);
		printf("ICMP Sequence: 0x%x\n", packet.icmp_sequence);
		printf("Data length: %d\n", packet.payload_size);*/

		// �������к�
		packet.icmp_sequence &= 0x7fff;
		unsigned short sequence = packet.icmp_sequence;
		if (recv_record[sequence] != 1) {
			// �����ݰ���ӵ��������ݰ���������
			status = insert_icmp_frag(icmp_frag_link_list_head, packet);
			if (!status) {
				// malloc����
				printf("insert_icmp_frag error.\n");
				break;
			}
			
			recv_record[sequence] = 1;
			recv_packet_count++;
			recv_len += packet.payload_size;
			if ((recv_packet_count == total_packet) && (recv_len == total_len)) {
				printf("\nAll fragments received correctly!\n");
				status = true;
				break;
			}
		}
		else {
			// �ظ��İ�������
			printf("repeated packet...\n");
		}
	}

	if (!status) {
		// TODO: ������
	}

	// �����Ƭ
	big_packet reasm_icmp_recv_packet;
	memset(&reasm_icmp_recv_packet, 0, sizeof(icmp_packet));

	reasm_icmp_recv_packet.ip_id = third_packet.ip_id;
	strcpy(reasm_icmp_recv_packet.dst_addr, third_packet.dst_addr);
	strcpy(reasm_icmp_recv_packet.src_addr, third_packet.src_addr);
	reasm_icmp_recv_packet.icmp_identifier = third_packet.icmp_identifier;
	reasm_icmp_recv_packet.icmp_sequence = 0;
	reasm_icmp_recv_packet.type = third_packet.type;
	reasm_icmp_recv_packet.code = third_packet.code;
	reasm_icmp_recv_packet.payload_size = total_len;
	reassembly_icmp_frag(icmp_frag_link_list_head, &reasm_icmp_recv_packet);
	if (total_len > MAXSIZE) {
		FILE *fp;
		fp = fopen("hello.txt", "wb");
		fwrite(reasm_icmp_recv_packet.payload, sizeof(char), reasm_icmp_recv_packet.payload_size, fp);
		fclose(fp);
		printf("the file has been saved.\n");
	}

	process_whole_packet(reasm_icmp_recv_packet);

	// TODO: �ͷŹ�����Դ
	unsigned short ip_id = reasm_icmp_recv_packet.ip_id;
	unsigned short icmp_identifier = reasm_icmp_recv_packet.icmp_identifier;
	int id_hash = my_hash(ip_id, icmp_identifier);

	pthread_mutex_lock(&mutex);

	packet_abstract* prev = hash_array[id_hash];
	packet_abstract* cur = prev->next;
	if (prev->ip_id == ip_id &&
		prev->icmp_identifier == icmp_identifier &&
		!strcmp(prev->src_addr, reasm_icmp_recv_packet.src_addr) &&
		!strcmp(prev->dst_addr, reasm_icmp_recv_packet.dst_addr)) {
		hash_array[id_hash] = cur;
		free(prev);
	}
	else {
		while (cur != NULL) {
			if (cur->ip_id == ip_id &&
				cur->icmp_identifier == icmp_identifier &&
				!strcmp(cur->src_addr, reasm_icmp_recv_packet.src_addr) &&
				!strcmp(cur->dst_addr, reasm_icmp_recv_packet.dst_addr)) {
				prev->next = cur->next;
				free(cur);
				break;
			}
			else {
				prev = cur;
				cur = cur->next;
			}
		}
		if (cur == NULL) {

		}
	}

	//id_thread_map.erase(id_hash);
	queue_record[queue_id] = 0;
	while (!icmp_packet_queue[queue_id].empty()) {
		icmp_packet_queue[queue_id].pop();
	}
	tid_index_map.erase(pthread_self());

	pthread_mutex_unlock(&mutex);
}

void process_whole_packet(big_packet packet)
{
	printf("source ip: %s\n", packet.src_addr);
	printf("destination ip: %s\n", packet.dst_addr);
	printf("ip id: %d\n", packet.ip_id);
	printf("icmp id: %d\n", packet.icmp_identifier);
	printf("icmp sequence: %d\n", packet.icmp_sequence);
	printf("icmp type: %d\n", packet.type);
	printf("icmp code: %d\n", packet.code);
	printf("length of payload: %ld\n", packet.payload_size);
	if (packet.payload_size > MAXSIZE) {
		FILE *fp;
		printf("please input the filename you want to save:");
		getchar();
		char *fname;
		scanf("%s",fname);
		fp = fopen(fname, "wb");
		fwrite(packet.payload, sizeof(char), packet.payload_size, fp);
		fclose(fp);
		printf("the file has been saved.\n");
		std::cout.write(packet.payload, packet.payload_size);
		printf("\n");
	}
	else
		printf("%s\n",packet.payload);
	/*for (int i = 0; i < packet.payload_size; i++) {
		printf("%c", packet.payload[i]);
		if (i >= packet.payload_size - 1) {
			printf("\n%d\n", i);
		}
	}*/
}
