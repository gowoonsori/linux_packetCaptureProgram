/*
    작성자 :      홍의성 (gowoonsori)

    공통 수집 :   Ehternet header
                 IP header

    기본 start :  TCP / UDP / ICMP 3종류의 tcp/ip프로토콜만 수집

    필터 입력 가능 정보 :  port와 ip로만 추출 가능
                        -port :
                            HTTP(80)
                            DNS (53)
                         두 종류의 프로토콜만 추출 가능
                        -ip
*/
#include <arpa/inet.h>         //network 정보 변환
#include <ctype.h>             //isdigit
#include <netinet/if_ether.h>  //etherrnet 구조체
#include <netinet/ip.h>        //ip header 구조체
#include <netinet/ip_icmp.h>   //icmp header 구조체
#include <netinet/tcp.h>       //tcp header 구조체
#include <netinet/udp.h>       //udp header 구조체
#include <pthread.h>           //thread
#include <stdio.h>             //basic
#include <stdlib.h>            //malloc 동적할당
#include <string.h>            //strlen, strcmp, strcpy
#include <sys/socket.h>        //소켓의 주소 설정 (sockaddr 구조체)
#include <sys/timeb.h>         //msec
#include <time.h>              //저장한 file 이름을 현재 날짜로 하기 위해

#define BUFFER_SIZE 65536  // buffer 사이즈 2^16 크기만큼 생성

typedef enum { false, true } bool;  // bool 자료형 선언

enum port { dns = 53, http = 80 };  //캡쳐할 port번호

enum CaptureOptions {
    A = 1,  // ascii
    X,      // hex
    S,      // summary (no detail)
    F       // file
};          // capture option

void *PacketCapture_thread(void *arg);  //캡쳐 스레드

void Capture_helper(FILE *captureFile, unsigned char *, int);                                       //캡쳐한 패킷 프로토콜 분류
void Ethernet_header_fprint(FILE *captureFile, struct iphdr *);                                     // Ethernet 헤더 정보 fprint
void Ip_header_fprint(FILE *captureFile, struct iphdr *, struct sockaddr_in, struct sockaddr_in);   // ip 헤더 정보 fprint
void Tcp_header_capture(FILE *captureFile, struct ethhdr *, struct iphdr *, unsigned char *, int);  // tcp 헤더 정보 capture
void Tcp_header_fprint(FILE *, unsigned char *, struct ethhdr *, struct iphdr *, struct tcphdr *, struct sockaddr_in, struct sockaddr_in,
                       int);                                                                        // tcp 헤더 정보 fprint
void Udp_header_capture(FILE *captureFile, struct ethhdr *, struct iphdr *, unsigned char *, int);  // udp 헤더 정보 capture
void Udp_header_fprint(FILE *, unsigned char *, struct ethhdr *, struct iphdr *, struct udphdr *, struct sockaddr_in, struct sockaddr_in,
                       int);  // udp 헤더 정보 fprint
void Dns_header_frpint();
void Icmp_header_capture(FILE *captureFile, struct ethhdr *, struct iphdr *, unsigned char *, int);  // icmp 헤더 정보 capture
void Icmp_header_fprint(FILE *, unsigned char *, struct ethhdr *, struct iphdr *, struct icmphdr *, struct sockaddr_in, struct sockaddr_in,
                        int);                                            // icmp 헤더 정보 fprint
void Change_hex_to_ascii(FILE *captureFile, unsigned char *, int, int);  // payload값 hex/ascii/file option에 맞게 출력

void MenuBoard();           // menu board
void Menu_helper();         // menu board exception handling
void StartMenuBoard();      // start menu board
bool start_helper(char *);  // start menu exception handling
bool IsPort(char *);        //포트 형식 검사 | 맞으면 true
bool IsIpAddress(char *);   // ip 형식 검사 | 맞으면 true
bool IsDigit();             // string 이 숫자인지 검사 | 맞으면 true
void buffer_flush();        //입력 버퍼 지우기

bool captureStart = false;                                                   //캡쳐 스레드 시작flag 변수
int total = 0, filter = 0, drop = 0;                                         //캡쳐한 패킷 갯수
char protocolOption[128], portOption[128], ipOption[128], printOption[128];  // filter option 변수

int main() {
    Menu_helper();

    return 0;
}

void *PacketCapture_thread(void *arg) {
    int rawSocket = *(int *)arg;                                   // raw socket 전달 받기
    int dataSize;                                                  //받은 데이터 정보 크기
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);  // buffer 공간 할당

    char filename[40];
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    sprintf(filename, "captureFile(%d-%d-%dT%d:%d:%d).txt", tm.tm_year - 100, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    FILE *captureData = fopen(filename, "a+");  //파일 이어서 작성
    if (captureData == NULL) {
        printf("  !! 파일 열기 실패 하여 종료됩니다.\n");  //에러 처리
        exit(1);
    }

    //캡쳐 시작
    while (captureStart) {
        if ((dataSize = recvfrom(rawSocket, buffer, BUFFER_SIZE, 0, NULL, NULL)) == -1)  //패킷 recv
        {
            drop++;
            printf("packet 받기 실패\n");  // packet drop시
            continue;
        }
        Capture_helper(captureData, buffer, dataSize);  //받은 패킷을 프로토콜 종류에따라 처리
    }

    free(buffer);         //버퍼 공간 해제
    fclose(captureData);  // file close
}

void Capture_helper(FILE *captureData, unsigned char *buffer, int size) {
    struct ethhdr *etherHeader = (struct ethhdr *)buffer;          //버퍼에서 이더넷 정보 get
    struct iphdr *ipHeader = (struct iphdr *)(buffer + ETH_HLEN);  //받은 패킷의 ip header 부분 get
    total++;                                                       // recv한 모든 패킷 수 증가

    /*IPv4의 모든 프로토콜 (ETH_P_IP == 0800)*/
    if (etherHeader->h_proto == 8) {
        /* all 프로토콜 선택시*/
        if (!strcmp(protocolOption, "*")) {
            if (ipHeader->protocol == 1) {
                Icmp_header_capture(captureData, etherHeader, ipHeader, buffer, size);
            } else if (ipHeader->protocol == 6) {
                Tcp_header_capture(captureData, etherHeader, ipHeader, buffer, size);
            } else if (ipHeader->protocol == 17) {
                Udp_header_capture(captureData, etherHeader, ipHeader, buffer, size);
            }
        } else if (!strcmp(protocolOption, "tcp") && (ipHeader->protocol == 6))  // tcp
        {
            Tcp_header_capture(captureData, etherHeader, ipHeader, buffer, size);
        } else if (!strcmp(protocolOption, "udp") && (ipHeader->protocol == 17))  // udp
        {
            Udp_header_capture(captureData, etherHeader, ipHeader, buffer, size);
        } else if (!strcmp(protocolOption, "icmp") && (ipHeader->protocol == 1))  // icmp
        {
            Icmp_header_capture(captureData, etherHeader, ipHeader, buffer, size);
        }
    }
}

void Ethrenet_header_fprint(FILE *captureData, struct ethhdr *etherHeader) {
    filter++;  // filter 거쳐 캡쳐한 패킷은 이 함수는 무조건 한번씩 거치기 때문에 filter 패킷 값 증가
    fprintf(captureData, "\n           --------------------------------------------------------\n");
    fprintf(captureData, "          |                     Ethernet Header                    |\n");
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "               Ethernet Type         |      0x%02X00\n",
            etherHeader->h_proto);  // L3 패킷 타입 IPv4 : 0x0800  | ARP 패킷 : 0x0806 | VLAN Tag : 0x8100
    fprintf(captureData, "               Src MAC Addr          |      [%02x:%02x:%02x:%02x:%02x:%02x]\n",  // 6 byte for src
            etherHeader->h_source[0], etherHeader->h_source[1], etherHeader->h_source[2], etherHeader->h_source[3],
            etherHeader->h_source[4], etherHeader->h_source[5]);
    fprintf(captureData, "               Dst MAC Addr          |      [%02x:%02x:%02x:%02x:%02x:%02x]\n",  // 6 byte for dest
            etherHeader->h_dest[0], etherHeader->h_dest[1], etherHeader->h_dest[2], etherHeader->h_dest[3], etherHeader->h_dest[4],
            etherHeader->h_dest[5]);
    fprintf(captureData, "           --------------------------------------------------------\n\n");
}

void Ip_header_fprint(FILE *captureData, struct iphdr *ipHeader, struct sockaddr_in source, struct sockaddr_in dest) {
    fprintf(captureData, "\n           --------------------------------------------------------\n");
    fprintf(captureData, "          |                       IP Header                        |\n");
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                IP Version           |    IPv%d\n", (unsigned int)ipHeader->version);
    fprintf(captureData, "                IP Header Length     |    %d DWORDS ( %d Bytes )\n", (unsigned int)ipHeader->ihl,
            ((unsigned int)(ipHeader->ihl)) * 4);
    fprintf(captureData, "                Type Of Service      |    %d\n", (unsigned int)ipHeader->tos);
    fprintf(captureData, "                IP Total Length      |    %d Bytes\n", ntohs(ipHeader->tot_len));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                Identification       |    %d\n", ntohs(ipHeader->id));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                Time To Live (TTL)   |    %d\n", (unsigned int)ipHeader->ttl);
    fprintf(captureData, "                Protocol             |    %d\n", (unsigned int)ipHeader->protocol);
    fprintf(captureData, "                Checksum             |    0x%04X\n", ntohs(ipHeader->check));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                Src IP Addr          |    %s\n", inet_ntoa(source.sin_addr));
    fprintf(captureData, "                Dst IP Addr          |    %s\n", inet_ntoa(dest.sin_addr));
    fprintf(captureData, "           --------------------------------------------------------\n\n");
}

void Tcp_header_capture(FILE *captureData, struct ethhdr *etherHeader, struct iphdr *ipHeader, unsigned char *Buffer, int Size) {
    struct tcphdr *tcpHeader = (struct tcphdr *)(Buffer + (ipHeader->ihl * 4) + ETH_HLEN);  //버퍼에서 tcp 헤더 정보 get
    struct sockaddr_in source, dest;  //출발, 목적지 주소 정보 저장할 변수
    source.sin_addr.s_addr = ipHeader->saddr;
    dest.sin_addr.s_addr = ipHeader->daddr;

    // filter ip 검사
    if (!strcmp(ipOption, "*") || !strcmp(inet_ntoa(source.sin_addr), ipOption) ||
        !strcmp(inet_ntoa(dest.sin_addr), ipOption)) {  // filter port번호 검사
        if (!strcmp(portOption, "*") || (atoi(portOption) == (int)ntohs(tcpHeader->source)) ||
            (atoi(portOption) == (int)ntohs(tcpHeader->dest))) {
            /*현재 시간 get*/
            struct timeb itb;
            ftime(&itb);
            struct tm *tm = localtime(&itb.time);
            fprintf(stdout, "\n%02d:%02d:%02d:%03d IPv", tm->tm_hour, tm->tm_min, tm->tm_sec, itb.millitm);
            if (ntohs(tcpHeader->source) == http) {
                fprintf(stdout, "%d %s:http > ", (unsigned int)ipHeader->version, inet_ntoa(source.sin_addr));
                fprintf(stdout, "%s:%u = TCP Flags [", inet_ntoa(dest.sin_addr), ntohs(tcpHeader->dest));
            } else if (ntohs(tcpHeader->dest) == http) {
                fprintf(stdout, "%d %s:%u > ", (unsigned int)ipHeader->version, inet_ntoa(source.sin_addr), ntohs(tcpHeader->source));
                fprintf(stdout, "%s:http = TCP Flags [", inet_ntoa(dest.sin_addr));
            } else {
                fprintf(stdout, "%d %s:%u > ", (unsigned int)ipHeader->version, inet_ntoa(source.sin_addr), ntohs(tcpHeader->source));
                fprintf(stdout, "%s:%u = TCP Flags [", inet_ntoa(dest.sin_addr), ntohs(tcpHeader->dest));
            }
            if ((unsigned int)tcpHeader->urg == 1) fprintf(stdout, "U.");
            if ((unsigned int)tcpHeader->ack == 1) fprintf(stdout, "A.");
            if ((unsigned int)tcpHeader->psh == 1) fprintf(stdout, "P.");
            if ((unsigned int)tcpHeader->rst == 1) fprintf(stdout, "R.");
            if ((unsigned int)tcpHeader->syn == 1) fprintf(stdout, "S.");
            if ((unsigned int)tcpHeader->fin == 1) fprintf(stdout, "F.");
            fprintf(stdout, "], seq %u, ack %u, win %d, length %d", ntohl(tcpHeader->seq), ntohl(tcpHeader->ack_seq),
                    ntohs(tcpHeader->window), Size);

            /*print option에 따라 payload 부분 다르게 출력*/
            /*ascill 출력*/
            if (!strcmp(printOption, "a")) {
                fprintf(stdout, "\n\033[101methernet\033[0m");
                Change_hex_to_ascii(captureData, Buffer, A, ETH_HLEN);  // ethernet
                fprintf(stdout, "\n\033[101mip\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN, A, (ipHeader->ihl * 4));  // ip
                fprintf(stdout, "\n\033[101mtcp\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4), A, sizeof tcpHeader);  // tcp
                fprintf(stdout, "\n\033[101mpayload\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof tcpHeader, A,
                                    (Size - sizeof tcpHeader - (ipHeader->ihl * 4) - ETH_HLEN));  // payload
            }
            /*hex 출력*/
            else if (!strcmp(printOption, "x")) {
                fprintf(stdout, "\n\033[101methernet\033[0m");
                Change_hex_to_ascii(captureData, Buffer, X, ETH_HLEN);  // ethernet
                fprintf(stdout, "\n\033[101mip\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN, X, (ipHeader->ihl * 4));  // ip
                fprintf(stdout, "\n\033[101mtcp\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4), X, sizeof tcpHeader);  // tcp
                fprintf(stdout, "\n\033[101mpayload\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof tcpHeader, X,
                                    (Size - sizeof tcpHeader - (ipHeader->ihl * 4) - ETH_HLEN));  // payload
            }
            /*file 출력*/
            Tcp_header_fprint(captureData, Buffer, etherHeader, ipHeader, tcpHeader, source, dest, Size);
        }
    }
}
void Tcp_header_fprint(FILE *captureData, unsigned char *Buffer, struct ethhdr *etherHeader, struct iphdr *ipHeader,
                       struct tcphdr *tcpHeader, struct sockaddr_in source, struct sockaddr_in dest, int Size) {
    fprintf(captureData, "\n############################## TCP Packet #####################################\n");
    Ethrenet_header_fprint(captureData, etherHeader);       // ethernet 정보 fprint
    Ip_header_fprint(captureData, ipHeader, source, dest);  // ip 정보 fprint

    fprintf(captureData, "\n           --------------------------------------------------------\n");
    fprintf(captureData, "          |                       TCP Header                       |\n");
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "             Source Port             |   %u\n", ntohs(tcpHeader->source));
    fprintf(captureData, "             Dest Port               |   %u\n", ntohs(tcpHeader->dest));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "             Sequence Number         |   %u\n", ntohl(tcpHeader->seq));
    fprintf(captureData, "             Acknowledge Number      |   %u\n", ntohl(tcpHeader->ack_seq));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "             OFFSET(Header Length)   |   %d DWORDS (%d BYTES)\n", (unsigned int)tcpHeader->doff,
            (unsigned int)tcpHeader->doff * 4);
    fprintf(captureData, "           -- FLAGS -----------------------------------------------\n");
    fprintf(captureData, "              |-Urgent Flag          |   %d\n", (unsigned int)tcpHeader->urg);
    fprintf(captureData, "              |-Ack Flag             |   %d\n", (unsigned int)tcpHeader->ack);
    fprintf(captureData, "              |-Push Flag            |   %d\n", (unsigned int)tcpHeader->psh);
    fprintf(captureData, "              |-Reset Flag           |   %d\n", (unsigned int)tcpHeader->rst);
    fprintf(captureData, "              |-Synchronise Flag     |   %d\n", (unsigned int)tcpHeader->syn);
    fprintf(captureData, "              |-Finish Flag          |   %d\n", (unsigned int)tcpHeader->fin);
    fprintf(captureData, "             Window Size (rwnd)      |   %d\n", ntohs(tcpHeader->window));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "             Checksum                |   0x%04x\n", ntohs(tcpHeader->check));
    fprintf(captureData, "             Urgent Pointer          |   %d\n", tcpHeader->urg_ptr);
    fprintf(captureData, "           --------------------------------------------------------\n");

    /* 패킷 정보(payload) Hex dump 와 ASCII 변환 데이터 파일에 출력 */
    Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + tcpHeader->doff * 4, F,
                        (Size - tcpHeader->doff * 4 - (ipHeader->ihl * 4) - ETH_HLEN));
    fprintf(captureData, "\n===============================================================================\n");
}

void Udp_header_capture(FILE *captureData, struct ethhdr *etherHeader, struct iphdr *ipHeader, unsigned char *Buffer, int Size) {
    struct udphdr *udpHeader = (struct udphdr *)(Buffer + ipHeader->ihl * 4 + ETH_HLEN);  //버퍼에서 udp 헤더 정보 get
    struct sockaddr_in source, dest;                                                      //출발, 목적지 주소 정보 저장할 변수
    source.sin_addr.s_addr = ipHeader->saddr;
    dest.sin_addr.s_addr = ipHeader->daddr;

    // ip filter 검사
    if (!strcmp(ipOption, "*") || !strcmp(inet_ntoa(source.sin_addr), ipOption) ||
        !strcmp(inet_ntoa(dest.sin_addr), ipOption)) {  // port 번호 filter 검사
        if (!strcmp(portOption, "*") || (atoi(portOption) == (int)ntohs(udpHeader->source)) ||
            (atoi(portOption) == (int)ntohs(udpHeader->dest))) {
            /*현재 시간 get*/
            struct timeb itb;
            ftime(&itb);
            struct tm *tm = localtime(&itb.time);
            fprintf(stdout, "\n%02d:%02d:%02d:%03d IPv", tm->tm_hour, tm->tm_min, tm->tm_sec, itb.millitm);
            if (ntohs(udpHeader->source) == dns) {
                fprintf(stdout, "%d %s:dns > ", (unsigned int)ipHeader->version, inet_ntoa(source.sin_addr));
                fprintf(stdout, "%s:%u = UDP ", inet_ntoa(dest.sin_addr), ntohs(udpHeader->dest));
                Dns_header_frpint(Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof udpHeader, Size);
            } else if (ntohs(udpHeader->dest) == dns) {
                fprintf(stdout, "%d %s:%u > ", (unsigned int)ipHeader->version, inet_ntoa(source.sin_addr), ntohs(udpHeader->source));
                fprintf(stdout, "%s:dns = UDP ", inet_ntoa(dest.sin_addr));
                Dns_header_frpint(Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof udpHeader, Size);
            } else {
                fprintf(stdout, "%d %s:%u > ", (unsigned int)ipHeader->version, inet_ntoa(source.sin_addr), ntohs(udpHeader->source));
                fprintf(stdout, "%s:%u = UDP ", inet_ntoa(dest.sin_addr), ntohs(udpHeader->dest));
            }
            fprintf(stdout, "( length %d )", Size);

            /*ascii 출력*/
            if (!strcmp(printOption, "a")) {
                fprintf(stdout, "\n\033[101methernet\033[0m");
                Change_hex_to_ascii(captureData, Buffer, A, ETH_HLEN);  // ethernert
                fprintf(stdout, "\n\033[101mip\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN, A, (ipHeader->ihl * 4));  // ip
                fprintf(stdout, "\n\033[101mudp\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4), A, sizeof udpHeader);  // udp
                fprintf(stdout, "\n\033[101mpayload\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof udpHeader, A,
                                    (Size - sizeof udpHeader - (ipHeader->ihl * 4) - ETH_HLEN));  // payload
            }
            /*hex 출력*/
            else if (!strcmp(printOption, "x")) {
                fprintf(stdout, "\n\033[101methernet\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer, X, ETH_HLEN);  // ethernert
                fprintf(stdout, "\n\033[101mip\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN, X, (ipHeader->ihl * 4));  // ip
                fprintf(stdout, "\n\033[101mudp\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4), X, sizeof udpHeader);  // udp
                fprintf(stdout, "\n\033[101mpayload\t\033[0m");
                Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof udpHeader, X,
                                    (Size - sizeof udpHeader - (ipHeader->ihl * 4) - ETH_HLEN));  // payload
            }
            /*file 출력*/
            Udp_header_fprint(captureData, Buffer, etherHeader, ipHeader, udpHeader, source, dest, Size);
        }
    }
}
void Udp_header_fprint(FILE *captureData, unsigned char *Buffer, struct ethhdr *etherHeader, struct iphdr *ipHeader,
                       struct udphdr *udpHeader, struct sockaddr_in source, struct sockaddr_in dest, int Size) {
    fprintf(captureData, "\n############################## UDP Packet #####################################\n");
    Ethrenet_header_fprint(captureData, etherHeader);       // ethernet 정보 print
    Ip_header_fprint(captureData, ipHeader, source, dest);  // ip 정보 print
    fprintf(captureData, "\n           --------------------------------------------------------\n");
    fprintf(captureData, "          |                       UDP Header                       |\n");
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                Source Port          |   %u\n", ntohs(udpHeader->source));
    fprintf(captureData, "                Destination Port     |   %u\n", ntohs(udpHeader->dest));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                UDP Length           |   %d\n", ntohs(udpHeader->len));
    fprintf(captureData, "                UDP Checksum         |   0x%04x\n", ntohs(udpHeader->check));
    fprintf(captureData, "           --------------------------------------------------------\n");

    /* 패킷 정보(payload) Hex dump 와 ASCII 변환 데이터 출력 */
    Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof udpHeader, F,
                        (Size - sizeof udpHeader - (ipHeader->ihl * 4) - ETH_HLEN));
    fprintf(captureData, "\n===============================================================================\n");
}

void Dns_header_frpint(unsigned char *dnsHeader, int Size) {
    int idx = 0;
    char q = ' ';

    // Transactoin Id
    fprintf(stdout, " 0x");
    for (idx = 0; idx < 2; idx++) {
        fprintf(stdout, "%02X", (unsigned char)dnsHeader[idx]);
    }

    // Flags (질의인지 응답인지만 구별)
    int flags = (unsigned char)dnsHeader[idx];
    if (!(flags & 128)) {
        q = '?';
    }
    idx += 5;
    // answer RRs
    int answerRR = (unsigned char)dnsHeader[idx];
    idx += 5;

    // Query
    fprintf(stdout, " ");
    while (1) {
        if (dnsHeader[idx] == 0) break;
        if (dnsHeader[idx] >= 32 && dnsHeader[idx] < 128)
            fprintf(stdout, "%c", (unsigned char)dnsHeader[idx]);  // data가 ascii라면 출력
        else
            fprintf(stdout, ".");  //그외 데이터는 . 으로 표현
        idx++;
    }
    idx += 2;

    //질의 type
    int type = (unsigned char)dnsHeader[idx];
    if (type == 1)
        fprintf(stdout, " A %c", q);
    else if (type == 28)
        fprintf(stdout, " AAAA %c", q);
    else if (type == 12)
        fprintf(stdout, " PTR %c", q);
    idx += 2;

    //응답이있다면 응답 data출력(응답 RR이 1이상이라면)
    for (int i = 0; i < answerRR; i++) {
        while (1) {
            if (dnsHeader[idx] == 0) break;
            idx++;
        }
        idx += 2;
        int type = (unsigned char)dnsHeader[idx];
        if (type == 1)
            fprintf(stdout, " A ");
        else if (type == 28)
            fprintf(stdout, " AAAA ");
        else if (type == 12)
            fprintf(stdout, " PTR ");
        idx += 8;

        int length = (unsigned char)dnsHeader[idx];
        idx++;
        if (type == 1) {
            for (int j = 0; j < length; idx++, j++) {
                int ip = (unsigned char)dnsHeader[idx];
                fprintf(stdout, "%d", ip);
                if (j != length - 1) fprintf(stdout, ".");
            }
        } else if (type == 28) {
            for (int j = 0; j < length; idx++, j++) {
                if ((unsigned char)dnsHeader[idx] == 0) continue;

                fprintf(stdout, "%02X", (unsigned char)dnsHeader[idx]);
                if (j == 1 || j == 3 || j == 5) fprintf(stdout, ":");
                if (j == length - 1) fprintf(stdout, "::%0x", (unsigned char)dnsHeader[idx]);
            }
        } else if (type == 12) {
            for (int j = 0; j < length; idx++, j++) {
                if ((unsigned char)dnsHeader[idx] == 0) continue;

                if (dnsHeader[idx] >= 32 && dnsHeader[idx] < 128)
                    fprintf(stdout, "%c", (unsigned char)dnsHeader[idx]);  // data가 ascii라면 출력
                else
                    fprintf(stdout, ".");  //그외 데이터는 . 으로 표현
            }
        }
        fprintf(stdout, " ");
    }
}

void Icmp_header_capture(FILE *captureData, struct ethhdr *etherHeader, struct iphdr *ipHeader, unsigned char *Buffer, int Size) {
    struct icmphdr *icmpHeader = (struct icmphdr *)(Buffer + ipHeader->ihl * 4 + ETH_HLEN);  //버퍼에서 icp정보 get
    struct sockaddr_in source, dest;  //출발, 목적지 주소 정보 저장할 변수
    source.sin_addr.s_addr = ipHeader->saddr;
    dest.sin_addr.s_addr = ipHeader->daddr;

    // ip filter 검사
    if (!strcmp(ipOption, "*") || !strcmp(inet_ntoa(source.sin_addr), ipOption) || !strcmp(inet_ntoa(dest.sin_addr), ipOption)) {
        /*현재 시간 get*/
        struct timeb itb;
        ftime(&itb);
        struct tm *tm = localtime(&itb.time);
        fprintf(stdout, "\n%02d:%02d:%02d:%03d IPv%d %s > ", tm->tm_hour, tm->tm_min, tm->tm_sec, itb.millitm,
                (unsigned int)ipHeader->version, inet_ntoa(source.sin_addr));
        fprintf(stdout, "%s = ICMP [Type : %d/Code : %d] TTL=%d ", inet_ntoa(dest.sin_addr), (unsigned int)icmpHeader->type,
                (unsigned int)icmpHeader->code, (unsigned int)ipHeader->ttl);
        fprintf(stdout, "length %d", Size);

        /*ascii 출력*/
        if (!strcmp(printOption, "a")) {
            fprintf(stdout, "\n\033[101methernet\033[0m");
            Change_hex_to_ascii(captureData, Buffer, A, ETH_HLEN);  // ethernert
            fprintf(stdout, "\n\033[101mip\t\033[0m");
            Change_hex_to_ascii(captureData, Buffer + ETH_HLEN, A, (ipHeader->ihl * 4));  // ip
            fprintf(stdout, "\n\033[101micmp\t\033[0m");
            Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4), A, sizeof icmpHeader);  // icmp
            fprintf(stdout, "\n\033[101mpayload\t\033[0m");
            Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof icmpHeader, A,
                                (Size - sizeof icmpHeader - (ipHeader->ihl * 4) - ETH_HLEN));  // payload
        }
        /*hex 출력*/
        else if (!strcmp(printOption, "x")) {
            fprintf(stdout, "\n\033[101methernet\033[0m");
            fprintf(stdout, "\n\033[101mip\t\033[0m");
            fprintf(stdout, "\n\033[101micmp\t\033[0m");
            fprintf(stdout, "\n\033[101mpayload\t\033[0m");
            Change_hex_to_ascii(captureData, Buffer, X, ETH_HLEN);                                            // ethernert
            Change_hex_to_ascii(captureData, Buffer + ETH_HLEN, X, (ipHeader->ihl * 4));                      // ip
            Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4), X, sizeof icmpHeader);  // icmp
            Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof icmpHeader, X,
                                (Size - sizeof icmpHeader - (ipHeader->ihl * 4) - ETH_HLEN));  // payload
        }
        /*file 출력*/
        Icmp_header_fprint(captureData, Buffer, etherHeader, ipHeader, icmpHeader, source, dest, Size);
    }
}

void Icmp_header_fprint(FILE *captureData, unsigned char *Buffer, struct ethhdr *etherHeader, struct iphdr *ipHeader,
                        struct icmphdr *icmpHeader, struct sockaddr_in source, struct sockaddr_in dest, int Size) {
    fprintf(captureData, "\n############################## ICMP Packet ####################################\n");
    Ethrenet_header_fprint(captureData, etherHeader);       // ethernet 정보 print
    Ip_header_fprint(captureData, ipHeader, source, dest);  // ip 정보 print
    fprintf(captureData, "\n           --------------------------------------------------------\n");
    fprintf(captureData, "          |                      ICMP Header                       |\n");
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                  Type             |   %d\n", (unsigned int)(icmpHeader->type));
    fprintf(captureData, "           --------------------------------------------------------\n");
    fprintf(captureData, "                  Code             |   %d\n", (unsigned int)(icmpHeader->code));
    fprintf(captureData, "                  Checksum         |   0x%04x\n", ntohs(icmpHeader->checksum));
    fprintf(captureData, "           --------------------------------------------------------\n");
    /* 패킷 정보(payload) Hex dump 와 ASCII 변환 데이터 파일 출력 */
    Change_hex_to_ascii(captureData, Buffer + ETH_HLEN + (ipHeader->ihl * 4) + sizeof icmpHeader, F,
                        (Size - sizeof icmpHeader - (ipHeader->ihl * 4) - ETH_HLEN));
    fprintf(captureData, "\n===============================================================================\n");
}

void Change_hex_to_ascii(FILE *captureData, unsigned char *data, int op, int Size) {
    /*cmd에 ascill로 출력 */
    if (op == A) {
        fprintf(stdout, "\033[91m ");
        for (int i = 0; i < Size; i++) {
            if (data[i] >= 32 && data[i] < 128)
                fprintf(stdout, "%c", (unsigned char)data[i]);  // data가 ascii라면 출력
            else if (data[i] == 13)                             // cr(carrige return)라면 continue
                continue;
            else if (data[i] == 10)
                fprintf(stdout, "\n");  // lf(\n)라면 개행문자 출력
            else
                fprintf(stdout, ".");  //그외 데이터는 . 으로 표현
        }
        fprintf(stdout, "\033[0m");
    }
    /*cmd에 hex로 출력*/
    else if (op == X) {
        fprintf(stdout, "\033[91m ");
        for (int i = 0; i < Size; i++) {
            fprintf(stdout, " %02X", (unsigned int)data[i]);  //앞의 빈자리 0으로 초기화한 16진수로 데이터 출력
        }
        fprintf(stdout, "\033[0m");
    }
    /*file에 write하는 경우*/
    else if (op == F) {
        fprintf(captureData, "\n\nDATA (Payload)\n");
        for (int i = 0; i < Size; i++) {
            if (i != 0 && i % 16 == 0) {          // 16개 데이터 출력 했다면, ascii코드 출력후 개행후 이어서 출력
                fprintf(captureData, "\t\t");     // 16진수 data랑 ascii data 구분
                for (int j = i - 16; j < i; j++)  // 16진수 data를 ascii로 변환
                {
                    if (data[j] >= 32 && data[j] < 128)
                        fprintf(captureData, "%c", (unsigned char)data[j]);  // data가 ascii라면 출력

                    else
                        fprintf(captureData, ".");  //그외 데이터는 . 으로 표현
                }
                fprintf(captureData, "\n");
            }

            if (i % 16 == 0) fprintf(captureData, "\t");  //가시성을 위해 처음 오는 data는 tab

            fprintf(captureData, " %02X", (unsigned int)data[i]);  //앞의 빈자리 0으로 초기화한 16진수로 데이터 출력

            if (i == Size - 1)  //마지막 data
            {
                for (int j = 0; j < (15 - (i % 16)); j++)
                    fprintf(captureData, "   ");  //마지막 데이터는 16개 꽉 안채울 수 있으니 데이터 포맷을 위해 남은 공간만큼 space

                fprintf(captureData, "\t\t");  // 16자리 까지 공백 채운후 ascii 출력 위해 구분

                for (int j = (i - (i % 16)); j <= i; j++)  //남은 데이터 ascii로 변환
                {
                    if (data[j] >= 32 && data[j] < 128)
                        fprintf(captureData, "%c", (unsigned char)data[j]);
                    else
                        fprintf(captureData, ".");
                }
                fprintf(captureData, "\n");
            }
        }
    }
}

void MenuBoard() {
    system("clear");
    fprintf(stdout, "\n************************** WELCOME ************************\n");
    fprintf(stdout, "*                    Custom Packet Capture                *\n");
    fprintf(stdout, "**************************** Menu *************************\n\n");
    fprintf(stdout, "                     1. Capture start \n");
    fprintf(stdout, "                     2. Capture stop \n");
    fprintf(stdout, "                     3. show menu \n");
    fprintf(stdout, "                     0. exit \n");
    fprintf(stdout, " \n**********************************************************\n\n");
}

void StartMenuBoard() {
    system("clear");
    fprintf(stdout, "\n************************* 캡쳐 가능 프로토콜 **********************\n\n");
    fprintf(stdout, "   \033[100mprotocol\033[0m :      *(all) | tcp | udp | icmp \n");
    fprintf(stdout, "   \033[100mport\033[0m     :  *(all) | 0 ~ 65535 | [http(80) | dns(53) | icmp(*)]  \n");
    fprintf(stdout, "   \033[100mip\033[0m       :      *(all) | 0.0.0.0 ~ 255.255.255.255 \n");
    fprintf(stdout, "   \033[100moptions\033[0m  :      a : Ascill | x : Hex | s : Summary  \n");
    fprintf(stdout, "\n**************************** Start Rule ***************************\n\n");
    fprintf(stdout,
            "                입력 순서 :  \033[100mprotocol\033[0m \033[100mport\033[0m \033[100mip\033[0m \033[100moption\033[0m \n");
    fprintf(stdout, "\n*******************************************************************\n\n");
}

void Menu_helper() {
    int isDigit, menuItem;  // menu판 입력 변수  ( isDigit = 1:숫자  false: 숫자아님 / menuItem : 메뉴번호)
    pthread_t capture_thd;  //패킷 캡쳐 스레드
    int rawSocket;          // raw socket
    char str[128];

    if ((rawSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)  // raw socket 생성
    {
        printf("Socket 열기 실패\n");
        exit(1);
    }

    //프로그램 종료시까지 반복
    MenuBoard();
    while (1) {
        fprintf(stdout, "\n   \033[93m메뉴 번호 입력 :\033[0m ");
        isDigit = scanf("%d", &menuItem);  //메뉴판 번호 입력
        buffer_flush();                    //입력버퍼 flush

        if (menuItem == 0 && isDigit == 1)  //프로그램 종료
        {
            fprintf(stderr, "   !!! Good bye !!!");
            break;
        } else if (menuItem == 1 && isDigit == 1)  // TCP 캡쳐 시작
        {
            if (captureStart)
                fprintf(stdout, "이미 시작 중입니다 !!\n");
            else {
                StartMenuBoard();
                fprintf(stdout, "\n   \033[93m필터 입력 :\033[0m ");
                scanf("%[^\n]s", str);  //메뉴판 번호 입력

                if (start_helper(str)) {
                    captureStart = true;
                    pthread_create(&capture_thd, NULL, PacketCapture_thread, (void *)&rawSocket);  // TCP 캡쳐 스레드 생성
                    pthread_detach(capture_thd);                                                   //스레드 종료시 자원 해제
                }
            }
        } else if (menuItem == 2 && isDigit == 1)  // 캡쳐 중지
        {
            if (!captureStart)
                fprintf(stdout, "시작 중이 아닙니다 !!\n");
            else {
                captureStart = false;
                fprintf(stdout, "\n\n캡쳐 중지.\n");
                fprintf(stdout, "%d packets received\n", total);
                fprintf(stdout, "%d filtered packets captured\n", filter);
                fprintf(stdout, "%d packets dropped (fail received)\n", drop);

                /*변수 초기화*/
                total = 0, filter = 0, drop = 0;
                protocolOption[0] = '\0', ipOption[0] = '\0', portOption[0] = '\0', printOption[0] = '\0';
            }
        } else if (menuItem == 3 && isDigit == 1)  // show Menu
        {
            MenuBoard();
        } else {  // exception handling
            fprintf(stderr, "잘못 입력하셨습니다 !!\n\n");
        }
    }
    close(rawSocket);  // socket close
}
bool start_helper(char *str) {
    /*protocol*/
    char *option = strtok(str, " ");
    if (strcmp(option, "*") && strcmp(option, "tcp") && strcmp(option, "udp") && strcmp(option, "icmp") && strcmp(option, "http") &&
        strcmp(option, "dns")) {
        fprintf(stderr, "* | tcp | udp | icmp | http | dns 만 캡쳐가능합니다.\n");
        return false;
    }
    strcpy(protocolOption, option);

    /*port 번호*/
    option = strtok(NULL, " ");
    if (!IsPort(option)) {
        fprintf(stderr, "잘못된 port 입력입니다.\n");
        return false;
    }
    strcpy(portOption, option);

    /*ip 주소*/
    option = strtok(NULL, " ");
    char *pOption = strtok(NULL, "\0");
    char s[48];
    strcpy(s, option);
    if (!IsIpAddress(s)) {
        fprintf(stderr, "잘못된 Ip 주소 입니다.\n");
        return false;
    }
    strcpy(ipOption, option);

    /*출력 option*/
    if (strcmp(pOption, "a") && strcmp(pOption, "s") && strcmp(pOption, "x")) {
        fprintf(stderr, "잘못된 Option 입니다.\n");
        return false;
    }
    strcpy(printOption, pOption);

    return true;
}

bool IsPort(char *str) {
    if (!strcmp(str, "*")) return true;
    if (!IsDigit(str))  //숫자가 아니라면 flase
        return false;
    if (atoi(str) < 1 || atoi(str) > 65535)  //없는 포트번호거나  false
        return false;
    return true;
}

bool IsIpAddress(char *str) {
    if (!strcmp(str, "*"))  //모든 ip주소 filter
        return true;
    int numberOfOctet = 0;
    char *octet = strtok(str, ".");  // ip octet 규칙 검사
    while (octet != NULL) {
        if ((!isdigit(octet[0]) && atoi(octet) == 0) || atoi(octet) > 255)  //알파벳이거나 255를 넘는다면 false
        {
            return false;
        }
        numberOfOctet++;
        octet = strtok(NULL, ".");
    }
    if (numberOfOctet != 4)  // octet 이 4개가 안된다면 false
        return false;

    return true;
}

void buffer_flush() {
    while (getchar() != '\n')
        ;
}
bool IsDigit(char *str) {
    for (int i = 0; i < (int)strlen(str); i++) {
        if (!isdigit(str[i]))  //숫자아니라면 false
            return false;
    }
    return true;
}