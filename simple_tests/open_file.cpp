#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/*
  Source: http://tonylukasavage.com/blog/2010/12/19/offline-packet-capture-analysis-with-c-c----amp--libpcap/
*/

using namespace std;

// declare function
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char **argv) {
  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];

  // open capture file for offline processing
  if(argc<2) {
    printf("[ERROR] Missing the pcap file as argument!\nUsage: ./open.out my_file.pcap\n");
    return 1;
  }

  descr = pcap_open_offline(argv[1], errbuf);
  if (descr == NULL) {
      cout << "pcap_open_live() failed: " << errbuf << endl;
      return 1;
  }

  // start packet processing loop, just like live capture
  if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
      cout << "pcap_loop() failed: " << pcap_geterr(descr);
      return 1;
  }

  cout << "capture finished" << endl;
  return 0;
}


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  // this is the function called in the pcap_loop()
  const struct ether_header* ethernetHeader;
  const struct ip* ipHeader;
  const struct tcphdr* tcpHeader;
  char sourceIp[INET_ADDRSTRLEN];
  char destIp[INET_ADDRSTRLEN];
  u_int sourcePort, destPort;
  u_char *data;
  int dataLength = 0;
  string dataStr = "";

  // get the Ethernet header
  ethernetHeader = (struct ether_header*)packet;

  // check if packet is IP
  if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
      // get IP header
      ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
      inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

      // check if packet is TCP
      if (ipHeader->ip_p == IPPROTO_TCP) {
          // gets information from packet
          tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
          sourcePort = ntohs(tcpHeader->source);
          destPort = ntohs(tcpHeader->dest);
          data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
          dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

          // convert non-printable characters, other than carriage return, line feed,
          // or tab into periods when displayed.
          for (int i = 0; i < dataLength; i++) {
              if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13) {
                  dataStr += (char)data[i];
              } else {
                  dataStr += ".";
              }
          }

          // print the results
          cout << sourceIp << ":" << sourcePort << " -> " << destIp << ":" << destPort << endl;
          if (dataLength > 0) {
              cout << dataStr << endl;
          }
      }
  }
}
