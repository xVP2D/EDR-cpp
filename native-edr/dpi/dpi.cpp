#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>
#include <limits.h>
#include <unistd.h>
#include "logging.hpp"


static constexpr unsigned ETH_HDR = 14;
static constexpr unsigned IP_HDR_MIN = 20;
static constexpr unsigned TCP_HDR_MIN = 20;

struct IOCs {
    std::vector<std::string> ips;
    std::vector<std::string> domains;
};

static std::string iocs_path() {
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n < 0) return "dpi/iocs.txt";
    buf[n] = '\0';
    return (std::filesystem::path(buf).parent_path() / "../dpi/iocs.txt")
               .lexically_normal().string();
}

static IOCs load_iocs(const std::string& path) {
    IOCs iocs;
    std::ifstream f(path);
    if (!f.is_open()) {
        edr::log::error("impossible d'ouvrir " + path);
        return iocs;
    }
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();

        if (line.substr(0, 3) == "ip:")
            iocs.ips.push_back(line.substr(3));
        else if (line.substr(0, 7) == "domain:")
            iocs.domains.push_back(line.substr(7));
    }
    edr::log::info(std::to_string(iocs.ips.size()) + " IPs, " +
                   std::to_string(iocs.domains.size()) + " domaines charges");
    return iocs;
}

static void on_packet(u_char* user,
                      const struct pcap_pkthdr* header,
                      const u_char* packet)
{
    auto* iocs = reinterpret_cast<IOCs*>(user);
    const unsigned cap = header->caplen;

    if (cap < ETH_HDR + IP_HDR_MIN) return;

    auto* iph = reinterpret_cast<const struct ip*>(packet + ETH_HDR);
    if (iph->ip_v != 4) return;
    if (iph->ip_hl < 5) return; 
    if (iph->ip_p != IPPROTO_TCP) return;

    const unsigned ip_hdr_len = iph->ip_hl * 4u;
    if (cap < ETH_HDR + ip_hdr_len + TCP_HDR_MIN) return;

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &iph->ip_dst, dst, sizeof(dst));

    for (const auto& ip : iocs->ips) {
        if (ip == src) edr::log::warn("IOC IP src=" + std::string(src));
        if (ip == dst) edr::log::warn("IOC IP dst=" + std::string(dst));
    }

    auto* tcph = reinterpret_cast<const struct tcphdr*>(
        packet + ETH_HDR + ip_hdr_len);

    if (tcph->th_off < 5) return; 
    const unsigned tcp_hdr_len = tcph->th_off * 4u;

    if (ntohs(tcph->th_dport) != 80) return;

    if (cap < ETH_HDR + ip_hdr_len + tcp_hdr_len) return;

    const u_char* payload = packet + ETH_HDR + ip_hdr_len + tcp_hdr_len;
    const unsigned payload_len = cap - (ETH_HDR + ip_hdr_len + tcp_hdr_len);
    if (payload_len == 0) return;

    std::string data(reinterpret_cast<const char*>(payload), payload_len);
    auto pos = data.find("Host: ");
    if (pos == std::string::npos) return;
    pos += 6;
    auto end = data.find("\r\n", pos);
    if (end == std::string::npos) return;

    std::string host = data.substr(pos, end - pos);
    edr::log::info("HTTP host=" + host);

    for (const auto& domain : iocs->domains)
        if (host.find(domain) != std::string::npos)
            edr::log::warn("IOC DOMAIN host=" + host);
}

static std::string getDefaultInterface() {
    std::ifstream file("/proc/net/route");
    std::string line;

    std::getline(file, line); 

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string iface, dest;
        iss >> iface >> dest;

        if (dest == "00000000")
            return iface;
    }
    return "";
}


int run_dpi() {
    edr::log::init("dpi");
    edr::log::info("Initialisation de mini-dpi");


    std::string iface = getDefaultInterface();
    IOCs iocs = load_iocs(iocs_path());

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface.c_str(), 65535, 1, 1000, errbuf);
    if (!handle) {
        edr::log::error("pcap_open_live: " + std::string(errbuf));
        edr::log::shutdown();
        return 1;
    }

    edr::log::info("Capture sur " + iface);
    pcap_loop(handle, 0, on_packet, reinterpret_cast<u_char*>(&iocs));

    pcap_close(handle);
    edr::log::shutdown();
    return 0;
}
