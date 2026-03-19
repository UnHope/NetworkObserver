#include "snifferworker.h"
#include <QDateTime>
#include <QHostAddress>
#include <ws2tcpip.h>
#include <QCoreApplication>
#pragma comment(lib, "Ws2_32.lib")

SnifferWorker::SnifferWorker(QObject* parent) : QObject(parent) {}

SnifferWorker::~SnifferWorker() { stopCapture(); }

void SnifferWorker::setInterface(const std::string& name) {
    m_interfaceName = name;
    m_isOfflineMode = false;
}

void SnifferWorker::setFileName(const QString& fileName) {
    m_fileName = fileName;
    m_isOfflineMode = true;
}

void SnifferWorker::stopCapture() { m_running = false; }

void SnifferWorker::startCapture() {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (m_isOfflineMode) {
        m_handle = pcap_open_offline(m_fileName.toStdString().c_str(), errbuf);
        if (!m_handle) {
            emit errorOccurred(tr("Error opening file: ") + QString::fromLocal8Bit(errbuf));
            emit finished();
            return;
        }
    }
    else {
        m_handle = pcap_open_live(m_interfaceName.c_str(), 65536, 1, 1000, errbuf);
        if (!m_handle) {
            emit errorOccurred(tr("Adapter error: ") + QString::fromLocal8Bit(errbuf));
            emit finished();
            return;
        }
    }

    m_running = true;
    m_packetCount = 0;
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    int res;
    QVector<PacketDisplayData> buffer;
    buffer.reserve(50);

    while (m_running) {
        res = pcap_next_ex(m_handle, &header, &pkt_data);

        if (res == 1) {
            analyzePacket(header, pkt_data, buffer);
        }
        else if (res == -1) {
            emit errorOccurred(tr("Read error"));
            break;
        }
        else if (res == -2) {
            break; 
        }

        if (buffer.size() >= (m_isOfflineMode ? 200 : 10)) {
            emit packetsReady(buffer);
            buffer.clear();
            if (m_isOfflineMode) QCoreApplication::processEvents();
        }
        if (!m_isOfflineMode) QCoreApplication::processEvents();
    }

    if (!buffer.isEmpty()) emit packetsReady(buffer);
    pcap_close(m_handle);
    emit finished();
}

void SnifferWorker::analyzePacket(const pcap_pkthdr* header, const u_char* pkt_data, QVector<PacketDisplayData>& buffer) {
    EthHeader* eth = (EthHeader*)pkt_data;
    if (ntohs(eth->type) != 0x0800) return;

    IpHeader* ip = (IpHeader*)(pkt_data + sizeof(EthHeader));
    int ipHeaderLen = (ip->ver_ihl & 0x0F) * 4;

    PacketDisplayData info;
    m_packetCount++;
    info.number = m_packetCount;
    info.time = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    info.length = header->len;
    info.isUrgent = false;
    info.rawData = QByteArray((const char*)pkt_data, header->caplen);

    info.srcPort = 0;
    info.dstPort = 0;

    quint32 saddr = (ip->saddr[0] << 24) | (ip->saddr[1] << 16) | (ip->saddr[2] << 8) | (ip->saddr[3]);
    quint32 daddr = (ip->daddr[0] << 24) | (ip->daddr[1] << 16) | (ip->daddr[2] << 8) | (ip->daddr[3]);
    info.sourceIp = QHostAddress(saddr).toString();
    info.destIp = QHostAddress(daddr).toString();

    switch (ip->proto) {
    case 1:
        info.protocol = "ICMP"; info.info = "Echo Request/Reply";
        detectAnomalies(info.sourceIp, info.destIp, 1, 0, 0, info.length, info);
        break;
    case 2:
        info.protocol = "IGMP"; info.info = "Group Membership"; break;
    case 6: {
        info.protocol = "TCP";
        TcpHeader* tcp = (TcpHeader*)(pkt_data + sizeof(EthHeader) + ipHeaderLen);
        info.srcPort = ntohs(tcp->sport);
        info.dstPort = ntohs(tcp->dport);
        info.info = QString("%1 -> %2 [Seq: %3]").arg(info.srcPort).arg(info.dstPort).arg(ntohl(tcp->seqnum));
        detectAnomalies(info.sourceIp, info.destIp, 6, info.dstPort, tcp->flags, info.length, info);
        break;
    }
    case 17: {
        UdpHeader* udp = (UdpHeader*)(pkt_data + sizeof(EthHeader) + ipHeaderLen);
        info.srcPort = ntohs(udp->sport);
        info.dstPort = ntohs(udp->dport);
        info.protocol = "UDP"; info.info = QString("%1 -> %2").arg(info.srcPort).arg(info.dstPort);

        if (info.srcPort == 4500 || info.dstPort == 4500) { info.protocol = "IPSec (NAT-T)"; info.info = "Encapsulated ESP"; }
        else if (info.srcPort == 500 || info.dstPort == 500) { info.protocol = "ISAKMP"; info.info = "VPN Key Exchange"; }
        else if (info.srcPort == 1194 || info.dstPort == 1194) { info.protocol = "OpenVPN"; info.info = "Encrypted Tunnel"; }
        else if (info.srcPort == 51820 || info.dstPort == 51820) { info.protocol = "WireGuard"; info.info = "Secure Tunnel"; }
        else if (info.srcPort == 53 || info.dstPort == 53) { info.protocol = "DNS"; info.info = "Domain Name Query"; }

        detectAnomalies(info.sourceIp, info.destIp, 17, info.dstPort, 0, info.length, info);
        break;
    }
    case 47: info.protocol = "GRE"; info.info = "Generic Routing Encapsulation"; break;
    case 50: info.protocol = "ESP"; info.info = "Encapsulating Security Payload"; break;
    case 89: info.protocol = "OSPF"; info.info = "Routing Protocol"; break;
    default: info.protocol = QString("UNK (%1)").arg(ip->proto); info.info = "Unknown Protocol"; break;
    }
    buffer.append(info);
}

void SnifferWorker::detectAnomalies(const QString& srcIp, const QString& dstIp, int proto, int dport, int flags, int len, PacketDisplayData& data) {
    qint64 now = QDateTime::currentSecsSinceEpoch();
    IpStats& st = m_stats[srcIp];

    if (now - st.lastReset > 5) { st.synCount = 0; st.icmpCount = 0; st.ports.clear(); st.lastReset = now; }


    if (srcIp == dstIp) { data.alert = tr("Land Attack (Self-DoS)"); data.isUrgent = true; return; }

    if (proto == 6) {
        if (flags == 0) { data.alert = tr("Null Scan (Nmap)"); data.isUrgent = true; }
        else if ((flags & 0x29) == 0x29) { data.alert = tr("Xmas Scan"); data.isUrgent = true; }
        else if ((flags & 0x02) && (flags & 0x01)) { data.alert = tr("SYN-FIN Anomaly"); data.isUrgent = true; }

        if (flags & 0x02) {
            st.synCount++;
            if (st.synCount > 100) { data.alert = tr("SYN Flood"); data.isUrgent = true; }
            st.ports[dport]++;
            if (st.ports.size() > 20) { data.alert = tr("Port Scan"); data.isUrgent = true; }
        }
    }
    else if (proto == 17) {
        if ((dport == 53 || st.ports.contains(53)) && len > 1000) { data.alert = tr("DNS Tunneling Suspect"); data.isUrgent = true; }
    }
    else if (proto == 1) {
        st.icmpCount++;
        if (st.icmpCount > 50) { data.alert = tr("ICMP Flood"); data.isUrgent = true; }
        if (len > 1400) { data.alert = tr("Large ICMP (Suspicious)"); data.isUrgent = true; }
    }

    if (data.rawData.size() > 54) {
        QByteArray payload = data.rawData.mid(0, 1000);
        QString content = QString::fromLatin1(payload);

        if (content.contains("UNION SELECT", Qt::CaseInsensitive) ||
            content.contains("' OR '1'='1", Qt::CaseInsensitive) ||
            content.contains("DROP TABLE", Qt::CaseInsensitive)) {
            data.alert = tr("SQL Injection Attempt"); data.isUrgent = true;
        }
        else if (content.contains("<script>", Qt::CaseInsensitive) ||
            content.contains("javascript:", Qt::CaseInsensitive)) {
            data.alert = tr("XSS Attack Detected"); data.isUrgent = true;
        }
        else if (content.contains("cmd.exe", Qt::CaseInsensitive) ||
            content.contains("/bin/sh", Qt::CaseInsensitive)) {
            data.alert = tr("Remote Shell Attempt"); data.isUrgent = true;
        }
        else if (dport == 80 || dport == 8080 || dport == 21) {
            if (content.contains("password=", Qt::CaseInsensitive) ||
                content.contains("Authorization: Basic", Qt::CaseInsensitive)) {
                data.alert = tr("Credentials Leak"); data.isUrgent = true;
            }
        }
    }
}