#pragma once
#include <QString>
#include <QByteArray>
#include <winsock2.h> 

#pragma pack(push, 1)
struct EthHeader {
    u_char dest[6];
    u_char src[6];
    u_short type;
};

struct IpHeader {
    u_char ver_ihl;
    u_char tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short crc;
    u_char saddr[4];
    u_char daddr[4];
};

struct TcpHeader {
    u_short sport;
    u_short dport;
    u_int seqnum;
    u_int acknum;
    u_char offset_reserved;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short urgentptr;
};

struct UdpHeader {
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
};
#pragma pack(pop)

struct PacketDisplayData {
    long number;
    QString time;
    QString sourceIp;
    QString destIp;
    QString protocol;
    QString info;
    QString alert;
    int length;
    int srcPort;
    int dstPort;
    bool isUrgent;
    QByteArray rawData;
};