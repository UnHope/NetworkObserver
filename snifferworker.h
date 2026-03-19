#pragma once
#include <QObject>
#include <QVector>
#include <QMap>
#include <pcap.h>
#include "packetdata.h"

struct IpStats {
    int synCount = 0;
    int icmpCount = 0;
    QMap<int, int> ports;
    qint64 lastReset = 0;
};

class SnifferWorker : public QObject
{
    Q_OBJECT

public:
    explicit SnifferWorker(QObject* parent = nullptr);
    ~SnifferWorker();

    void setInterface(const std::string& name);
    void setFileName(const QString& fileName);

public slots:
    void startCapture();
    void stopCapture();

signals:
    void packetsReady(QVector<PacketDisplayData> packets);
    void errorOccurred(QString message);
    void finished();

private:
    void analyzePacket(const pcap_pkthdr* header, const u_char* pkt_data, QVector<PacketDisplayData>& buffer);

    void detectAnomalies(const QString& srcIp, const QString& dstIp, int proto, int dport, int flags, int len, PacketDisplayData& data);

    pcap_t* m_handle = nullptr;
    bool m_running = false;
    std::string m_interfaceName;
    QString m_fileName;
    bool m_isOfflineMode = false;

    long m_packetCount = 0;


    QMap<QString, IpStats> m_stats;
};