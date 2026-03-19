#include "PacketModel.h"
#include <QColor>
#include <QBrush>

PacketModel::PacketModel(QObject* parent) : QAbstractTableModel(parent) {}

int PacketModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    return m_data.count();
}

int PacketModel::columnCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    return 8;
}

QVariant PacketModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid()) return QVariant();

    const PacketDisplayData& pkt = m_data.at(index.row());

    if (role == Qt::ForegroundRole) {
        return QBrush(Qt::black);
    }

    if (role == Qt::BackgroundRole) {
        if (pkt.isUrgent) return QBrush(QColor(255, 100, 100));
        if (pkt.protocol == "TCP") return QBrush(QColor(220, 255, 220));
        if (pkt.protocol == "UDP" || pkt.protocol == "DNS") return QBrush(QColor(200, 245, 200));
        if (pkt.protocol == "ICMP") return QBrush(QColor(210, 255, 180));
        if (pkt.protocol.contains("VPN") || pkt.protocol == "WireGuard" || pkt.protocol == "OpenVPN")
            return QBrush(QColor(200, 230, 255));
        return QBrush(Qt::white);
    }

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case 0: return (long long)pkt.number;
        case 1: return pkt.time;
        case 2: return pkt.sourceIp;
        case 3: return pkt.destIp;
        case 4: if (pkt.srcPort > 0) return pkt.srcPort; else return "";
        case 5: if (pkt.dstPort > 0) return pkt.dstPort; else return "";
        case 6: return pkt.protocol;
        case 7: return pkt.length;
        default: return QVariant();
        }
    }

    if (role == Qt::TextAlignmentRole) {
        if (index.column() == 0 || index.column() == 4 || index.column() == 5 || index.column() == 7)
            return int(Qt::AlignRight | Qt::AlignVCenter);
        return int(Qt::AlignLeft | Qt::AlignVCenter);
    }

    return QVariant();
}

QVariant PacketModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal) return QVariant();
    switch (section) {
    case 0: return tr("No.");
    case 1: return tr("Time");
    case 2: return tr("Source IP");
    case 3: return tr("Dest IP");
    case 4: return tr("Src Port");
    case 5: return tr("Dst Port");
    case 6: return tr("Protocol");
    case 7: return tr("Length");
    default: return QString();
    }
}

void PacketModel::appendPackets(const QList<PacketDisplayData>& newPackets) {
    if (newPackets.isEmpty()) return;
    beginInsertRows(QModelIndex(), m_data.count(), m_data.count() + newPackets.count() - 1);
    m_data.append(newPackets);
    endInsertRows();
}

void PacketModel::clear() {
    beginResetModel();
    m_data.clear();
    endResetModel();
}