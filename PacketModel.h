#pragma once
#include <QAbstractTableModel>
#include <QList>
#include "packetdata.h"

class PacketModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit PacketModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    void appendPackets(const QList<PacketDisplayData>& newPackets);
    const PacketDisplayData& getPacket(int row) const { return m_data.at(row); }
    const QList<PacketDisplayData>& getAllData() const { return m_data; }

    void clear(); 

private:
    QList<PacketDisplayData> m_data;
};