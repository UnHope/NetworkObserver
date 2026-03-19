#pragma once

#include <QDialog>
#include <QtCharts>
#include <QMap>
#include <QTabWidget>
#include <QTableWidget>
#include <QCheckBox>
#include <QLineEdit>     
#include <QTextEdit>     
#include <QSplitter>     
#include "packetdata.h"

class StatsWindow : public QDialog
{
    Q_OBJECT

public:
    explicit StatsWindow(QWidget* parent = nullptr);

public slots:
    void updateData(const QList<PacketDisplayData>& packets);

private slots:
    void onExcludeTcpToggled();

    void onThreatRowSelected();            
    void onThreatSearchChanged(const QString& text); 

private:
    void calculateProtocolStats();
    void calculateTrafficOverTime();
    void updateThreatsTable();

    void setupChartStyle(QChart* chart, QChartView* view, QString title);

    // UI Elements
    QTabWidget* m_tabWidget;
    QCheckBox* m_excludeTcpCheck;

    // Charts
    QChartView* m_protocolChart;
    QChartView* m_timeChart;

    // Threats Tab Elements
    QLineEdit* m_searchEdit;      
    QTableWidget* m_threatsTable;
    QTextEdit* m_threatDetails;   

    // Data
    QList<PacketDisplayData> m_currentPackets;
};