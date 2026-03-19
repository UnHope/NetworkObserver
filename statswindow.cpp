#include "statswindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QDateTime>
#include <QLabel>
#include <QDebug>

StatsWindow::StatsWindow(QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Live Network Security Analysis"));
    resize(1200, 800);

    if (parent) {
        QPalette pal = palette();
        pal.setColor(QPalette::Window, parent->palette().color(QPalette::Window));
        setPalette(pal);
    }
    setAutoFillBackground(true);

    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    QHBoxLayout* controlsLayout = new QHBoxLayout();
    m_excludeTcpCheck = new QCheckBox(tr("Exclude TCP (Show minor protocols)"), this);
    QFont font = m_excludeTcpCheck->font();
    font.setBold(true);
    m_excludeTcpCheck->setFont(font);

    controlsLayout->addWidget(m_excludeTcpCheck);
    controlsLayout->addStretch();
    mainLayout->addLayout(controlsLayout);

    connect(m_excludeTcpCheck, &QCheckBox::toggled, this, &StatsWindow::onExcludeTcpToggled);

    m_tabWidget = new QTabWidget(this);
    mainLayout->addWidget(m_tabWidget);

    QWidget* tabGeneral = new QWidget();
    QVBoxLayout* generalLayout = new QVBoxLayout(tabGeneral);

    m_protocolChart = new QChartView(this);
    setupChartStyle(new QChart(), m_protocolChart, tr("Protocol Distribution"));
    generalLayout->addWidget(m_protocolChart);

    m_timeChart = new QChartView(this);
    setupChartStyle(new QChart(), m_timeChart, tr("Traffic Load (Packets/Sec)"));
    generalLayout->addWidget(m_timeChart);

    m_tabWidget->addTab(tabGeneral, tr("Traffic Overview"));

    QWidget* tabThreats = new QWidget();
    QVBoxLayout* threatsLayout = new QVBoxLayout(tabThreats);

    QHBoxLayout* searchLayout = new QHBoxLayout();
    QLabel* searchLabel = new QLabel(tr("Search Threats:"), this);
    searchLabel->setStyleSheet("font-weight: bold;");
    searchLayout->addWidget(searchLabel);

    m_searchEdit = new QLineEdit(this);
    m_searchEdit->setPlaceholderText(tr("Filter by Type, IP, Port or Info..."));
    searchLayout->addWidget(m_searchEdit);
    threatsLayout->addLayout(searchLayout);

    QSplitter* splitter = new QSplitter(Qt::Vertical, this);

    m_threatsTable = new QTableWidget(this);
    QStringList headers;
    headers << tr("No.") << tr("Time") << tr("Threat Type") << tr("Source IP") << tr("Dest IP") << tr("Details");
    m_threatsTable->setColumnCount(headers.size());
    m_threatsTable->setHorizontalHeaderLabels(headers);
    m_threatsTable->horizontalHeader()->setStretchLastSection(true);
    m_threatsTable->verticalHeader()->setVisible(false);
    m_threatsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_threatsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_threatsTable->setStyleSheet("QHeaderView::section { background-color: #8B0000; color: white; font-weight: bold; }");

    splitter->addWidget(m_threatsTable);

    m_threatDetails = new QTextEdit(this);
    m_threatDetails->setReadOnly(true);
    m_threatDetails->setFont(QFont("Courier New", 10));
    m_threatDetails->setPlaceholderText(tr("Select a threat row to analyze packet payload..."));

    splitter->addWidget(m_threatDetails);
    splitter->setStretchFactor(0, 65);
    splitter->setStretchFactor(1, 35);

    threatsLayout->addWidget(splitter);
    m_tabWidget->addTab(tabThreats, tr("Detected Threats"));

    connect(m_threatsTable, &QTableWidget::itemSelectionChanged, this, &StatsWindow::onThreatRowSelected);
    connect(m_searchEdit, &QLineEdit::textChanged, this, &StatsWindow::onThreatSearchChanged);
}

void StatsWindow::setupChartStyle(QChart* chart, QChartView* view, QString title)
{
    chart->setTitle(title);
    chart->setTitleFont(QFont("Segoe UI", 12, QFont::Bold));
    chart->setAnimationOptions(QChart::NoAnimation);
    chart->setBackgroundBrush(Qt::NoBrush);
    view->setBackgroundBrush(Qt::NoBrush);
    chart->setTitleBrush(palette().text());

    chart->legend()->setLabelColor(palette().text().color());
    chart->legend()->setFont(QFont("Segoe UI", 10));
    chart->legend()->setMarkerShape(QLegend::MarkerShapeCircle);

    view->setChart(chart);
    view->setRenderHint(QPainter::Antialiasing);
}

void clearChart(QChart* chart) {
    chart->removeAllSeries();
    QList<QAbstractAxis*> axes = chart->axes();
    for (auto axis : axes) chart->removeAxis(axis);
}

void StatsWindow::updateData(const QList<PacketDisplayData>& packets)
{
    m_currentPackets = packets;
    calculateProtocolStats();
    calculateTrafficOverTime();
    updateThreatsTable();
}

void StatsWindow::onExcludeTcpToggled()
{
    calculateProtocolStats();
    calculateTrafficOverTime();
}

void StatsWindow::calculateProtocolStats()
{
    QChart* chart = m_protocolChart->chart();
    clearChart(chart);

    if (m_currentPackets.isEmpty()) return;

    QMap<QString, int> counts;
    int total = 0;
    bool hideTcp = m_excludeTcpCheck->isChecked();

    for (const auto& pkt : m_currentPackets) {
        if (hideTcp && pkt.protocol == "TCP") continue;
        counts[pkt.protocol]++;
        total++;
    }

    if (total == 0) return;

    QPieSeries* series = new QPieSeries();
    for (auto it = counts.begin(); it != counts.end(); ++it) {
        QPieSlice* slice = series->append(it.key(), it.value());

        double percentage = (total > 0) ? (static_cast<double>(it.value()) / total * 100.0) : 0;
        QString label = QString("%1 - %2%").arg(it.key()).arg(percentage, 0, 'f', 1);

        slice->setLabel(label);
        slice->setLabelVisible(false);

        if (percentage > 50) slice->setExploded(true);
    }

    series->setHoleSize(0.35);
    chart->addSeries(series);
    chart->legend()->setVisible(true);
    chart->legend()->setAlignment(Qt::AlignRight);
}

void StatsWindow::calculateTrafficOverTime()
{
    QChart* chart = m_timeChart->chart();
    clearChart(chart);

    QMap<QString, int> timeCounts;
    bool hideTcp = m_excludeTcpCheck->isChecked();

    for (const auto& pkt : m_currentPackets) {
        if (hideTcp && pkt.protocol == "TCP") continue;
        timeCounts[pkt.time.left(8)]++;
    }

    QLineSeries* series = new QLineSeries();
    QStringList categories;
    int index = 0;
    int start = qMax(0, timeCounts.size() - 20);
    auto it = timeCounts.begin();
    std::advance(it, start);

    for (; it != timeCounts.end(); ++it) {
        series->append(index, it.value());
        categories << it.key();
        index++;
    }

    QPen pen(QColor(0, 120, 215));
    pen.setWidth(2);
    series->setPen(pen);
    series->setPointsVisible(true);

    chart->addSeries(series);
    chart->legend()->setVisible(false);

    QBarCategoryAxis* axisX = new QBarCategoryAxis();
    axisX->append(categories);
    axisX->setLabelsColor(palette().text().color());
    chart->addAxis(axisX, Qt::AlignBottom);
    series->attachAxis(axisX);

    QValueAxis* axisY = new QValueAxis();
    axisY->setLabelsColor(palette().text().color());
    axisY->setLabelFormat("%d");
    chart->addAxis(axisY, Qt::AlignLeft);
    series->attachAxis(axisY);
}

void StatsWindow::updateThreatsTable()
{
    m_threatsTable->blockSignals(true);
    m_threatsTable->setRowCount(0);
    m_threatDetails->clear();

    for (const auto& pkt : m_currentPackets) {
        if (pkt.isUrgent) {
            int row = m_threatsTable->rowCount();
            m_threatsTable->insertRow(row);

            QTableWidgetItem* itemNo = new QTableWidgetItem(QString::number(pkt.number));
            QTableWidgetItem* itemTime = new QTableWidgetItem(pkt.time);

            QString threatName = pkt.alert.isEmpty() ? "Suspicious Activity" : pkt.alert;
            QTableWidgetItem* itemThreat = new QTableWidgetItem(threatName);

            QTableWidgetItem* itemSrc = new QTableWidgetItem(pkt.sourceIp);
            QTableWidgetItem* itemDst = new QTableWidgetItem(pkt.destIp);
            QTableWidgetItem* itemInfo = new QTableWidgetItem(pkt.info);

            QColor threatBg(255, 225, 225);

            itemNo->setBackground(threatBg);
            itemTime->setBackground(threatBg);
            itemThreat->setBackground(threatBg);
            itemSrc->setBackground(threatBg);
            itemDst->setBackground(threatBg);
            itemInfo->setBackground(threatBg);

            itemThreat->setFont(QFont("Arial", 9, QFont::Bold));
            itemThreat->setForeground(Qt::red);

            m_threatsTable->setItem(row, 0, itemNo);
            m_threatsTable->setItem(row, 1, itemTime);
            m_threatsTable->setItem(row, 2, itemThreat);
            m_threatsTable->setItem(row, 3, itemSrc);
            m_threatsTable->setItem(row, 4, itemDst);
            m_threatsTable->setItem(row, 5, itemInfo);
        }
    }
    m_threatsTable->blockSignals(false);
    if (!m_searchEdit->text().isEmpty()) {
        onThreatSearchChanged(m_searchEdit->text());
    }
}

void StatsWindow::onThreatSearchChanged(const QString& text)
{
    QString filter = text.toLower();

    for (int i = 0; i < m_threatsTable->rowCount(); ++i) {
        bool match = false;
        for (int j = 0; j < m_threatsTable->columnCount(); ++j) {
            QTableWidgetItem* item = m_threatsTable->item(i, j);
            if (item && item->text().toLower().contains(filter)) {
                match = true;
                break;
            }
        }
        m_threatsTable->setRowHidden(i, !match);
    }
}

void StatsWindow::onThreatRowSelected()
{
    auto selectedItems = m_threatsTable->selectedItems();
    if (selectedItems.isEmpty()) return;

    int row = selectedItems.first()->row();
    QTableWidgetItem* noItem = m_threatsTable->item(row, 0);
    if (!noItem) return;

    long packetNum = noItem->text().toLong();

    PacketDisplayData targetPkt;
    bool found = false;
    for (const auto& pkt : m_currentPackets) {
        if (pkt.number == packetNum) {
            targetPkt = pkt;
            found = true;
            break;
        }
    }

    if (!found) return;

    QString report;
    report += "=================================================\n";
    report += tr("Security Alert: %1\n").arg(targetPkt.alert);
    report += "=================================================\n\n";

    report += tr("Timestamp:   %1\n").arg(targetPkt.time);
    report += tr("Source:      %1 : %2\n").arg(targetPkt.sourceIp).arg(targetPkt.srcPort);
    report += tr("Destination: %1 : %2\n").arg(targetPkt.destIp).arg(targetPkt.dstPort);
    report += tr("Protocol:    %1\n").arg(targetPkt.protocol);
    report += tr("Info:        %1\n").arg(targetPkt.info);
    report += tr("Packet Size: %1 bytes\n").arg(targetPkt.length);

    if (targetPkt.rawData.size() > 54) {
        QString content = QString::fromLatin1(targetPkt.rawData);

        report += tr("\n--- Content Analysis ---\n");
        bool suspicious = false;
        if (content.contains("SELECT", Qt::CaseInsensitive) || content.contains("UNION", Qt::CaseInsensitive)) {
            report += tr("[!] Detected SQL keywords (Possible Injection)\n"); suspicious = true;
        }
        if (content.contains("<script>", Qt::CaseInsensitive)) {
            report += tr("[!] Detected Script tags (Possible XSS)\n"); suspicious = true;
        }
        if (content.contains("cmd.exe", Qt::CaseInsensitive) || content.contains("/bin/sh", Qt::CaseInsensitive)) {
            report += tr("[!] Detected Shell commands (Possible RCE)\n"); suspicious = true;
        }

        if (!suspicious) report += "No standard text signatures found in preview.\n";
    }

    report += tr("\n--- Raw Packet Dump (Hex & ASCII) ---\n");

    QString hexPart;
    QString asciiPart;
    QByteArray data = targetPkt.rawData;

    for (int i = 0; i < data.size(); ++i) {
        QString byteStr = QString("%1").arg((unsigned char)data[i], 2, 16, QChar('0')).toUpper();
        hexPart += byteStr + " ";
        char c = data[i];
        if (c >= 32 && c <= 126) asciiPart += c;
        else asciiPart += ".";

        if ((i + 1) % 16 == 0) {
            report += QString("%1   %2   %3\n")
                .arg(i - 15, 6, 16, QChar('0')).toUpper()
                .arg(hexPart.leftJustified(48))
                .arg(asciiPart);
            hexPart.clear(); asciiPart.clear();
        }
    }
    if (!asciiPart.isEmpty()) {
        int offset = (data.size() / 16) * 16;
        report += QString("%1   %2   %3\n")
            .arg(offset, 6, 16, QChar('0')).toUpper()
            .arg(hexPart.leftJustified(48))
            .arg(asciiPart);
    }

    m_threatDetails->setText(report);
    m_threatDetails->moveCursor(QTextCursor::Start);
}