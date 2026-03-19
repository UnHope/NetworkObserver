#include "networkobserver.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QDebug>
#include <pcap.h> 
#include <QSplitter>
#include <QFileDialog>
#include <QDataStream>
#include <QDateTime>
#include <QCoreApplication>

NetworkObserver::NetworkObserver(QWidget* parent) : QWidget(parent) {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    QHBoxLayout* topPanel = new QHBoxLayout();

    m_adapterLabel = new QLabel(this);
    topPanel->addWidget(m_adapterLabel);

    m_adapterCombo = new QComboBox(this);
    m_adapterCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    topPanel->addWidget(m_adapterCombo);

    m_startBtn = new QPushButton(this);
    topPanel->addWidget(m_startBtn);

    m_clearBtn = new QPushButton(this);
    topPanel->addWidget(m_clearBtn);

    m_openBtn = new QPushButton(this);
    topPanel->addWidget(m_openBtn);

    m_saveBtn = new QPushButton(this);
    topPanel->addWidget(m_saveBtn);

    m_statsBtn = new QPushButton(this);
    topPanel->addWidget(m_statsBtn);

    m_filterLabel = new QLabel(this);
    topPanel->addWidget(m_filterLabel);

    m_filterEdit = new QLineEdit(this);
    topPanel->addWidget(m_filterEdit);

    m_statusLabel = new QLabel(this);
    topPanel->addWidget(m_statusLabel);

   
    mainLayout->addLayout(topPanel);

    QSplitter* splitter = new QSplitter(Qt::Vertical, this);
    mainLayout->addWidget(splitter);

    m_tableView = new QTableView(this);
    splitter->addWidget(m_tableView);

    m_hexView = new QTextEdit(this);
    m_hexView->setReadOnly(true);
    m_hexView->setFont(QFont("Courier New", 10));
    splitter->addWidget(m_hexView);

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);

  
    QHBoxLayout* bottomLayout = new QHBoxLayout();

    
    m_langBtn = new QPushButton("EN / RU", this);
    
    bottomLayout->addWidget(m_langBtn);

    
    m_aboutBtn = new QPushButton(this);
    bottomLayout->addWidget(m_aboutBtn);

   
    bottomLayout->addStretch();

    
    mainLayout->addLayout(bottomLayout);

 
    m_model = new PacketModel(this);
    m_proxyModel = new QSortFilterProxyModel(this);
    m_proxyModel->setSourceModel(m_model);
    m_proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxyModel->setFilterKeyColumn(-1);
    m_tableView->setModel(m_proxyModel);

    m_tableView->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    m_tableView->verticalHeader()->setDefaultSectionSize(24);
    m_tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tableView->horizontalHeader()->setStretchLastSection(true);
    m_tableView->verticalHeader()->setVisible(false);

    m_updateTimer = new QTimer(this);
    m_updateTimer->setInterval(200);
    connect(m_updateTimer, &QTimer::timeout, this, &NetworkObserver::processPacketBuffer);
    m_updateTimer->start();

    loadAdapters();

    
    connect(m_startBtn, &QPushButton::clicked, this, &NetworkObserver::onStartStopClicked);
    connect(m_clearBtn, &QPushButton::clicked, this, &NetworkObserver::onClearClicked);
    connect(m_statsBtn, &QPushButton::clicked, this, &NetworkObserver::onStatsClicked);
    connect(m_saveBtn, &QPushButton::clicked, this, &NetworkObserver::onSaveClicked);
    connect(m_openBtn, &QPushButton::clicked, this, &NetworkObserver::onOpenClicked);

    connect(m_langBtn, &QPushButton::clicked, this, &NetworkObserver::onLanguageClicked);
    connect(m_aboutBtn, &QPushButton::clicked, this, &NetworkObserver::onAboutClicked); // Подключаем About

    connect(m_filterEdit, &QLineEdit::textChanged, this, &NetworkObserver::onFilterTextChanged);
    connect(m_tableView->selectionModel(), &QItemSelectionModel::currentRowChanged,
        this, &NetworkObserver::onRowSelected);

    retranslateUi();
}

NetworkObserver::~NetworkObserver() {
    if (m_workerThread) {
        m_worker->stopCapture();
        m_workerThread->quit();
        m_workerThread->wait();
    }
}


void NetworkObserver::onAboutClicked() {
    QMessageBox msgBox(this);
    msgBox.setWindowTitle(tr("About Program"));

   
    QPixmap icon("logo.png");
    if (!icon.isNull()) {
        msgBox.setIconPixmap(icon.scaled(100, 100, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    }
    else {
        msgBox.setIcon(QMessageBox::Information);
    }

   
    msgBox.setTextFormat(Qt::RichText);

    QString text;
    
    text += QString("<h3 style='margin:0;'>Network Observer</h3>");


   
    text += QString("%1: UnHope<br>").arg(tr("Developer"));
    text += QString("%1: 1.0").arg(tr("Version"));
    text += QString("<p>%1</p>").arg(tr("The program is a diploma project of a student of NRU \"BelSU\""));

    msgBox.setText(text);
    msgBox.setStandardButtons(QMessageBox::Ok);
    msgBox.exec();
}
void NetworkObserver::onLanguageClicked() {
    if (m_isRussian) {
        qApp->removeTranslator(&m_translator);
        m_isRussian = false;
    }
    else {
        if (m_translator.load("ru.qm", qApp->applicationDirPath())) {
            qApp->installTranslator(&m_translator);
            m_isRussian = true;
        }
        else {
            QMessageBox::warning(this, "Error", "Could not load ru.qm file!");
        }
    }

}

void NetworkObserver::changeEvent(QEvent* event) {
    if (event->type() == QEvent::LanguageChange) {
        retranslateUi();
    }
    QWidget::changeEvent(event);
}

void NetworkObserver::retranslateUi() {
    setWindowTitle(tr("Network Observer"));
    m_adapterLabel->setText(tr("Adapter:"));
    m_filterLabel->setText(tr("Filter:"));

    if (!m_isCapturing) {
        m_startBtn->setText(tr("Start Capture"));
        m_statusLabel->setText(tr("Status: Stopped"));
    }
    else {
        m_startBtn->setText(tr("Stop Capture"));
        m_statusLabel->setText(tr("Status: Capturing..."));
    }

    m_clearBtn->setText(tr("Clear"));
    m_openBtn->setText(tr("Open .pcap"));
    m_saveBtn->setText(tr("Save .pcap"));
    m_statsBtn->setText(tr("Statistics"));
    m_aboutBtn->setText(tr("About")); 

    if (m_isRussian) m_langBtn->setText(tr("Language: RU"));
    else m_langBtn->setText(tr("Language: EN"));

    m_model->headerData(0, Qt::Horizontal, Qt::DisplayRole);
    m_tableView->viewport()->update();
}


void NetworkObserver::loadAdapters() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) return;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        QString name = QString::fromLocal8Bit(d->name);
        QString desc = d->description ? QString::fromLocal8Bit(d->description) : name;
        m_adapterCombo->addItem(desc, name);
    }
    pcap_freealldevs(alldevs);
}

void NetworkObserver::onStartStopClicked() {
    if (!m_isCapturing) {
        QString adapterName = m_adapterCombo->currentData().toString();
        if (adapterName.isEmpty()) return;

        m_workerThread = new QThread;
        m_worker = new SnifferWorker();
        m_worker->setInterface(adapterName.toStdString());
        m_worker->moveToThread(m_workerThread);

        connect(m_workerThread, &QThread::started, m_worker, &SnifferWorker::startCapture);
        connect(m_worker, &SnifferWorker::packetsReady, this, &NetworkObserver::onPacketsReady);
        connect(m_worker, &SnifferWorker::finished, m_workerThread, &QThread::quit);
        connect(m_worker, &SnifferWorker::finished, this, &NetworkObserver::onSnifferFinished);
        connect(m_workerThread, &QThread::finished, m_worker, &QObject::deleteLater);
        connect(m_workerThread, &QThread::finished, m_workerThread, &QObject::deleteLater);
        connect(m_worker, &SnifferWorker::errorOccurred, this, [this](QString msg) {
            QMessageBox::warning(this, tr("Sniffer Error"), msg);
            });

        m_workerThread->start();

        m_isCapturing = true;
        retranslateUi();
        m_openBtn->setEnabled(false); m_saveBtn->setEnabled(false);
        m_adapterCombo->setEnabled(false);
        m_statusLabel->setStyleSheet("color: green; font-weight: bold;");
    }
    else {
        if (m_worker) m_worker->stopCapture();
        m_startBtn->setEnabled(false);
        m_statusLabel->setText(tr("Status: Stopping..."));
    }
}

void NetworkObserver::onSnifferFinished() {
    m_isCapturing = false;
    retranslateUi();
    m_startBtn->setEnabled(true);
    m_openBtn->setEnabled(true);
    m_saveBtn->setEnabled(true);
    m_adapterCombo->setEnabled(true);
    m_statusLabel->setStyleSheet("color: black;");
    m_worker = nullptr;
    m_workerThread = nullptr;
}

void NetworkObserver::onOpenClicked() {
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open Capture"), "", "PCAP Files (*.pcap *.cap)");
    if (fileName.isEmpty()) return;
    onClearClicked();
    m_workerThread = new QThread;
    m_worker = new SnifferWorker();
    m_worker->setFileName(fileName);
    m_worker->moveToThread(m_workerThread);
    connect(m_workerThread, &QThread::started, m_worker, &SnifferWorker::startCapture);
    connect(m_worker, &SnifferWorker::packetsReady, this, &NetworkObserver::onPacketsReady);
    connect(m_worker, &SnifferWorker::finished, m_workerThread, &QThread::quit);
    connect(m_worker, &SnifferWorker::finished, this, &NetworkObserver::onSnifferFinished);
    connect(m_workerThread, &QThread::finished, m_worker, &QObject::deleteLater);
    connect(m_workerThread, &QThread::finished, m_workerThread, &QObject::deleteLater);
    connect(m_worker, &SnifferWorker::errorOccurred, this, [this](QString msg) { QMessageBox::warning(this, tr("Error"), msg); });
    m_workerThread->start();
    m_isCapturing = true;
    m_startBtn->setText(tr("Stop Loading"));
    m_openBtn->setEnabled(false); m_saveBtn->setEnabled(false);
    m_statusLabel->setText(tr("Status: Reading file..."));
    m_statusLabel->setStyleSheet("color: blue; font-weight: bold;");
}

void NetworkObserver::onSaveClicked() {
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Capture"), "", "PCAP Files (*.pcap)");
    if (fileName.isEmpty()) return;
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly)) { QMessageBox::critical(this, tr("Error"), tr("Could not create file!")); return; }
    writePcapHeader(file);
    const QList<PacketDisplayData>& allData = m_model->getAllData();
    for (const auto& pkt : allData) writePacketToPcap(file, pkt);
    file.close();
    QMessageBox::information(this, tr("Success"), tr("Saved %1 packets.").arg(allData.count()));
}

void NetworkObserver::onClearClicked() {
    m_model->clear();
    m_hexView->clear();
    m_buffer.clear();
    if (m_statsWindow && m_statsWindow->isVisible()) {
        m_statsWindow->updateData(QList<PacketDisplayData>());
    }
}

void NetworkObserver::writePcapHeader(QFile& file) {
    struct {
        quint32 magic = 0xa1b2c3d4;
        quint16 ver_major = 2; quint16 ver_minor = 4;
        qint32 zone = 0; quint32 sig = 0; quint32 snap = 65535; quint32 net = 1;
    } header;
    file.write((const char*)&header, sizeof(header));
}

void NetworkObserver::writePacketToPcap(QFile& file, const PacketDisplayData& pkt) {
    struct { quint32 sec; quint32 usec; quint32 caplen; quint32 len; } header;
    QTime t = QTime::fromString(pkt.time, "HH:mm:ss.zzz");
    QDateTime dt = QDateTime(QDate::currentDate(), t);
    header.sec = dt.toSecsSinceEpoch();
    header.usec = t.msec() * 1000;
    header.caplen = pkt.rawData.size();
    header.len = pkt.length;
    file.write((const char*)&header, sizeof(header));
    file.write(pkt.rawData);
}

void NetworkObserver::onFilterTextChanged(const QString& text) { m_proxyModel->setFilterFixedString(text); }

void NetworkObserver::onStatsClicked() {
    if (m_statsWindow) { m_statsWindow->raise(); m_statsWindow->activateWindow(); return; }
    m_statsWindow = new StatsWindow(this);
    m_statsWindow->setAttribute(Qt::WA_DeleteOnClose);
    connect(m_statsWindow, &QWidget::destroyed, this, [this]() { m_statsWindow = nullptr; });
    m_statsWindow->updateData(m_model->getAllData());
    m_statsWindow->show();
}

void NetworkObserver::onRowSelected(const QModelIndex& current, const QModelIndex& previous) {
    if (!current.isValid()) return;
    QModelIndex sourceIndex = m_proxyModel->mapToSource(current);
    const PacketDisplayData& pkt = m_model->getPacket(sourceIndex.row());
    QByteArray data = pkt.rawData;

    QString output;
    output.append(tr("Packet No: %1 | Length: %2 bytes\n").arg(pkt.number).arg(pkt.length));
    output.append(tr("Proto: %1 | Info: %2\n").arg(pkt.protocol).arg(pkt.info));
    output.append("-----------------------------------------------------------------\n");
    output.append("Offset   Hex                                               ASCII\n");
    output.append("-----------------------------------------------------------------\n");

    QString hexPart, asciiPart;
    for (int i = 0; i < data.size(); ++i) {
        QString byteStr = QString("%1").arg((unsigned char)data[i], 2, 16, QChar('0')).toUpper();
        hexPart += byteStr + " ";
        char c = data[i];
        if (c >= 32 && c <= 126) asciiPart += c; else asciiPart += ".";

        if ((i + 1) % 16 == 0) {
            output.append(QString("%1   %2   %3\n").arg(i - 15, 6, 16, QChar('0')).toUpper().arg(hexPart.leftJustified(48)).arg(asciiPart));
            hexPart.clear(); asciiPart.clear();
        }
    }
    if (!asciiPart.isEmpty()) {
        int offset = (data.size() / 16) * 16;
        output.append(QString("%1   %2   %3\n").arg(offset, 6, 16, QChar('0')).toUpper().arg(hexPart.leftJustified(48)).arg(asciiPart));
    }
    m_hexView->setText(output);
}

void NetworkObserver::onPacketsReady(const QVector<PacketDisplayData>& packets) {
    for (const auto& packet : packets) m_buffer.append(packet);
}

void NetworkObserver::processPacketBuffer() {
    if (m_buffer.isEmpty()) return;
    m_model->appendPackets(m_buffer);
    m_buffer.clear();
    m_tableView->scrollToBottom();
    if (m_statsWindow && m_statsWindow->isVisible()) m_statsWindow->updateData(m_model->getAllData());
}