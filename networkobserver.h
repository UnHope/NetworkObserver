#pragma once

#include <QWidget>
#include <QTableView>
#include <QPushButton>
#include <QComboBox>
#include <QLabel>
#include <QThread>
#include <QTimer>
#include <QLineEdit>
#include <QTextEdit>
#include <QSortFilterProxyModel>
#include <QTranslator>
#include <QEvent>

#include "PacketModel.h"
#include "snifferworker.h"
#include "statswindow.h"

class NetworkObserver : public QWidget
{
    Q_OBJECT

public:
    explicit NetworkObserver(QWidget* parent = nullptr);
    ~NetworkObserver();

protected:
    void changeEvent(QEvent* event) override;

private slots:
    void onStartStopClicked();
    void onSnifferFinished();
    void onPacketsReady(const QVector<PacketDisplayData>& packets);
    void processPacketBuffer();
    void onClearClicked();
    void onStatsClicked();
    void onSaveClicked();
    void onOpenClicked();
    void onFilterTextChanged(const QString& text);
    void onRowSelected(const QModelIndex& current, const QModelIndex& previous);

    void onLanguageClicked();
    void onAboutClicked(); 

private:
    void loadAdapters();
    void writePcapHeader(QFile& file);
    void writePacketToPcap(QFile& file, const PacketDisplayData& pkt);

    void retranslateUi();

    QComboBox* m_adapterCombo;
    QPushButton* m_startBtn;
    QPushButton* m_clearBtn;
    QPushButton* m_statsBtn;
    QPushButton* m_saveBtn;
    QPushButton* m_openBtn;

    QPushButton* m_langBtn;
    QPushButton* m_aboutBtn; 

    QLineEdit* m_filterEdit;
    QLabel* m_statusLabel;
    QLabel* m_adapterLabel;
    QLabel* m_filterLabel;

    QTableView* m_tableView;
    QTextEdit* m_hexView;

    PacketModel* m_model;
    QSortFilterProxyModel* m_proxyModel;

    QThread* m_workerThread = nullptr;
    SnifferWorker* m_worker = nullptr;
    QTimer* m_updateTimer;
    QVector<PacketDisplayData> m_buffer;

    StatsWindow* m_statsWindow = nullptr;
    bool m_isCapturing = false;

    QTranslator m_translator;
    bool m_isRussian = false;
};