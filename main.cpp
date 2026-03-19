#include <QtWidgets/QApplication>
#include "networkobserver.h"
#include <QIcon> 

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setWindowIcon(QIcon("shield.ico"));
    NetworkObserver window;
    window.resize(900, 600);
    window.setWindowTitle("Network Observer");
    window.show();

    return app.exec();
}
