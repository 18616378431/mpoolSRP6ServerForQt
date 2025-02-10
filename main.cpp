#include <QCoreApplication>
#include <iostream>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QDebug>

#include "network.h"

void dbTest(QString sql);

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    std::cout << "main func" << std::endl;

    qDebug() << "available drivers";

    QStringList drivers = QSqlDatabase::drivers();

    foreach (QString driver, drivers)
    {
        qDebug() << driver;
    }

    // dbTest(QString("SELECT id, username, last_ip, salt, verifier FROM account a WHERE username = '%1' limit 1").arg("TEST"));

    // TcpServer server(QCoreApplication::instance()->thread());
    TcpServer server;

    //tcpserver run in thread, not for sub handler
    // QThread *thread = new QThread();
    // server.moveToThread(thread);

    // QObject::connect(thread, &QThread::finished, &server, &QObject::deleteLater);

    // thread->start();

    //improve
    if (!server.listen(QHostAddress::Any, 1234)) {
        qDebug() << "network server listen fail!"
                 << ",error reason:" << server.errorString();

        return 1;
    } else {
        qDebug() << "Server started!====";
    }

    qDebug() << "main thread:" << QThread::currentThreadId();

    return a.exec();
}

void dbTest(QString sql)
{
    auto db = QSqlDatabase::addDatabase("QMYSQL");
    db.setHostName("127.0.0.1");
    db.setPort(3506);
    db.setDatabaseName("mpool");
    db.setUserName("root");
    db.setPassword("123456");

    if (!db.open())
    {
        qDebug() << "mysql connection fail!";
    }
    else
    {
        qDebug() << "connect to the db!";
    }

    QSqlQuery query;

    if (!query.exec(sql))
    {
        qDebug() << "sel error:" << sql;
    }
    else
    {
        while (query.next())
        {
            QString username = query.value("username").toString();

            qDebug() << "get username:" << username;
        }
    }

}
