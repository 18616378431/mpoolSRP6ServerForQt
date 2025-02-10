#ifndef NETWORK_H
#define NETWORK_H

#include <QCoreApplication>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QDebug>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <optional>

#include "types.h"
#include "SRP6.h"

template<typename T>
using Optional = std::optional<T>;

class ClientHandler : public QObject {
    Q_OBJECT

public:
    // ClientHandler(QTcpSocket *socket, QObject *parent = nullptr);
    ClientHandler(qintptr socketDescriptor, QObject *parent = nullptr);
    QSqlDatabase getDb();
    bool VerifyVersion(uint8 const* a, int32 aLength, mpool::Crypto::SHA1::Digest const& versionProof, bool isReconnect = false);
    QString GetRemoteIpAddress() const;

public:
    void start();

private slots:
    void onReadyRead();

    void onDisconnected();
signals:
    void finished();

private:
    QTcpSocket *socket;
    qintptr mSocketDescriptor;

    std::optional<mpool::Crypto::SRP6> _srp6;
    SessionKey _sessionKey = {};

    std::string winCheckSumSeed = "CDCBBD5188315E6B4D19449D492DBCFAF156A347";
    std::string macCheckSumSeed = "B706D13FF2F4018839729461E3F8A0E2B5FDC034";
    std::string _os;
    std::array<uint8, 20> WindowsHash;
    std::array<uint8, 20> MacHash;
    std::string _localizationName;
    QString UserName;

    QSqlDatabase db;
};

class TcpServer : public QTcpServer {
    Q_OBJECT

public:
    TcpServer(QObject *parent = nullptr);

private slots:
    // void onNewConnection();
    void incomingConnection(qintptr socketDescriptor) override;

private:
    // QTcpServer *server;
};

#endif // NETWORK_H
