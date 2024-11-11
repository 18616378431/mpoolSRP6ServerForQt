#include "network.h"
#include "types.h"
#include "Util.h"

#include <QCoreApplication>
#include <iostream>
#include <QSqlDatabase>
#include <QSqlQuery>

ClientHandler::ClientHandler(QTcpSocket *socket, QObject *parent)
    : QObject(parent)
    , socket(socket)
{
    connect(socket, &QTcpSocket::readyRead, this, &ClientHandler::onReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &ClientHandler::onDisconnected);
}

QSqlDatabase ClientHandler::getDb()
{
    auto db = QSqlDatabase::addDatabase("QMYSQL");
    db.setHostName("127.0.0.1");
    db.setPort(3506);
    db.setDatabaseName("mpool");
    db.setUserName("root");
    db.setPassword("123456");

    if (!db.open()) {
        qDebug() << "mysql connection fail!";
    } else {
        qDebug() << "connect to the db!";
    }

    return db;
}

void ClientHandler::onReadyRead()
{
    QByteArray inComingData = socket->readAll();
    qDebug() << "received data:" << inComingData;

    QByteArray send_data;
    QDataStream out(&send_data, QIODevice::WriteOnly);

    if (inComingData.size() < 2) {
        qDebug() << "error packet size:" << inComingData.size();
        return;
    }

    uint8 cmd = inComingData.at(0);

    switch (cmd) {
    case AUTH_LOGON_CHALLENGE: //first packet
    {
        sAuthLogonChallenge_C *challenge = reinterpret_cast<sAuthLogonChallenge_C *>(inComingData.data());

        if (challenge->size - (sizeof(sAuthLogonChallenge_C) - AUTH_LOGON_CHALLENGE_INITIAL_SIZE - 1) != challenge->I_len) {
            qDebug() << "数据包大小有误";
            return;
        }

        std::string login((char const*)challenge->I, challenge->I_len);
        QString login1 = QString::fromStdString(login);

        qDebug() << "username:" << login;

        std::array<char, 5> os;
        os.fill('\0');
        memcpy(os.data(), challenge->os, sizeof(challenge->os));
        _os = os.data();
        std::reverse(_os.begin(), _os.end());

        _localizationName.resize(4);
        for (int i = 0; i < 4; ++i)
            _localizationName[i] = challenge->country[4 - i - 1];

        uint32 id;
        // UserName;
        QString last_ip;
        QByteArray salt;
        QByteArray verifier;

        //databse query
        if (!db.isOpen()) {
            db = getDb();
        }

        QSqlQuery query;
        QString sql = QString("SELECT id, username, last_ip, salt, verifier FROM account WHERE username = '%1' limit 1").arg(login1);

        qDebug() << "sql:" << sql;


        sAuthLogonChallenge_S first_feedback;

        first_feedback.cmd = uint8(AUTH_LOGON_CHALLENGE);
        first_feedback.unk2 = uint8(0x00);

        if (!query.exec(sql)) {
            qDebug() << "sel error:" << sql;
            return;
        } else {
            //no record
            if (query.size() <= 0) {
                first_feedback.error = uint8(WOW_FAIL_UNKNOWN_ACCOUNT);

                out.writeRawData((const char *) &first_feedback, 3);

                std::cout << "account no record:" << login << "\n";

                return;
            }
        }

        while (query.next()) {
            id = query.value("id").toInt();
            UserName = query.value("username").toString();
            last_ip = query.value("last_ip").toString();
            salt = query.value("salt").toByteArray();
            verifier = query.value("verifier").toByteArray();

            qDebug() << "id:" << id;
            qDebug() << "accountName:" << UserName;
            qDebug() << "last_ip:" << last_ip;
            qDebug() << "salt:" << salt << ",size:" << salt.length();
            qDebug() << "verifier:" << verifier << ",size:" << verifier.length();
        }

        //SRP6
        mpool::Crypto::SRP6::Salt arr_salt;
        std::memcpy(arr_salt.data(), salt.data(), 32);

        mpool::Crypto::SRP6::Verifier arr_verifier;
        std::memcpy(arr_verifier.data(), verifier.data(), 32);

        _srp6.emplace(UserName.toStdString(), arr_salt, arr_verifier);

        //success
        first_feedback.error = uint8(WOW_SUCCESS);

        std::memcpy((char *)first_feedback.B, (char *)_srp6->B.data(), 32);

        first_feedback.g_len = uint8(1);
        std::strncpy((char *)first_feedback.g, (char *)_srp6->g.data(), 1);

        first_feedback.N_len = uint8(32);
        std::strncpy((char *)first_feedback.N, (char *)_srp6->N.data(), 32);

        std::strncpy((char *)first_feedback.s, (char *)_srp6->s.data(), 32);

        std::array<uint8, 16> VersionChallenge = { { 0xBA, 0xA3, 0x1E, 0x99, 0xA0, 0x0B, 0x21, 0x57, 0xFC, 0x37, 0x3F, 0xB3, 0x69, 0xCD, 0xD2, 0xF1 } };
        std::strncpy((char *)first_feedback.unk3, (char *)VersionChallenge.data(), VersionChallenge.size());

        uint8 securityFlags = 0;
        first_feedback.N_len = uint8(securityFlags);

        out.writeRawData((const char *)&first_feedback, sizeof(sAuthLogonChallenge_S));
    }
    break;
    case AUTH_LOGON_PROOF:
    {
        qDebug() << "AUTH_LOGON_PROOF";
        sAuthLogonProof_C *logonProof = reinterpret_cast<sAuthLogonProof_C *>(inComingData.data());
        qDebug() << "logonProof.cmd:" << logonProof->cmd;

        //second feedback
        sAuthLogonProof_S proofS;

        using EphemeralKey = std::array<uint8, 32>;

        EphemeralKey A;
        memcpy(A.data(), logonProof->A, 32);

        std::array<uint8, 20> M1;
        memcpy(M1.data(), logonProof->M1, 20);

        if (Optional<SessionKey> K = _srp6->VerifyChallengeResponse(A, M1))
        {
            std::cout << "K success" << std::endl;
            _sessionKey = *K;

            //bn中的hex字符串为逆序,服务端为正确顺序,客户端调用的toHex为bn中的逆序
            printHex((const unsigned char *)_sessionKey.data(), 40);

            std::array<uint8, 20> crc_hash;
            memcpy(crc_hash.data(), logonProof->crc_hash, 20);

            if (!VerifyVersion(logonProof->A, 32, crc_hash, false))
            {
                proofS.cmd = uint8(AUTH_LOGON_PROOF);
                proofS.error = uint8(WOW_FAIL_VERSION_INVALID);

                out.writeRawData((const char *)&proofS, 2);

                std::cout << "VerifyVersion check fail\n";

                return ;
            }

            std::cout << "update login info\n";

            //databse query
            if (!db.isOpen()) {
                db = getDb();
            }

            QSqlQuery query;

            //params
            std::string session_key_std((char const*)_sessionKey.data(), 40);
            QString address = GetRemoteIpAddress();

            QString sql = QString("UPDATE account SET session_key = :session_key, last_ip = :last_ip, last_login = NOW(), locale = :locale, os = :os WHERE username = :username");

            qDebug() << "sql:" << sql;

            sAuthLogonChallenge_S first_feedback;

            first_feedback.cmd = uint8(AUTH_LOGON_CHALLENGE);
            first_feedback.unk2 = uint8(0x00);

            query.prepare(sql);
            query.bindValue(":session_key", QByteArray::fromRawData(session_key_std.c_str(), 40), QSql::Binary); // yourData是指向数据的指针，dataSize是数据大小
            query.bindValue(":last_ip", address.remove(0, 7));
            query.bindValue(":locale", QString::fromStdString(_localizationName));
            query.bindValue(":os", QString::fromStdString(_os));
            query.bindValue(":username", UserName);

            if (!query.exec()) {
                qDebug() << "sel error:" << sql;
                return;
            } else {
                //no record
                if (query.numRowsAffected() == 0) {
                    first_feedback.error = uint8(WOW_FAIL_UNKNOWN_ACCOUNT);

                    out.writeRawData((const char *) &first_feedback, 3);

                    qDebug() << "account no record:" << UserName << "\n";

                    return;
                }
            }

            //generic M2
            mpool::Crypto::SHA1::Digest M2 = mpool::Crypto::SRP6::GetSessionVerifier(A, M1, _sessionKey);

            proofS.cmd = uint8(AUTH_LOGON_PROOF);
            proofS.error = uint8(0);
            std::memcpy(proofS.M2, M2.data(), 20);
            proofS.accountFlags = 0x00800000;
            proofS.surveyId = 0;
            proofS.unkFlags = 0;

            out.writeRawData((const char *)&proofS, sizeof(proofS));
        }
        else
        {
            proofS.cmd = uint8(AUTH_LOGON_PROOF);
            proofS.error = uint8(WOW_FAIL_UNKNOWN_ACCOUNT);

            out.writeRawData((const char *)&proofS, 2);

            return ;
        }
    } break;
    default:
        break;
    }

    quint64 send_bytes = socket->write(send_data);

    qDebug() << "send_bytes:" << send_bytes;
}

void ClientHandler::onDisconnected()
{
    qDebug() << "Client disconnected";
    qDebug() << "ClientHandler thread:" << QThread::currentThreadId();
    socket->deleteLater();
    deleteLater();
}

bool ClientHandler::VerifyVersion(uint8 const* a, int32 aLength, mpool::Crypto::SHA1::Digest const& versionProof, bool isReconnect)
{
    qDebug() << "VerifyVersion";

    mpool::Crypto::SHA1::Digest zeros{};
    mpool::Crypto::SHA1::Digest const* versionHash{ nullptr };

    if (!isReconnect)
    {
        if (_os == "Win")
        {
            HexStrToByteArray(winCheckSumSeed, WindowsHash);
            versionHash = &WindowsHash;
        }
        else if (_os == "OSX")
        {
            HexStrToByteArray(macCheckSumSeed, MacHash);
            versionHash = &MacHash;
        }

        if (zeros == *versionHash)
            return true;                                                            // not filled serverside
    }
    else
        versionHash = &zeros;

    mpool::Crypto::SHA1 version;
    version.UpdateData(a, aLength);
    version.UpdateData(*versionHash);
    version.Finalize();

    qDebug() << "VerifyVersion result:" << (versionProof == version.GetDigest());

    return (versionProof == version.GetDigest());
}

QString ClientHandler::GetRemoteIpAddress() const
{
    return socket->peerAddress().toString();
}

TcpServer::TcpServer(QObject *parent)
    : QObject(parent)
    , server(new QTcpServer(this))
{
    connect(server, &QTcpServer::newConnection, this, &TcpServer::onNewConnection);

    if (!server->listen(QHostAddress::Any, 1234)) {
        qDebug() << "network server listen fail!"
                 << ",error reason:" << server->errorString();
        return;
    } else {
        qDebug() << "Server started!====";
    }
}

void TcpServer::onNewConnection()
{
    QTcpSocket *socket = server->nextPendingConnection();

    // QThread *thread = new QThread();

    qDebug() << "new conn" << QThread::currentThreadId();

    ClientHandler *handler = new ClientHandler(socket, this);
    // handler->moveToThread(thread);

    // connect(thread, &QThread::finished, handler, &QObject::deleteLater);

    // thread->start();
}
