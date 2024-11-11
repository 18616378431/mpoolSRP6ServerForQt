QT += core network

QT += sql

CONFIG += c++17 cmdline

INCLUDEPATH += /opt/homebrew/include
LIBS += -L/opt/homebrew/opt/openssl@3.2/lib -lssl -lcrypto

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
        BigNumber.cpp \
        CryptoRandom.cpp \
        SRP6.cpp \
        Util.cpp \
        main.cpp \
        network.cpp

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

HEADERS += \
    BigNumber.h \
    CryptoHash.h \
    CryptoRandom.h \
    Defines.h \
    SRP6.h \
    Util.h \
    network.h \
    types.h
