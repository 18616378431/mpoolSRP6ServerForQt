# mpoolSRP6ServerForQt
SRP6 服务端Qt实现

简介:
该c++服务端实现了SRP6服务端算法,mysql驱动配置参考[Qt6 mysql驱动安装](https://github.com/18616378431/MysqlDriverForQt6)

一、依赖

`brew install openssl@3 mysql-client@8.0`


二、Qt配置

```c++
项目配置文件(projects.pro)修改依赖openssl路径

INCLUDEPATH += /opt/homebrew/include
LIBS += -L/opt/homebrew/opt/openssl@3.2/lib -lssl -lcrypto

添加数据库驱动

QT += sql
```

### 相关项目

项目  |  名称  |  地址
----  ----  ----
mpool | SRP6服务端 | [mpool](https://github.com/18616378431/mpool) Qt6实现的服务端[mpoolSRP6ServerForQt](https://github.com/18616378431/mpoolSRP6ServerForQt)

SRP6ClientForQt6 | SRP6客户端 | [SRP6ClientForQt6](https://github.com/18616378431/SRP6ClientForQt6)

SRP6Register | SRP6注册 ｜  [SRP6Register](https://github.com/18616378431/SRP6Register)



