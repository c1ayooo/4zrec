package memshell

import "strings"

// ProbeInput is the host-collected response data used for memory-shell
// selection. The host performs the HTTP request; this package only classifies.
type ProbeInput struct {
	TargetURL    string
	StatusCode   int
	Server       string
	PoweredBy    string
	NotFoundBody string // body of a 404 probe, used to distinguish javax/jakarta
}

type ProbeResult struct {
	TargetURL  string   `json:"target_url"`
	StatusCode int      `json:"status_code"`
	Server     string   `json:"server,omitempty"`
	PoweredBy  string   `json:"powered_by,omitempty"`
	Family     string   `json:"family"` // tomcat | tomcat-jakarta | iis | php | unknown
	Suggest    []Kind   `json:"suggest"`
	Detail     []string `json:"detail"`
}

// Probe classifies the container/runtime and suggests memory-shell kinds.
func Probe(in ProbeInput) ProbeResult {
	res := ProbeResult{
		TargetURL: in.TargetURL, StatusCode: in.StatusCode,
		Server: truncate(in.Server, 200), PoweredBy: truncate(in.PoweredBy, 200),
		Suggest: []Kind{}, Detail: []string{},
	}
	server := strings.ToLower(res.Server)
	powered := strings.ToLower(res.PoweredBy)
	switch {
	case strings.Contains(server, "coyote") || strings.Contains(server, "tomcat") ||
		strings.Contains(server, "jetty") || strings.Contains(server, "resin"):
		res.Family = "tomcat"
	case strings.Contains(server, "microsoft-iis") || strings.Contains(powered, "asp.net"):
		res.Family = "iis"
	case strings.Contains(powered, "php"):
		res.Family = "php"
	default:
		res.Family = "unknown"
	}
	if res.Family == "tomcat" && in.NotFoundBody != "" {
		body := strings.ToLower(in.NotFoundBody)
		switch {
		case strings.Contains(body, "jakarta"):
			res.Family = "tomcat-jakarta"
			res.Detail = append(res.Detail, "404 页含 jakarta 关键字 → Tomcat 10/11")
		case strings.Contains(body, "javax"):
			res.Detail = append(res.Detail, "404 页含 javax 关键字 → Tomcat 7-9")
		default:
			res.Detail = append(res.Detail, "404 页未含命名空间关键字，默认按 Tomcat 7-9(javax) 处理")
		}
	}
	switch res.Family {
	case "tomcat":
		res.Suggest = append(res.Suggest, KindTomcatFilter, KindTomcatValve, KindTomcatServlet)
		res.Detail = append(res.Detail, "Server: "+res.Server)
	case "tomcat-jakarta":
		res.Suggest = append(res.Suggest, KindTomcatFilterJakarta)
		res.Detail = append(res.Detail, "Tomcat 10/11（jakarta 命名空间），Filter 家族唯一支持型")
	case "iis":
		res.Suggest = append(res.Suggest, KindAspxHttpModule)
		res.Detail = append(res.Detail, "IIS/ASP.NET 环境（.NET 4.5+ RegisterModule 路线）")
	case "php":
		res.Suggest = append(res.Suggest, KindPhpUserIni)
		res.Detail = append(res.Detail, "PHP 环境：.user.ini auto_prepend 准无文件持久化")
	default:
		res.Suggest = append(res.Suggest, KindTomcatFilter, KindSpringController)
		res.Detail = append(res.Detail, "指纹不足：按通用顺序建议，Spring 型需额外确认存在 DispatcherServlet")
	}
	return res
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max]
}
