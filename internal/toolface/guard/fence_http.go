// fence_http.go 结构化 HTTP 工具(http_probe)的围栏对象提取。
//
// http_probe 的输入是 JSON 而不是 shell 命令：把整段 JSON 当命令文本喂给
// 命令解析器会把 proxy 地址、headers 里的 Host/Referer、body/extract 里的
// URL、save_to_file 路径全部误提取成测试目标。这里按字段语义取对象——
// 只有真正发起请求的 URL(url / requests[].url / template.url × matrix/range)
// 是围栏对象，其余字段一律不参与提取。
package guard

import (
	"encoding/json"
	"fmt"
	"strings"
)

// httpProbeFenceInput 只声明围栏关心的字段；未声明的字段（headers/body/
// proxy/extract/...）天然不可能被提取。
type httpProbeFenceInput struct {
	URL      string               `json:"url"`
	Requests []httpProbeFenceSpec `json:"requests"`
	Template *httpProbeFenceSpec  `json:"template"`
	Matrix   []map[string]string  `json:"matrix"`
	Range    *httpProbeFenceRange `json:"range"`
}

type httpProbeFenceSpec struct {
	URL string `json:"url"`
}

type httpProbeFenceRange struct {
	Var  string `json:"var"`
	From int    `json:"from"`
	To   int    `json:"to"`
	Step int    `json:"step"`
}

// probeTemplateURLOffset 与工具自身的展开上限一致(expandProbeSpecs 上限 50)。
const probeTemplateURLOffset = 50

// extractHTTPProbeTargets 从 http_probe 的工具输入提取围栏目标。
//   - url / requests[].url 直取 host;
//   - template.url 先用 matrix/range 行代入 {var}(与工具同语义),再取 host;
//   - 代入后 host 位置仍有 {var}(如 extract 串行链变量)→ Opaque:目标运行时
//     才确定,围栏必须走审批,不能因为「静态读不到」放行;
//   - proxy/headers/body/cookie/extract/save_to_file 不产生目标。
func extractHTTPProbeTargets(input []byte) fenceTargets {
	var in httpProbeFenceInput
	if err := json.Unmarshal(input, &in); err != nil {
		// 非法 JSON 由工具自身报错;围栏把它当「无对象」而不是 Opaque。
		return fenceTargets{}
	}
	c := newFenceCollector(nil)
	var urls []string
	if u := strings.TrimSpace(in.URL); u != "" {
		urls = append(urls, u)
	}
	for _, sp := range in.Requests {
		if u := strings.TrimSpace(sp.URL); u != "" {
			urls = append(urls, u)
		}
	}
	if in.Template != nil && strings.TrimSpace(in.Template.URL) != "" {
		urls = append(urls, expandProbeTemplateURLs(in.Template.URL, in.Matrix, in.Range)...)
	}
	opaque := false
	reason := ""
	for _, u := range urls {
		if strings.Contains(u, "{") && strings.Contains(u, "}") {
			// 未解析的 {var}(串行链 extract 回填)落在 host 位时目标不可知。
			if host := probeURLHost(u); host == "" || strings.ContainsAny(host, "{}") {
				opaque = true
				if reason == "" {
					reason = fmt.Sprintf("URL %q 含运行时回填的变量，无法静态确定目标", u)
				}
				continue
			}
		}
		c.addHost(u)
	}
	out := c.result()
	if opaque {
		out.Opaque = true
		if out.Reason == "" {
			out.Reason = reason
		}
	}
	return out
}

// expandProbeTemplateURLs 把 template.url 按 matrix/range 行代入,返回逐行
// 展开后的 URL 清单(与 expandProbeSpecs/substituteSpec 同语义;超出工具
// 自身上限的部分不展开——那里的请求工具自身也会拒绝)。
func expandProbeTemplateURLs(tmpl string, matrix []map[string]string, rng *httpProbeFenceRange) []string {
	var rows []map[string]string
	if rng != nil && rng.Var != "" {
		step := rng.Step
		if step <= 0 {
			step = 1
		}
		for v := rng.From; v <= rng.To && len(rows) < probeTemplateURLOffset; v += step {
			rows = append(rows, map[string]string{rng.Var: fmt.Sprintf("%d", v)})
		}
	} else {
		rows = matrix
	}
	if len(rows) == 0 {
		return []string{tmpl} // 无变量行:模板即最终 URL(可能不含 {var})
	}
	if len(rows) > probeTemplateURLOffset {
		rows = rows[:probeTemplateURLOffset]
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		s := tmpl
		for k, v := range row {
			s = strings.ReplaceAll(s, "{"+k+"}", v)
		}
		out = append(out, s)
	}
	return out
}

// probeURLHost 取 URL 的 host 位(供未解析变量判定);与 fenceCollector.addHost
// 的归一化不同,这里要保留原始形态才能看出 {var} 是否落在 host 上。
func probeURLHost(u string) string {
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	} else if strings.HasPrefix(rest, "//") {
		rest = rest[2:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	return rest
}
