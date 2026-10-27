package guard

// 命令形态黑名单：与目标围栏并列的第二道判定——不看命令连到哪里，只看
// 命令做什么。目标围栏提取的是「网络对象」，而 docker exec / nsenter /
// 读宿主 /proc 这类命令的目标不是 IP/域名，围栏天然提取不到；但它们的
// 风险形态是明确的（进入别的命名空间、触碰宿主文件系统）。命中即交人工
// 裁决（ask），不是硬拒绝——现场确实有需要进容器的合法场景，人批了就放行。
//
// 已知边界（必须如实宣传）：这是正则形态匹配，`sh -c "$(echo docker) exec"`
// 这类组装形态能绕。它的价值是抬高误操作的成本、留下审批记录——「顺手就
// docker inspect 看看」正是最常见的事故起点——不是防住有意的绕过。围栏
// 不是安全边界，文档与审批文案都应这么写。

import "regexp"

// ForbiddenPattern 是一条命令形态黑名单规则。
type ForbiddenPattern struct {
	Name string         // 规则名（审批记录/事件里用）
	Re   *regexp.Regexp // 形态匹配
	Why  string         // 给模型和操作者看的理由
}

// ForbiddenPatterns 是内置黑名单。命中任意一条即应交人工裁决。
var ForbiddenPatterns = []ForbiddenPattern{
	{"docker-exec", regexp.MustCompile(`\bdocker\s+(exec|run|cp)\b`), "进入宿主容器命名空间"},
	{"nsenter", regexp.MustCompile(`\bnsenter\b`), "进入其他命名空间"},
	{"host-proc", regexp.MustCompile(`/proc/\d+/root`), "读取宿主进程根目录"},
	{"mount-bind", regexp.MustCompile(`\bmount\b.*\bbind\b`), "挂载宿主目录"},
}

// HitForbiddenPattern 报告命令文本命中的第一条黑名单规则；未命中返回 nil。
// 只做文本形态判定，无 IO；宿主在 ask 文案里带上 Name 与 Why。
func HitForbiddenPattern(cmd string) *ForbiddenPattern {
	for i := range ForbiddenPatterns {
		if ForbiddenPatterns[i].Re.MatchString(cmd) {
			return &ForbiddenPatterns[i]
		}
	}
	return nil
}
