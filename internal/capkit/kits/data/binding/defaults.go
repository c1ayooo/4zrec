package binding

// DefaultBindings is the built-in table. It is intentionally small: it covers
// products whose naming varies enough between fingerprint feeds and template
// libraries that a substring gate is unreliable. A host is expected to ship
// its own table; this one exists so the capability works out of the box.
var DefaultBindings = []Binding{
	{
		Product: "泛微OA",
		Aliases: []string{"泛微", "Weaver", "Weaver OA", "e-cology", "e-office", "ecology"},
		Query:   []string{"泛微", "Weaver"},
	},
	{
		Product: "通达OA",
		Aliases: []string{"通达", "Tongda OA", "Office Anywhere", "TDOA"},
		Query:   []string{"通达OA", "Office Anywhere"},
	},
	{
		Product: "致远OA",
		Aliases: []string{"致远", "Seeyon", "Seeyon OA", "A8"},
		Query:   []string{"致远OA", "Seeyon"},
	},
	{
		Product: "蓝凌OA",
		Aliases: []string{"蓝凌", "Landray", "Landray OA", "EKP"},
		Query:   []string{"蓝凌", "Landray"},
	},
	{
		Product: "用友",
		Aliases: []string{"用友软件", "Yonyou", "U8", "NC", "NC Cloud", "畅捷通"},
		Query:   []string{"用友", "Yonyou"},
	},
	{
		Product: "金蝶",
		Aliases: []string{"金蝶软件", "Kingdee", "EAS", "K3"},
		Query:   []string{"金蝶", "Kingdee"},
	},
	{
		Product: "AJ-Report",
		Aliases: []string{"AJ-Report数据大屏", "AJ-Report数据大屏系统", "AJ-Report数据可视化", "ajreport"},
		Query:   []string{"AJ-Report"},
	},
	{
		Product: "若依",
		Aliases: []string{"RuoYi", "若依管理系统", "RuoYi-Vue", "ruoyi"},
		Query:   []string{"若依", "RuoYi"},
	},
	{
		Product: "Nacos",
		Aliases: []string{"Alibaba Nacos", "Nacos Console"},
		Query:   []string{"Nacos"},
	},
	{
		Product: "Apache Struts2",
		Aliases: []string{"Struts2", "Struts", "Apache Struts"},
		Query:   []string{"Struts2", "Apache Struts"},
	},
	{
		Product: "Apache Log4j2",
		Aliases: []string{"Log4j", "Log4j2", "Apache Log4j"},
		Query:   []string{"Log4j", "Log4j2"},
	},
	{
		Product: "Spring",
		Aliases: []string{"Spring Framework", "Spring Boot", "Spring Cloud"},
		Query:   []string{"Spring", "Spring Boot"},
	},
	{
		Product: "ThinkPHP",
		Aliases: []string{"Think PHP", "ThinkPHP5", "ThinkPHP6"},
		Query:   []string{"ThinkPHP"},
	},
	{
		Product: "Shiro",
		Aliases: []string{"Apache Shiro", "Shiro RememberMe"},
		Query:   []string{"Shiro", "Apache Shiro"},
	},
	{
		Product: "Tomcat",
		Aliases: []string{"Apache Tomcat", "Tomcat Manager"},
		Query:   []string{"Tomcat", "Apache Tomcat"},
	},
	{
		Product: "Jenkins",
		Aliases: []string{"Jenkins CI", "Hudson"},
		Query:   []string{"Jenkins"},
	},
	{
		Product: "GitLab",
		Aliases: []string{"GitLab CE", "GitLab EE"},
		Query:   []string{"GitLab"},
	},
	{
		Product: "Confluence",
		Aliases: []string{"Atlassian Confluence", "Confluence Wiki"},
		Query:   []string{"Confluence"},
	},
	{
		Product: "Weblogic",
		Aliases: []string{"Oracle WebLogic", "WebLogic Server", "weblogic"},
		Query:   []string{"Weblogic", "WebLogic"},
	},
	{
		Product: "Fastjson",
		Aliases: []string{"alibaba fastjson", "Fastjson2"},
		Query:   []string{"Fastjson"},
	},
}
