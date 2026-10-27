package memshell

import "testing"

func TestProbeFamilies(t *testing.T) {
	cases := []struct {
		name string
		in   ProbeInput
		want string
	}{
		{"tomcat", ProbeInput{Server: "Apache-Coyote/1.1"}, "tomcat"},
		{"tomcat-jakarta", ProbeInput{Server: "Apache Tomcat/10.1", NotFoundBody: "jakarta.servlet"}, "tomcat-jakarta"},
		{"iis", ProbeInput{Server: "Microsoft-IIS/10.0", PoweredBy: "ASP.NET"}, "iis"},
		{"php", ProbeInput{PoweredBy: "PHP/8.2"}, "php"},
		{"unknown", ProbeInput{}, "unknown"},
	}
	for _, c := range cases {
		got := Probe(c.in)
		if got.Family != c.want {
			t.Errorf("%s: family = %q want %q", c.name, got.Family, c.want)
		}
		if len(got.Suggest) == 0 {
			t.Errorf("%s: no suggestions", c.name)
		}
	}
}

func TestProbeJakartaSuggest(t *testing.T) {
	got := Probe(ProbeInput{Server: "Apache Tomcat/11.0", NotFoundBody: "jakarta.servlet"})
	if len(got.Suggest) != 1 || got.Suggest[0] != KindTomcatFilterJakarta {
		t.Fatalf("suggest = %+v", got.Suggest)
	}
}
