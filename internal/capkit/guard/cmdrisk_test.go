package guard

import "testing"

func TestHitForbiddenPattern(t *testing.T) {
	// 每条规则至少一个真实形态命中。
	hits := map[string]string{
		"docker exec": `docker exec -it app cat /app/main.go`,
		"docker run":  `docker run --rm -v /:/host busybox ls /host`,
		"docker cp":   `docker cp app:/app/main.go .`,
		"nsenter":     `nsenter -t 1234 -n curl http://10.0.0.5/`,
		"host-proc":   `cat /proc/1234/root/etc/passwd`,
		"mount-bind":  `mount --bind /host /mnt`,
	}
	for name, cmd := range hits {
		if HitForbiddenPattern(cmd) == nil {
			t.Errorf("%s: %q 应命中黑名单", name, cmd)
		}
	}
	clean := []string{
		`curl http://target.example.com/`,
		`nmap -p 80 192.168.1.10`,
		`docker --version`,      // --version 不在 (exec|run|cp) 内，不误拦
		`cat /proc/self/status`, // 非 <pid>/root 形态
	}
	for _, cmd := range clean {
		if p := HitForbiddenPattern(cmd); p != nil {
			t.Errorf("%q 不应命中（命中了 %s）", cmd, p.Name)
		}
	}
}
