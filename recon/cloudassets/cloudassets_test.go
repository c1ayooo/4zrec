package cloudassets

import "testing"

func TestExtractCNAME(t *testing.T) {
	cases := []struct {
		cname    string
		provider string
		kind     string
		name     string
		wantHit  bool
	}{
		// AWS S3 bucket（虚拟主机风格）
		{"assets.s3.amazonaws.com", "aws", "bucket", "assets", true},
		{"my-bucket.s3.us-east-1.amazonaws.com", "aws", "bucket", "my-bucket", true},
		{"static.s3-website-us-east-1.amazonaws.com", "aws", "bucket", "static", true},
		{"www.s3-website.ap-southeast-1.amazonaws.com", "aws", "bucket", "www", true},
		{"upload.s3-accelerate.amazonaws.com", "aws", "bucket", "upload", true},
		{"upload.s3-accelerate.dualstack.amazonaws.com", "aws", "bucket", "upload", true},
		{"media.s3.dualstack.us-west-2.amazonaws.com", "aws", "bucket", "media", true},
		// AWS CloudFront 分发
		{"d111111abcdef8.cloudfront.net", "aws", "distribution", "d111111abcdef8", true},
		// Azure 存储账号
		{"account1.blob.core.windows.net", "azure", "storage_account", "account1", true},
		{"account2.blob.storage.azure.net", "azure", "storage_account", "account2", true},
		{"tables.table.core.windows.net", "azure", "storage_account", "tables", true},
		{"queues.queue.storage.azure.net", "azure", "storage_account", "queues", true},
		{"files.file.core.windows.net", "azure", "storage_account", "files", true},
		// 阿里云 OSS
		{"img.oss-cn-hangzhou.aliyuncs.com", "alicloud", "bucket", "img", true},
		{"img.oss-accelerate.aliyuncs.com", "alicloud", "bucket", "img", true},
		{"img.oss-cn-hangzhou-internal.aliyuncs.com", "alicloud", "bucket", "img", true},
		{"file.oss-us-west-1.aliyuncs.com", "alicloud", "bucket", "file", true},
		// 腾讯云 COS
		{"data.cos.ap-shanghai.myqcloud.com", "tencent", "bucket", "data", true},
		{"data.cos-internal.ap-guangzhou.myqcloud.com", "tencent", "bucket", "data", true},
		{"data.cos.accelerate.myqcloud.com", "tencent", "bucket", "data", true},
		// 华为云 OBS
		{"backup.obs.cn-north-4.myhuaweicloud.com", "huawei", "bucket", "backup", true},
		{"site.obs-website.cn-north-4.myhuaweicloud.com", "huawei", "bucket", "site", true},
		// Google GCS
		{"gcs-bucket.storage.googleapis.com", "google", "bucket", "gcs-bucket", true},
		{"gcs-bucket.storage-download.googleapis.com", "google", "bucket", "gcs-bucket", true},
		// 大小写与尾部点容忍
		{"Assets.S3.AMAZONAWS.COM.", "aws", "bucket", "assets", true},

		// 反向：普通/非云 CNAME 一律不命中
		{"www.example.com", "", "", "", false},
		{"cdn.cloudflare.net", "", "", "", false},
		{"api.aliyuncs.com", "", "", "", false},
		{"ecs.aliyuncs.com", "", "", "", false}, // 无前缀的 aliyuncs API 端点
		{"vpc.myqcloud.com", "", "", "", false}, // 非 cos 前缀
		{"obs.myhuaweicloud.com", "", "", "", false},
		{"cloud.google.com", "", "", "", false},
		{"", "", "", "", false},
		{"amazonaws.com", "", "", "", false}, // 无 bucket 前缀
	}
	for _, c := range cases {
		res, hit := ExtractCNAME(c.cname)
		if hit != c.wantHit {
			t.Errorf("ExtractCNAME(%q) hit = %v, want %v", c.cname, hit, c.wantHit)
			continue
		}
		if !hit {
			continue
		}
		if res.Provider != c.provider || res.Kind != c.kind || res.Name != c.name {
			t.Errorf("ExtractCNAME(%q) = {%s,%s,%s}, want {%s,%s,%s}",
				c.cname, res.Provider, res.Kind, res.Name, c.provider, c.kind, c.name)
		}
	}
}
