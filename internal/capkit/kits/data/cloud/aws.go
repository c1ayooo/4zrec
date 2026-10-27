package cloud

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// awsProvider talks to AWS through aws-sdk-go-v2. Signing (SigV4) is entirely
// the SDK's: this file wires a static credential provider and the injected HTTP
// client, then maps responses.
type awsProvider struct{ h *httpDoerClient }

func newAWSProvider(h *httpDoerClient) Provider { return &awsProvider{h: h} }

func (p *awsProvider) Name() string { return ProviderAWS }

// defaultAWSRegion is used when the caller gave no region: STS and IAM are
// global, so a verification does not need one.
const defaultAWSRegion = "us-east-1"

// awsConfig builds the SDK config from the caller's credential only. It
// deliberately does not use config.LoadDefaultConfig: that would also read
// environment variables and shared config files, and a cloud tool must never
// pick up ambient credentials the caller did not pass (the brief: 凭据只从调用方
// 传入).
func (p *awsProvider) awsConfig(creds Credentials) (awssdk.Config, *Error) {
	ak := strings.TrimSpace(creds.AccessKey)
	sk := strings.TrimSpace(creds.SecretKey)
	if ak == "" || sk == "" {
		return awssdk.Config{}, newError(ReasonInvalidCredential, ProviderAWS, "MissingCredential",
			"access_key/secret_key 必填", maskAK(ak))
	}
	region := strings.TrimSpace(creds.Region)
	if region == "" {
		region = defaultAWSRegion
	}
	cfg := awssdk.Config{
		Region: region,
		Credentials: awssdk.NewCredentialsCache(
			credentials.NewStaticCredentialsProvider(ak, sk, "")),
		HTTPClient: p.h.client(),
		// One attempt: the host's limiter and audit already wrap the port, and a
		// silent SDK retry would multiply the requests Meta.Requests reports.
		RetryMaxAttempts: 1,
	}
	if ep := strings.TrimSpace(creds.Endpoint); ep != "" {
		cfg.BaseEndpoint = awssdk.String(ep)
	}
	return cfg, nil
}

func (p *awsProvider) Verify(ctx context.Context, creds Credentials) (Identity, error) {
	cfg, cerr := p.awsConfig(creds)
	if cerr != nil {
		return Identity{}, cerr
	}
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, awsError(err)
	}
	arn := awssdk.ToString(out.Arn)
	return Identity{
		AccountID: awssdk.ToString(out.Account),
		ARN:       arn,
		Type:      awsIdentityType(arn),
		Alias:     awssdk.ToString(out.UserId),
	}, nil
}

// awsIdentityType reads the principal kind out of the ARN, so the agent can tell
// a root account key from a scoped IAM user.
func awsIdentityType(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return ""
	}
	resource := parts[5]
	switch {
	case resource == "root":
		return "root_account"
	case strings.HasPrefix(resource, "user/"):
		return "iam_user"
	case strings.HasPrefix(resource, "assumed-role/"):
		return "assumed_role"
	case strings.HasPrefix(resource, "federated-user/"):
		return "federated_user"
	case strings.HasPrefix(resource, "role/"):
		return "iam_role"
	default:
		return resource
	}
}

func (p *awsProvider) ListAssets(ctx context.Context, creds Credentials, req AssetRequest) (AssetPage, error) {
	cfg, cerr := p.awsConfig(creds)
	if cerr != nil {
		return AssetPage{}, cerr
	}
	var out AssetPage
	for _, kind := range req.Kinds {
		switch kind {
		case AssetCompute:
			instances, next, err := p.ec2Instances(ctx, cfg, req)
			if err != nil {
				out.Warnings = append(out.Warnings, "EC2 列举失败："+reasonLabel(err))
				continue
			}
			out.Instances = append(out.Instances, instances...)
			if next != "" {
				out.Cursor, out.HasMore = next, true
			}
		case AssetDatabase:
			instances, marker, err := p.rdsInstances(ctx, cfg, req)
			if err != nil {
				out.Warnings = append(out.Warnings, "RDS 列举失败："+reasonLabel(err))
				continue
			}
			out.Instances = append(out.Instances, instances...)
			if marker != "" {
				out.Cursor, out.HasMore = marker, true
			}
		default:
			out.Warnings = append(out.Warnings, "跳过不支持的资产类型："+kind)
		}
	}
	if len(out.Instances) == 0 && len(out.Warnings) > 0 && len(out.Warnings) == len(req.Kinds) {
		return out, newError(ReasonUpstream, ProviderAWS, "assets", strings.Join(out.Warnings, "；"), "")
	}
	out.Total = len(out.Instances)
	return out, nil
}

func (p *awsProvider) ec2Instances(ctx context.Context, cfg awssdk.Config, req AssetRequest) ([]Instance, string, error) {
	in := &ec2.DescribeInstancesInput{}
	if req.PageSize > 0 {
		// EC2 rejects MaxResults below 5.
		size := int32(req.PageSize)
		if size < 5 {
			size = 5
		}
		in.MaxResults = awssdk.Int32(size)
	}
	if req.Cursor != "" {
		in.NextToken = awssdk.String(req.Cursor)
	}
	out, err := ec2.NewFromConfig(cfg).DescribeInstances(ctx, in)
	if err != nil {
		return nil, "", awsError(err)
	}
	var instances []Instance
	for _, reservation := range out.Reservations {
		for _, inst := range reservation.Instances {
			instances = append(instances, Instance{
				ID:        awssdk.ToString(inst.InstanceId),
				Name:      tagValue(inst.Tags, "Name"),
				Kind:      AssetCompute,
				Status:    string(inst.State.Name),
				Type:      string(inst.InstanceType),
				Region:    cfg.Region,
				Zone:      awssdk.ToString(inst.Placement.AvailabilityZone),
				PrivateIP: nonEmpty(awssdk.ToString(inst.PrivateIpAddress)),
				PublicIP:  nonEmpty(awssdk.ToString(inst.PublicIpAddress)),
			})
		}
	}
	return instances, awssdk.ToString(out.NextToken), nil
}

func (p *awsProvider) rdsInstances(ctx context.Context, cfg awssdk.Config, req AssetRequest) ([]Instance, string, error) {
	in := &rds.DescribeDBInstancesInput{}
	if req.PageSize > 0 {
		size := int32(req.PageSize)
		if size < 20 {
			size = 20
		}
		in.MaxRecords = awssdk.Int32(size)
	}
	if req.Cursor != "" {
		in.Marker = awssdk.String(req.Cursor)
	}
	out, err := rds.NewFromConfig(cfg).DescribeDBInstances(ctx, in)
	if err != nil {
		return nil, "", awsError(err)
	}
	var instances []Instance
	for _, db := range out.DBInstances {
		inst := Instance{
			ID:     awssdk.ToString(db.DBInstanceIdentifier),
			Kind:   AssetDatabase,
			Status: awssdk.ToString(db.DBInstanceStatus),
			Type:   awssdk.ToString(db.DBInstanceClass),
			Region: cfg.Region,
			Zone:   awssdk.ToString(db.AvailabilityZone),
		}
		switch {
		case db.Engine != nil:
			inst.Engine = awssdk.ToString(db.Engine)
			if db.EngineVersion != nil {
				inst.Engine += " " + awssdk.ToString(db.EngineVersion)
			}
		}
		if db.Endpoint != nil {
			inst.PrivateIP = nonEmpty(awssdk.ToString(db.Endpoint.Address))
		}
		instances = append(instances, inst)
	}
	return instances, awssdk.ToString(out.Marker), nil
}

// maxAdminProbe bounds how many users get the attached-policy lookups that
// produce the admin hint: the surface is worth exposing, a per-user call storm
// is not.
const maxAdminProbe = 20

func (p *awsProvider) ListIAM(ctx context.Context, creds Credentials, req IAMRequest) (IAMPage, error) {
	cfg, cerr := p.awsConfig(creds)
	if cerr != nil {
		return IAMPage{}, cerr
	}
	client := iam.NewFromConfig(cfg)
	var page IAMPage
	for _, include := range req.Include {
		switch include {
		case "users":
			out, err := client.ListUsers(ctx, &iam.ListUsersInput{MaxItems: awssdk.Int32(int32(clampMax(req.MaxResults)))})
			if err != nil {
				page.Warnings = append(page.Warnings, "子用户列举失败："+reasonLabel(awsError(err)))
				continue
			}
			for _, u := range out.Users {
				page.Users = append(page.Users, IAMUser{
					Name:      awssdk.ToString(u.UserName),
					ID:        awssdk.ToString(u.UserId),
					CreatedAt: timeString(u.CreateDate),
				})
			}
			page.Cursor, page.HasMore = awssdk.ToString(out.Marker), out.IsTruncated
		case "policies":
			out, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{
				Scope:    iamtypes.PolicyScopeTypeLocal,
				MaxItems: awssdk.Int32(int32(clampMax(req.MaxResults))),
			})
			if err != nil {
				page.Warnings = append(page.Warnings, "策略列举失败："+reasonLabel(awsError(err)))
				continue
			}
			for _, pol := range out.Policies {
				page.Policies = append(page.Policies, IAMPolicy{
					Name:        awssdk.ToString(pol.PolicyName),
					ID:          awssdk.ToString(pol.PolicyId),
					Description: strings.TrimSpace(awssdk.ToString(pol.Description)),
					Attachments: int(awssdk.ToInt32(pol.AttachmentCount)),
					Admin:       adminish(awssdk.ToString(pol.PolicyName)),
				})
			}
		case "access_keys":
			out, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
				MaxItems: awssdk.Int32(int32(clampMax(req.MaxResults))),
			})
			if err != nil {
				page.Warnings = append(page.Warnings, "AccessKey 列举失败："+reasonLabel(awsError(err)))
				continue
			}
			for _, key := range out.AccessKeyMetadata {
				page.AccessKeys = append(page.AccessKeys, AccessKey{
					User:      awssdk.ToString(key.UserName),
					ID:        awssdk.ToString(key.AccessKeyId),
					Status:    string(key.Status),
					CreatedAt: timeString(key.CreateDate),
				})
			}
		default:
			page.Warnings = append(page.Warnings, "跳过不支持的 IAM 类别："+include)
		}
	}
	// Mark users whose directly attached policy looks administrative. Bounded by
	// maxAdminProbe so a large account does not turn one tool call into hundreds.
	for i := range page.Users {
		if i >= maxAdminProbe {
			break
		}
		attached, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: awssdk.String(page.Users[i].Name),
		})
		if err != nil {
			continue
		}
		for _, pol := range attached.AttachedPolicies {
			if adminish(awssdk.ToString(pol.PolicyName)) || adminish(awssdk.ToString(pol.PolicyArn)) {
				page.Users[i].AdminHint = awssdk.ToString(pol.PolicyName)
				break
			}
		}
	}
	page.Total = len(page.Users) + len(page.Policies) + len(page.AccessKeys)
	if page.Total == 0 && len(page.Warnings) > 0 && len(page.Warnings) == len(req.Include) {
		return page, newError(ReasonUpstream, ProviderAWS, "iam", strings.Join(page.Warnings, "；"), "")
	}
	return page, nil
}

func (p *awsProvider) ListStorage(ctx context.Context, creds Credentials, req StorageRequest) (StoragePage, error) {
	cfg, cerr := p.awsConfig(creds)
	if cerr != nil {
		return StoragePage{}, cerr
	}
	client := s3.NewFromConfig(cfg)
	if strings.TrimSpace(req.Bucket) == "" {
		out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return StoragePage{}, awsError(err)
		}
		var page StoragePage
		for _, b := range out.Buckets {
			page.Buckets = append(page.Buckets, Bucket{
				Name:      awssdk.ToString(b.Name),
				CreatedAt: timeString(b.CreationDate),
			})
		}
		sort.Slice(page.Buckets, func(i, j int) bool { return page.Buckets[i].Name < page.Buckets[j].Name })
		page.Total = len(page.Buckets)
		return page, nil
	}
	in := &s3.ListObjectsV2Input{Bucket: awssdk.String(strings.TrimSpace(req.Bucket))}
	if req.Prefix != "" {
		in.Prefix = awssdk.String(req.Prefix)
	}
	if req.MaxResults > 0 {
		in.MaxKeys = awssdk.Int32(int32(clampMax(req.MaxResults)))
	}
	if req.Cursor != "" {
		in.ContinuationToken = awssdk.String(req.Cursor)
	}
	out, err := client.ListObjectsV2(ctx, in)
	if err != nil {
		return StoragePage{}, awsError(err)
	}
	var page StoragePage
	for _, obj := range out.Contents {
		page.Objects = append(page.Objects, Object{
			Key:          awssdk.ToString(obj.Key),
			Size:         awssdk.ToInt64(obj.Size),
			LastModified: timeString(obj.LastModified),
		})
	}
	page.Cursor, page.HasMore = awssdk.ToString(out.NextContinuationToken), awssdk.ToBool(out.IsTruncated)
	page.Total = len(page.Objects)
	return page, nil
}

// commandPollInterval is how often the SSM invocation is polled.
const commandPollInterval = 2 * time.Second

func (p *awsProvider) RunCommand(ctx context.Context, creds Credentials, req CommandRequest) (CommandResult, error) {
	cfg, cerr := p.awsConfig(creds)
	if cerr != nil {
		return CommandResult{}, cerr
	}
	client := ssm.NewFromConfig(cfg)
	timeout := int32(req.TimeoutSec)
	if timeout <= 0 {
		timeout = int32(defaultCommandTimeout / time.Second)
	}
	sent, err := client.SendCommand(ctx, &ssm.SendCommandInput{
		DocumentName:   awssdk.String("AWS-RunShellScript"),
		InstanceIds:    []string{req.InstanceID},
		Parameters:     map[string][]string{"commands": {req.Command}},
		TimeoutSeconds: awssdk.Int32(timeout),
	})
	if err != nil {
		return CommandResult{}, awsError(err)
	}
	commandID := awssdk.ToString(sent.Command.CommandId)
	result := CommandResult{InstanceID: req.InstanceID, CommandID: commandID, Status: awssdk.ToString(sent.Command.StatusDetails)}
	for {
		inv, ierr := client.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  awssdk.String(commandID),
			InstanceId: awssdk.String(req.InstanceID),
		})
		if ierr != nil {
			// The invocation is registered a moment after SendCommand.
			var apiErr smithy.APIError
			if errors.As(ierr, &apiErr) && apiErr.ErrorCode() == "InvocationDoesNotExist" {
				if werr := waitFor(ctx, commandPollInterval); werr != nil {
					return result, awsError(werr)
				}
				continue
			}
			return result, awsError(ierr)
		}
		result.Status = string(inv.Status)
		result.ExitCode = int(inv.ResponseCode)
		result.Stdout = awssdk.ToString(inv.StandardOutputContent)
		result.Stderr = awssdk.ToString(inv.StandardErrorContent)
		if terminalCommandStatus(inv.Status) {
			return result, nil
		}
		if werr := waitFor(ctx, commandPollInterval); werr != nil {
			return result, awsError(werr)
		}
	}
}

func terminalCommandStatus(s ssmtypes.CommandInvocationStatus) bool {
	switch s {
	case ssmtypes.CommandInvocationStatusSuccess,
		ssmtypes.CommandInvocationStatusCancelled,
		ssmtypes.CommandInvocationStatusTimedOut,
		ssmtypes.CommandInvocationStatusFailed:
		return true
	}
	return false
}

// ────────────────────────── AWS error classification ──────────────────────────

// awsReasons maps documented AWS error codes onto the normalized reasons.
var awsReasons = map[string]Reason{
	"InvalidClientTokenId":         ReasonInvalidCredential,
	"InvalidAccessKeyId":           ReasonInvalidCredential,
	"SignatureDoesNotMatch":        ReasonInvalidCredential,
	"UnrecognizedClientException":  ReasonInvalidCredential,
	"AuthFailure":                  ReasonInvalidCredential,
	"ExpiredToken":                 ReasonInvalidCredential,
	"ExpiredTokenException":        ReasonInvalidCredential,
	"AccessDenied":                 ReasonPermissionDenied,
	"AccessDeniedException":        ReasonPermissionDenied,
	"UnauthorizedOperation":        ReasonPermissionDenied,
	"OptInRequired":                ReasonPermissionDenied,
	"AuthFailure.SignatureFailure": ReasonInvalidCredential,
	"InvalidRegion":                ReasonRegionInvalid,
	"InvalidInstanceID":            ReasonNotFound,
	"InvalidInstanceId":            ReasonNotFound,
	"InvalidParameterValue":        ReasonRegionInvalid,
	"InvalidDBInstanceState":       ReasonInstanceNotRunning,
	"InvalidInstanceStatus":        ReasonInstanceNotRunning,
	"IncorrectInstanceState":       ReasonInstanceNotRunning,
	"UnsupportedOperation":         ReasonInstanceNotRunning,
	"NoSuchBucket":                 ReasonNotFound,
	"NotFound":                     ReasonNotFound,
	"Throttling":                   ReasonThrottled,
	"ThrottlingException":          ReasonThrottled,
	"RequestLimitExceeded":         ReasonThrottled,
	"TooManyRequestsException":     ReasonThrottled,
	"RequestCanceled":              ReasonTimeout,
	"RequestTimeout":               ReasonTimeout,
	"InternalError":                ReasonUpstream,
}

// awsFallback catches the undocumented variants of the same failures.
var awsFallback = []matchRule{
	{"signature", ReasonInvalidCredential},
	{"security token", ReasonInvalidCredential},
	{"credential", ReasonInvalidCredential},
	{"not authorized", ReasonPermissionDenied},
	{"not in a valid state", ReasonInstanceNotRunning},
	{"not in a running state", ReasonInstanceNotRunning},
	{"throttl", ReasonThrottled},
	{"rate exceeded", ReasonThrottled},
	{"deadline exceeded", ReasonTimeout},
	{"timed out", ReasonTimeout},
	{"no such", ReasonNotFound},
	{"could not be found", ReasonNotFound},
	{"invalid region", ReasonRegionInvalid},
}

// classifyAWS turns an SDK error into a normalized *Error. The AWS SDK exposes
// the service error code through smithy.APIError, so no string parsing is needed
// for the documented cases.
//
// A failure raised by the host's own gates never reaches this function: awsError
// checks for it first, because a scope denial classified as "upstream_error,
// retryable" would invite exactly the retry the gate exists to refuse.
func classifyAWS(err error) *Error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return newError(ReasonTimeout, ProviderAWS, "context", err.Error(), "")
	}
	code, message := "", err.Error()
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code, message = apiErr.ErrorCode(), apiErr.ErrorMessage()
	}
	return newError(reasonFor(code, message, awsReasons, awsFallback), ProviderAWS, code, message, "")
}

// awsError classifies a vendor error but lets a failure raised by capkit itself
// (scope_denied / rate_limited / timeout from the host's HTTPDoer) pass through
// verbatim, so cloudkit.go's k.failure keeps the host's own error code instead
// of re-labelling it an upstream cloud failure.
func awsError(err error) error {
	if err == nil {
		return nil
	}
	if ce := asCapkitError(err); ce != nil {
		return ce
	}
	return classifyAWS(err)
}

// ────────────────────────── small shared helpers ──────────────────────────

func tagValue(tags []ec2types.Tag, key string) string {
	for _, tag := range tags {
		if awssdk.ToString(tag.Key) == key {
			return awssdk.ToString(tag.Value)
		}
	}
	return ""
}

func nonEmpty(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return []string{v}
}

func timeString(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// adminish reports whether a policy name or ARN looks like full administrative
// access — the privesc signal worth surfacing in cloud_iam_list.
func adminish(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "administratoraccess") ||
		strings.Contains(n, ":admin") ||
		strings.HasSuffix(n, "/admin") ||
		strings.Contains(n, "fullaccess")
}

func clampMax(v int) int {
	if v <= 0 {
		return defaultPageSize
	}
	if v > core.MaxListItems {
		return core.MaxListItems
	}
	return v
}

// reasonLabel renders a classified error for a partial-failure warning line.
func reasonLabel(err error) string {
	var ce *Error
	if errors.As(err, &ce) {
		label := ce.Reason.Label()
		if ce.Message != "" {
			return label + "（" + ce.Message + "）"
		}
		return label
	}
	return fmt.Sprintf("%v", err)
}

// waitFor sleeps until d or the context ends, so a long-running poll still
// honors the caller's deadline.
func waitFor(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
