package rules

// This file is the curated, production-grade built-in ruleset (DESIGN.md §12).
//
// Design notes that apply to every rule below:
//   - Keywords are LOWERCASE prescreen gates. The detector lowercases the line
//     before testing them, so a keyword like "gocspx" matches a "GOCSPX-" line.
//     We prefer a keyword that is part of the secret's fixed prefix so the
//     prescreen filters aggressively; contextual rules fall back to the
//     provider name.
//   - SecretGroup points at the capture group holding the raw secret so the
//     detector can redact/fingerprint just the credential, not the surrounding
//     context. Group 0 is used when the whole match IS the secret (PEM blocks).
//   - Entropy floors are set ONLY on contextual/generic rules where the value
//     is free-form; fixed-format tokens (hex UUIDs, base64 of known length) are
//     already structurally constrained, and a floor would wrongly drop valid
//     low-alphabet hex keys.
//   - Allowlist regexes kill well-known fixtures/placeholders (e.g. the AWS
//     documentation key) without weakening the main pattern.
//
// Severity policy: cloud/root creds, private keys and DB connection strings are
// critical; scoped provider API tokens are high; publishable keys, JWTs and
// webhook URLs are medium (they leak often but are lower blast radius).

import (
	"regexp"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// mc is a terse alias for regexp.MustCompile to keep the (large) rule table
// readable. Patterns are compile-time constants, so a panic here is a build bug.
func mc(expr string) *regexp.Regexp { return regexp.MustCompile(expr) }

// Builtin returns the curated built-in detection rules. The slice is freshly
// allocated on every call so callers may freely append custom rules to it.
func Builtin() []Rule {
	return []Rule{
		// ---------------------------------------------------------------
		// AWS
		// ---------------------------------------------------------------
		{
			ID:          "aws-access-key-id",
			Description: "AWS access key ID",
			// AKIA=long-term, ASIA=temporary, ABIA/ACCA=service-specific.
			Regex:       mc(`\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b`),
			SecretGroup: 1,
			Keywords:    []string{"akia", "asia", "abia", "acca"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"cloud", "aws"},
			// The AWS docs example key must never fire.
			Allowlist: []*regexp.Regexp{mc(`^AKIAIOSFODNN7EXAMPLE$`)},
		},
		{
			ID:          "aws-secret-access-key",
			Description: "AWS secret access key (contextual)",
			// 40-char base64 sitting next to an aws secret-key assignment. The
			// key alone is indistinguishable from any base64 blob, so we anchor
			// on the surrounding variable name.
			Regex:       mc(`(?i)aws_?(?:secret_?)?access_?key["'\s:=]{1,15}([A-Za-z0-9/+]{40})\b`),
			SecretGroup: 1,
			Keywords:    []string{"aws"},
			Entropy:     0.55,
			Severity:    finding.SeverityCritical,
			Tags:        []string{"cloud", "aws"},
			Allowlist:   []*regexp.Regexp{mc(`(?i)EXAMPLE`), mc(`^wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY$`)},
		},
		{
			ID:          "aws-session-token",
			Description: "AWS session token",
			Regex:       mc(`(?i)aws_?session_?token["'\s:=]{1,15}([A-Za-z0-9/+=]{100,})`),
			SecretGroup: 1,
			Keywords:    []string{"aws_session_token", "aws session token"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"cloud", "aws"},
		},
		{
			ID:          "aws-mws-auth-token",
			Description: "Amazon MWS auth token",
			Regex:       mc(`\b(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
			SecretGroup: 1,
			Keywords:    []string{"amzn.mws"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"cloud", "aws"},
		},

		// ---------------------------------------------------------------
		// Google Cloud / Firebase
		// ---------------------------------------------------------------
		{
			ID:          "gcp-api-key",
			Description: "Google Cloud / Firebase / Gemini API key",
			Regex:       mc(`\b(AIza[0-9A-Za-z_\-]{35})\b`),
			SecretGroup: 1,
			Keywords:    []string{"aiza"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"cloud", "gcp", "ai"},
		},
		{
			ID:          "gcp-service-account-private-key-id",
			Description: "GCP service-account private_key_id",
			Regex:       mc(`(?i)"private_key_id"\s*:\s*"([0-9a-f]{40})"`),
			SecretGroup: 1,
			Keywords:    []string{"private_key_id"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"cloud", "gcp"},
		},
		{
			ID:          "gcp-oauth-client-secret",
			Description: "Google OAuth client secret",
			Regex:       mc(`\b(GOCSPX-[A-Za-z0-9_\-]{28})\b`),
			SecretGroup: 1,
			Keywords:    []string{"gocspx"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"cloud", "gcp"},
		},
		{
			ID:          "google-oauth-refresh-token",
			Description: "Google OAuth refresh token",
			Regex:       mc(`\b(1//0[A-Za-z0-9_\-]{40,})\b`),
			SecretGroup: 1,
			Keywords:    []string{"1//0"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"cloud", "gcp"},
		},
		{
			ID:          "firebase-cloud-messaging-key",
			Description: "Firebase Cloud Messaging server key",
			Regex:       mc(`\b(AAAA[A-Za-z0-9_\-]{7}:APA91[A-Za-z0-9_\-]{130,})\b`),
			SecretGroup: 1,
			Keywords:    []string{"apa91"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"cloud", "gcp"},
		},

		// ---------------------------------------------------------------
		// Azure
		// ---------------------------------------------------------------
		{
			ID:          "azure-storage-account-key",
			Description: "Azure storage account key",
			// 88-char base64 ending in "==", typically after AccountKey=.
			Regex:       mc(`(?i)AccountKey\s*=\s*([A-Za-z0-9+/]{86}==)`),
			SecretGroup: 1,
			Keywords:    []string{"accountkey"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"cloud", "azure"},
		},
		{
			ID:          "azure-connection-string",
			Description: "Azure storage connection string",
			Regex:       mc(`(DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/]{86}==)`),
			SecretGroup: 1,
			Keywords:    []string{"defaultendpointsprotocol"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"cloud", "azure"},
		},
		{
			ID:          "azure-client-secret",
			Description: "Azure AD client secret (contextual)",
			Regex:       mc(`(?i)azure[a-z_]{0,20}(?:client_?secret|secret)["'\s:=]{1,15}([A-Za-z0-9~._\-]{34,40})`),
			SecretGroup: 1,
			Keywords:    []string{"azure"},
			Entropy:     0.55,
			Severity:    finding.SeverityCritical,
			Tags:        []string{"cloud", "azure"},
		},
		{
			ID:          "azure-sas-token",
			Description: "Azure shared access signature token",
			Regex:       mc(`(?i)[?&]sig=([A-Za-z0-9%]{43,})`),
			SecretGroup: 1,
			Keywords:    []string{"sig="},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"cloud", "azure"},
		},

		// ---------------------------------------------------------------
		// GitHub
		// ---------------------------------------------------------------
		{
			ID:          "github-pat",
			Description: "GitHub personal access token (classic)",
			Regex:       mc(`\b(ghp_[A-Za-z0-9]{36})\b`),
			SecretGroup: 1,
			Keywords:    []string{"ghp_"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"vcs", "github"},
		},
		{
			ID:          "github-oauth-token",
			Description: "GitHub OAuth access token",
			Regex:       mc(`\b(gho_[A-Za-z0-9]{36})\b`),
			SecretGroup: 1,
			Keywords:    []string{"gho_"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"vcs", "github"},
		},
		{
			ID:          "github-app-user-token",
			Description: "GitHub app user-to-server token",
			Regex:       mc(`\b(ghu_[A-Za-z0-9]{36})\b`),
			SecretGroup: 1,
			Keywords:    []string{"ghu_"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"vcs", "github"},
		},
		{
			ID:          "github-app-server-token",
			Description: "GitHub app server-to-server token",
			Regex:       mc(`\b(ghs_[A-Za-z0-9]{36})\b`),
			SecretGroup: 1,
			Keywords:    []string{"ghs_"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"vcs", "github"},
		},
		{
			ID:          "github-refresh-token",
			Description: "GitHub refresh token",
			Regex:       mc(`\b(ghr_[A-Za-z0-9]{36})\b`),
			SecretGroup: 1,
			Keywords:    []string{"ghr_"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"vcs", "github"},
		},
		{
			ID:          "github-fine-grained-pat",
			Description: "GitHub fine-grained personal access token",
			Regex:       mc(`\b(github_pat_[A-Za-z0-9_]{82})\b`),
			SecretGroup: 1,
			Keywords:    []string{"github_pat_"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"vcs", "github"},
		},

		// ---------------------------------------------------------------
		// GitLab
		// ---------------------------------------------------------------
		{
			ID:          "gitlab-pat",
			Description: "GitLab personal access token",
			Regex:       mc(`\b(glpat-[A-Za-z0-9_\-]{20})\b`),
			SecretGroup: 1,
			Keywords:    []string{"glpat-"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"vcs", "gitlab"},
		},
		{
			ID:          "gitlab-deploy-token",
			Description: "GitLab deploy token",
			Regex:       mc(`\b(gldt-[A-Za-z0-9_\-]{20})\b`),
			SecretGroup: 1,
			Keywords:    []string{"gldt-"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"vcs", "gitlab"},
		},
		{
			ID:          "gitlab-runner-token",
			Description: "GitLab runner authentication token",
			Regex:       mc(`\b(glrt-[A-Za-z0-9_\-]{20})\b`),
			SecretGroup: 1,
			Keywords:    []string{"glrt-"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"vcs", "gitlab"},
		},
		{
			ID:          "gitlab-pipeline-trigger-token",
			Description: "GitLab pipeline trigger token",
			Regex:       mc(`\b(glptt-[0-9a-f]{40})\b`),
			SecretGroup: 1,
			Keywords:    []string{"glptt-"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"vcs", "gitlab"},
		},

		// ---------------------------------------------------------------
		// Slack
		// ---------------------------------------------------------------
		{
			ID:          "slack-token",
			Description: "Slack API token (bot/user/app/refresh)",
			Regex:       mc(`\b(xox[baprs]-[A-Za-z0-9-]{10,48})\b`),
			SecretGroup: 1,
			Keywords:    []string{"xox"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"saas", "slack"},
		},
		{
			ID:          "slack-app-token",
			Description: "Slack app-level token",
			Regex:       mc(`\b(xapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[a-f0-9]+)\b`),
			SecretGroup: 1,
			Keywords:    []string{"xapp-"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"saas", "slack"},
		},
		{
			ID:          "slack-webhook-url",
			Description: "Slack incoming webhook URL",
			Regex:       mc(`(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9]{24})`),
			SecretGroup: 1,
			Keywords:    []string{"hooks.slack.com"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"saas", "slack", "webhook"},
		},

		// ---------------------------------------------------------------
		// Stripe
		// ---------------------------------------------------------------
		{
			ID:          "stripe-secret-key",
			Description: "Stripe live secret key",
			Regex:       mc(`\b(sk_live_[0-9a-zA-Z]{24,99})\b`),
			SecretGroup: 1,
			Keywords:    []string{"sk_live_"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"payments", "stripe"},
		},
		{
			ID:          "stripe-restricted-key",
			Description: "Stripe live restricted key",
			Regex:       mc(`\b(rk_live_[0-9a-zA-Z]{24,99})\b`),
			SecretGroup: 1,
			Keywords:    []string{"rk_live_"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"payments", "stripe"},
		},
		{
			ID:          "stripe-publishable-key",
			Description: "Stripe live publishable key",
			// Publishable keys are meant to ship in clients: real but low risk.
			Regex:       mc(`\b(pk_live_[0-9a-zA-Z]{24,99})\b`),
			SecretGroup: 1,
			Keywords:    []string{"pk_live_"},
			Severity:    finding.SeverityMedium,
			Tags:        []string{"payments", "stripe"},
		},
		{
			ID:          "stripe-test-secret-key",
			Description: "Stripe test secret key",
			Regex:       mc(`\b(sk_test_[0-9a-zA-Z]{24,99})\b`),
			SecretGroup: 1,
			Keywords:    []string{"sk_test_"},
			Severity:    finding.SeverityMedium,
			Tags:        []string{"payments", "stripe"},
		},

		// ---------------------------------------------------------------
		// AI providers
		// ---------------------------------------------------------------
		{
			ID:          "anthropic-api-key",
			Description: "Anthropic API key",
			Regex:       mc(`\b(sk-ant-api03-[A-Za-z0-9_\-]{80,120})\b`),
			SecretGroup: 1,
			Keywords:    []string{"sk-ant-api03"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"ai", "anthropic"},
		},
		{
			ID:          "anthropic-oauth-token",
			Description: "Anthropic OAuth access token",
			Regex:       mc(`\b(sk-ant-oat01-[A-Za-z0-9_\-]{80,120})\b`),
			SecretGroup: 1,
			Keywords:    []string{"sk-ant-oat01"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"ai", "anthropic"},
		},
		{
			ID:          "openai-api-key",
			Description: "OpenAI API key (classic)",
			// The hyphenated sk-proj-/sk-ant- forms can't match [A-Za-z0-9]{48}.
			Regex:       mc(`\b(sk-[A-Za-z0-9]{48})\b`),
			SecretGroup: 1,
			Keywords:    []string{"sk-"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"ai", "openai"},
		},
		{
			ID:          "openai-project-key",
			Description: "OpenAI project-scoped API key",
			Regex:       mc(`\b(sk-proj-[A-Za-z0-9_\-]{48,})\b`),
			SecretGroup: 1,
			Keywords:    []string{"sk-proj-"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"ai", "openai"},
		},
		{
			ID:          "cohere-api-key",
			Description: "Cohere API key (contextual)",
			Regex:       mc(`(?i)cohere[a-z_]{0,20}["'\s:=]{1,15}([A-Za-z0-9]{40})\b`),
			SecretGroup: 1,
			Keywords:    []string{"cohere"},
			Entropy:     0.55,
			Severity:    finding.SeverityHigh,
			Tags:        []string{"ai", "cohere"},
		},
		{
			ID:          "huggingface-token",
			Description: "Hugging Face access token",
			Regex:       mc(`\b(hf_[A-Za-z0-9]{34})\b`),
			SecretGroup: 1,
			Keywords:    []string{"hf_"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"ai", "huggingface"},
		},
		{
			ID:          "replicate-token",
			Description: "Replicate API token",
			Regex:       mc(`\b(r8_[A-Za-z0-9]{37})\b`),
			SecretGroup: 1,
			Keywords:    []string{"r8_"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"ai", "replicate"},
		},
		{
			ID:          "groq-api-key",
			Description: "Groq API key",
			Regex:       mc(`\b(gsk_[A-Za-z0-9]{52})\b`),
			SecretGroup: 1,
			Keywords:    []string{"gsk_"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"ai", "groq"},
		},

		// ---------------------------------------------------------------
		// Twilio / email delivery
		// ---------------------------------------------------------------
		{
			ID:          "twilio-account-sid",
			Description: "Twilio account SID",
			Regex:       mc(`\b(AC[0-9a-f]{32})\b`),
			SecretGroup: 1,
			Keywords:    []string{"ac"},
			Severity:    finding.SeverityMedium,
			Tags:        []string{"comms", "twilio"},
		},
		{
			ID:          "twilio-api-key-sid",
			Description: "Twilio API key SID",
			Regex:       mc(`\b(SK[0-9a-f]{32})\b`),
			SecretGroup: 1,
			Keywords:    []string{"sk"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"comms", "twilio"},
		},
		{
			ID:          "sendgrid-api-key",
			Description: "SendGrid API key",
			Regex:       mc(`\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b`),
			SecretGroup: 1,
			Keywords:    []string{"sg."},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"comms", "sendgrid"},
		},
		{
			ID:          "mailgun-api-key",
			Description: "Mailgun API key",
			Regex:       mc(`\b(key-[0-9a-zA-Z]{32})\b`),
			SecretGroup: 1,
			Keywords:    []string{"key-"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"comms", "mailgun"},
		},
		{
			ID:          "mailchimp-api-key",
			Description: "Mailchimp API key",
			Regex:       mc(`\b([0-9a-f]{32}-us[0-9]{1,2})\b`),
			SecretGroup: 1,
			Keywords:    []string{"-us"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"comms", "mailchimp"},
		},
		{
			ID:          "postmark-server-token",
			Description: "Postmark server token (contextual)",
			Regex:       mc(`(?i)postmark[a-z_]{0,20}["'\s:=]{1,15}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`),
			SecretGroup: 1,
			Keywords:    []string{"postmark"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"comms", "postmark"},
		},

		// ---------------------------------------------------------------
		// Observability / monitoring
		// ---------------------------------------------------------------
		{
			ID:          "datadog-api-key",
			Description: "Datadog API key (contextual)",
			Regex:       mc(`(?i)datadog[a-z_]{0,20}["'\s:=]{1,15}([0-9a-f]{32})\b`),
			SecretGroup: 1,
			Keywords:    []string{"datadog"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"observability", "datadog"},
		},
		{
			ID:          "newrelic-api-key",
			Description: "New Relic user API key",
			Regex:       mc(`\b(NRAK-[A-Z0-9]{27})\b`),
			SecretGroup: 1,
			Keywords:    []string{"nrak-"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"observability", "newrelic"},
		},
		{
			ID:          "pagerduty-api-key",
			Description: "PagerDuty API key (contextual)",
			Regex:       mc(`(?i)pagerduty[a-z_]{0,20}["'\s:=]{1,15}([A-Za-z0-9+_\-]{20})\b`),
			SecretGroup: 1,
			Keywords:    []string{"pagerduty"},
			Entropy:     0.5,
			Severity:    finding.SeverityHigh,
			Tags:        []string{"observability", "pagerduty"},
		},
		{
			ID:          "sentry-dsn",
			Description: "Sentry DSN with embedded public key",
			Regex:       mc(`(https://[0-9a-f]{32}@o[0-9]+\.ingest\.(?:[a-z]+\.)?sentry\.io/[0-9]+)`),
			SecretGroup: 1,
			Keywords:    []string{"ingest.sentry.io"},
			Severity:    finding.SeverityMedium,
			Tags:        []string{"observability", "sentry"},
		},
		{
			ID:          "grafana-service-account-token",
			Description: "Grafana service-account / cloud token",
			Regex:       mc(`\b(gl(?:sa|c)_[A-Za-z0-9_]{32,})\b`),
			SecretGroup: 1,
			Keywords:    []string{"glsa_", "glc_"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"observability", "grafana"},
		},

		// ---------------------------------------------------------------
		// Databases (only when credentials are embedded)
		// ---------------------------------------------------------------
		{
			ID:          "postgres-connection-uri",
			Description: "PostgreSQL connection URI with credentials",
			Regex:       mc(`\b(postgres(?:ql)?://[^:@/\s]+:[^@/\s]+@[^\s/]+)`),
			SecretGroup: 1,
			Keywords:    []string{"postgres"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"database"},
		},
		{
			ID:          "mysql-connection-uri",
			Description: "MySQL connection URI with credentials",
			Regex:       mc(`\b(mysql://[^:@/\s]+:[^@/\s]+@[^\s/]+)`),
			SecretGroup: 1,
			Keywords:    []string{"mysql://"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"database"},
		},
		{
			ID:          "mongodb-connection-uri",
			Description: "MongoDB connection URI with credentials",
			Regex:       mc(`\b(mongodb(?:\+srv)?://[^:@/\s]+:[^@/\s]+@[^\s/]+)`),
			SecretGroup: 1,
			Keywords:    []string{"mongodb"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"database"},
		},
		{
			ID:          "redis-connection-uri",
			Description: "Redis connection URI with credentials",
			Regex:       mc(`\b(rediss?://[^:@/\s]*:[^@/\s]+@[^\s/]+)`),
			SecretGroup: 1,
			Keywords:    []string{"redis://", "rediss://"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"database"},
		},

		// ---------------------------------------------------------------
		// JWT / bearer / private keys
		// ---------------------------------------------------------------
		{
			ID:          "jwt",
			Description: "JSON Web Token",
			// Three base64url segments; the leading eyJ is base64 of '{"'.
			Regex:       mc(`\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b`),
			SecretGroup: 1,
			Keywords:    []string{"eyj"},
			Severity:    finding.SeverityMedium,
			Tags:        []string{"token", "jwt"},
		},
		{
			ID:          "authorization-bearer",
			Description: "Bearer token in an Authorization header",
			Regex:       mc(`(?i)authorization["'\s:=]{1,6}bearer\s+([A-Za-z0-9_\-.=]{20,})`),
			SecretGroup: 1,
			Keywords:    []string{"bearer"},
			Entropy:     0.5,
			Severity:    finding.SeverityHigh,
			Tags:        []string{"token"},
		},
		{
			ID:          "private-key",
			Description: "Private key material (PEM block)",
			// Covers RSA/EC/DSA/OPENSSH/PGP/ENCRYPTED/PKCS8 ("PRIVATE KEY").
			Regex:       mc(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`),
			SecretGroup: 0,
			Keywords:    []string{"private key"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"key"},
		},

		// ---------------------------------------------------------------
		// Package registries / infra tooling
		// ---------------------------------------------------------------
		{
			ID:          "npm-token",
			Description: "npm access token",
			Regex:       mc(`\b(npm_[A-Za-z0-9]{36})\b`),
			SecretGroup: 1,
			Keywords:    []string{"npm_"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"registry", "npm"},
		},
		{
			ID:          "pypi-token",
			Description: "PyPI upload token",
			Regex:       mc(`\b(pypi-[A-Za-z0-9_\-]{50,})\b`),
			SecretGroup: 1,
			Keywords:    []string{"pypi-"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"registry", "pypi"},
		},
		{
			ID:          "rubygems-token",
			Description: "RubyGems API key",
			Regex:       mc(`\b(rubygems_[a-f0-9]{48})\b`),
			SecretGroup: 1,
			Keywords:    []string{"rubygems_"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"registry", "rubygems"},
		},
		{
			ID:          "docker-hub-token",
			Description: "Docker Hub personal access token",
			Regex:       mc(`\b(dckr_pat_[A-Za-z0-9_\-]{20,})\b`),
			SecretGroup: 1,
			Keywords:    []string{"dckr_pat_"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"registry", "docker"},
		},
		{
			ID:          "terraform-cloud-token",
			Description: "Terraform Cloud/Enterprise API token",
			Regex:       mc(`\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,})\b`),
			SecretGroup: 1,
			Keywords:    []string{"atlasv1"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"infra", "terraform"},
		},
		{
			ID:          "vault-token",
			Description: "HashiCorp Vault token",
			Regex:       mc(`\b(hv[sbr]\.[A-Za-z0-9_\-]{24,})\b`),
			SecretGroup: 1,
			Keywords:    []string{"hvs.", "hvb.", "hvr."},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"infra", "vault"},
		},

		// ---------------------------------------------------------------
		// Cloud hosting providers
		// ---------------------------------------------------------------
		{
			ID:          "cloudflare-api-token",
			Description: "Cloudflare API token (contextual)",
			Regex:       mc(`(?i)cloudflare[a-z_]{0,20}["'\s:=]{1,15}([A-Za-z0-9_\-]{40})\b`),
			SecretGroup: 1,
			Keywords:    []string{"cloudflare"},
			Entropy:     0.5,
			Severity:    finding.SeverityHigh,
			Tags:        []string{"infra", "cloudflare"},
		},
		{
			ID:          "digitalocean-token",
			Description: "DigitalOcean personal access / OAuth token",
			Regex:       mc(`\b(do[oprt]_v1_[a-f0-9]{64})\b`),
			SecretGroup: 1,
			Keywords:    []string{"dop_v1_", "doo_v1_", "dor_v1_", "dot_v1_"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"infra", "digitalocean"},
		},
		{
			ID:          "heroku-api-key",
			Description: "Heroku API key (contextual)",
			Regex:       mc(`(?i)heroku[a-z_]{0,20}["'\s:=]{1,15}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`),
			SecretGroup: 1,
			Keywords:    []string{"heroku"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"infra", "heroku"},
		},
		{
			ID:          "netlify-token",
			Description: "Netlify access token (contextual)",
			Regex:       mc(`(?i)netlify[a-z_]{0,20}["'\s:=]{1,15}([A-Za-z0-9_\-]{40,})`),
			SecretGroup: 1,
			Keywords:    []string{"netlify"},
			Entropy:     0.5,
			Severity:    finding.SeverityHigh,
			Tags:        []string{"infra", "netlify"},
		},
		{
			ID:          "vercel-token",
			Description: "Vercel access token (contextual)",
			Regex:       mc(`(?i)vercel[a-z_]{0,20}["'\s:=]{1,15}([A-Za-z0-9]{24})\b`),
			SecretGroup: 1,
			Keywords:    []string{"vercel"},
			Entropy:     0.5,
			Severity:    finding.SeverityHigh,
			Tags:        []string{"infra", "vercel"},
		},
		{
			ID:          "flyio-token",
			Description: "Fly.io API token",
			Regex:       mc(`\b(fo1_[A-Za-z0-9_\-]{40,})\b`),
			SecretGroup: 1,
			Keywords:    []string{"fo1_"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"infra", "flyio"},
		},

		// ---------------------------------------------------------------
		// SaaS platforms
		// ---------------------------------------------------------------
		{
			ID:          "square-access-token",
			Description: "Square access token",
			Regex:       mc(`\b(sq0atp-[A-Za-z0-9_\-]{22})\b`),
			SecretGroup: 1,
			Keywords:    []string{"sq0atp-"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"payments", "square"},
		},
		{
			ID:          "shopify-access-token",
			Description: "Shopify access token",
			Regex:       mc(`\b(shpat_[a-fA-F0-9]{32})\b`),
			SecretGroup: 1,
			Keywords:    []string{"shpat_"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"saas", "shopify"},
		},
		{
			ID:          "shopify-shared-secret",
			Description: "Shopify app shared secret",
			Regex:       mc(`\b(shpss_[a-fA-F0-9]{32})\b`),
			SecretGroup: 1,
			Keywords:    []string{"shpss_"},
			Severity:    finding.SeverityCritical,
			Tags:        []string{"saas", "shopify"},
		},
		{
			ID:          "shopify-custom-app-token",
			Description: "Shopify custom app access token",
			Regex:       mc(`\b(shpca_[a-fA-F0-9]{32})\b`),
			SecretGroup: 1,
			Keywords:    []string{"shpca_"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"saas", "shopify"},
		},
		{
			ID:          "atlassian-api-token",
			Description: "Atlassian / Jira API token",
			Regex:       mc(`\b(ATATT3[A-Za-z0-9_\-=]{100,})\b`),
			SecretGroup: 1,
			Keywords:    []string{"atatt3"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"saas", "atlassian"},
		},
		{
			ID:          "linear-api-key",
			Description: "Linear API key",
			Regex:       mc(`\b(lin_api_[A-Za-z0-9]{40})\b`),
			SecretGroup: 1,
			Keywords:    []string{"lin_api_"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"saas", "linear"},
		},
		{
			ID:          "notion-token",
			Description: "Notion integration token",
			Regex:       mc(`\b((?:secret_|ntn_)[A-Za-z0-9]{36,})\b`),
			SecretGroup: 1,
			Keywords:    []string{"ntn_", "secret_"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"saas", "notion"},
		},
		{
			ID:          "airtable-token",
			Description: "Airtable personal access token",
			Regex:       mc(`\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b`),
			SecretGroup: 1,
			Keywords:    []string{"pat", "airtable"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"saas", "airtable"},
		},
		{
			ID:          "asana-token",
			Description: "Asana personal access token (contextual)",
			Regex:       mc(`(?i)asana[a-z_]{0,20}["'\s:=]{1,15}([0-9]/[0-9]{16}:[A-Za-z0-9]{32})`),
			SecretGroup: 1,
			Keywords:    []string{"asana"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"saas", "asana"},
		},
		{
			ID:          "discord-bot-token",
			Description: "Discord bot token",
			Regex:       mc(`\b([MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38})\b`),
			SecretGroup: 1,
			Keywords:    []string{"discord"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"saas", "discord"},
		},
		{
			ID:          "discord-webhook-url",
			Description: "Discord webhook URL",
			Regex:       mc(`(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,80})`),
			SecretGroup: 1,
			Keywords:    []string{"discord.com/api/webhooks", "discordapp.com/api/webhooks"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"saas", "discord", "webhook"},
		},
		{
			ID:          "telegram-bot-token",
			Description: "Telegram bot token",
			Regex:       mc(`\b([0-9]{8,10}:AA[A-Za-z0-9_\-]{32,35})\b`),
			SecretGroup: 1,
			Keywords:    []string{":aa"},
			Severity:    finding.SeverityHigh,
			Tags:        []string{"saas", "telegram"},
		},

		// ---------------------------------------------------------------
		// Generic assignments & webhooks (entropy-gated to cut noise)
		// ---------------------------------------------------------------
		// Password and secret assignments have no fixed format, so they are
		// not regex rules: internal/detect/structural.go finds them by key name
		// with no entropy floor and emits generic-password-assignment /
		// generic-secret-assignment.
		{
			ID:          "generic-webhook-url",
			Description: "Generic secret-bearing webhook URL",
			Regex:       mc(`(https://[a-z0-9.\-]+/(?:webhooks?|hooks?)/[A-Za-z0-9_\-/]{16,})`),
			SecretGroup: 1,
			Keywords:    []string{"webhook", "hook"},
			Severity:    finding.SeverityMedium,
			Tags:        []string{"generic", "webhook"},
		},
	}
}
