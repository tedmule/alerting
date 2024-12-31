package dinding

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/prometheus/alertmanager/types"

	"github.com/grafana/alerting/logging"
	"github.com/grafana/alerting/receivers"
	"github.com/grafana/alerting/templates"
)

// Notifier is responsible for sending alert notifications to ding ding.
type Notifier struct {
	*receivers.Base
	log      logging.Logger
	ns       receivers.WebhookSender
	tmpl     *templates.Template
	settings Config
}

func New(cfg Config, meta receivers.Metadata, template *templates.Template, sender receivers.WebhookSender, logger logging.Logger) *Notifier {
	return &Notifier{
		Base:     receivers.NewBase(meta),
		log:      logger,
		ns:       sender,
		tmpl:     template,
		settings: cfg,
	}
}

// Notify sends the alert notification to dingding.
func (dd *Notifier) Notify(ctx context.Context, as ...*types.Alert) (bool, error) {
	dd.log.Info("sending dingding")

	dingDingURL := buildDingDingURL(dd)

	var tmplErr error
	tmpl, _ := templates.TmplText(ctx, dd.tmpl, as, dd.log, &tmplErr)

	message := tmpl(dd.settings.Message)
	title := tmpl(dd.settings.Title)

	msgType := tmpl(dd.settings.MessageType)
	b, err := buildBody(dingDingURL, msgType, title, message)
	if err != nil {
		return false, err
	}

	if tmplErr != nil {
		dd.log.Warn("failed to template DingDing message", "error", tmplErr.Error())
		tmplErr = nil
	}

	u := tmpl(dd.settings.URL)
	if len(dd.settings.Secret) > 0 {
		u = buildSignatureURL(dd.settings.URL, dd.settings.Secret)
	}
	if tmplErr != nil {
		dd.log.Warn("failed to template DingDing URL", "error", tmplErr.Error(), "fallback", dd.settings.URL)
		u = dd.settings.URL
	}

	cmd := &receivers.SendWebhookSettings{URL: u, Body: b}

	if err := dd.ns.SendWebhook(ctx, cmd); err != nil {
		return false, fmt.Errorf("send notification to dingding: %w", err)
	}

	return true, nil
}

func (dd *Notifier) SendResolved() bool {
	return !dd.GetDisableResolveMessage()
}

func buildDingDingURL(dd *Notifier) string {
	q := url.Values{
		"pc_slide": {"false"},
		"url":      {receivers.JoinURLPath(dd.tmpl.ExternalURL.String(), "/alerting/list", dd.log)},
	}

	// Use special link to auto open the message url outside Dingding
	// Refer: https://open-doc.dingtalk.com/docs/doc.htm?treeId=385&articleId=104972&docType=1#s9
	return "dingtalk://dingtalkclient/page/link?" + q.Encode()
}

func buildBody(url string, msgType string, title string, msg string) (string, error) {
	var bodyMsg map[string]interface{}
	if msgType == "actionCard" {
		bodyMsg = map[string]interface{}{
			"msgtype": "actionCard",
			"actionCard": map[string]string{
				"text":        msg,
				"title":       title,
				"singleTitle": "More",
				"singleURL":   url,
			},
		}
	} else {
		bodyMsg = map[string]interface{}{
			"msgtype": "link",
			"link": map[string]string{
				"text":       msg,
				"title":      title,
				"messageUrl": url,
			},
		}
	}
	body, err := json.Marshal(bodyMsg)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func buildSignatureURL(settingsURL string, secret string) string {
	fmt.Println("secrettttttttttt")
	// Get current timestamp(millisecond) as string
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Calculate HMAC-SHA256 signature using secret and timestamp
	secretBytes := []byte(secret)
	signatureBytes := []byte(fmt.Sprintf("%s\n%s", timestamp, secret))
	h := hmac.New(sha256.New, secretBytes)
	h.Write(signatureBytes)
	hmacSignature := h.Sum(nil)

	// Base64 encode
	sign := base64.StdEncoding.EncodeToString(hmacSignature)
	// URL quote
	signature := url.QueryEscape(sign)

	// URL format: https://oapi.dingtalk.com/robot/send?access_token=XXXXXX&timestamp=XXX&sign=XXX
	return fmt.Sprintf("%s&timestamp=%s&sign=%s", settingsURL, timestamp, signature)
}
