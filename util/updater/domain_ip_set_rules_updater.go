package updater

import (
	"net/http"
	"time"

	"github.com/floating-cat/heteroglossia/conf/rule"
	"github.com/floating-cat/heteroglossia/util/log"
)

const (
	domainRulesFileURL       = "https://cdn.jsdelivr.net/gh/floating-cat/domain-ip-set-rules@release/domain-rules.cbor"
	domainRulesFileSHA256URL = "https://cdn.jsdelivr.net/gh/floating-cat/domain-ip-set-rules@release/domain-rules.cbor.sha256sum"
	ipSetRulesFileURL        = "https://cdn.jsdelivr.net/gh/floating-cat/domain-ip-set-rules@release/ip-set-rules.cbor"
	ipSetRulesFileSHA256URL  = "https://cdn.jsdelivr.net/gh/floating-cat/domain-ip-set-rules@release/ip-set-rules.cbor.sha256sum"

	rulesFilesNeedUpdateInterval = 15 * 10 * time.Hour
)

func UpdateRulesFiles(client *http.Client) (bool, error) {
	update, err := needUpdateFile(rule.CborDomainRulesFilePath, rulesFilesNeedUpdateInterval)
	if err != nil {
		return false, err
	}
	if !update {
		return false, nil
	}

	err = updateRulesFiles(client)
	if err != nil {
		return false, err
	}
	return true, nil
}

func updateRulesFiles(client *http.Client) error {
	log.Info("start to update rules' files")
	err := updateFile(client, rule.CborDomainRulesFilePath, domainRulesFileURL, domainRulesFileSHA256URL)
	if err != nil {
		return err
	}
	return updateFile(client, rule.CborIpSetRulesFilePath, ipSetRulesFileURL, ipSetRulesFileSHA256URL)
}
