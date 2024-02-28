package updater

import (
	"net/http"
	"time"

	"github.com/floating-cat/heteroglossia/conf/rule"
	"github.com/floating-cat/heteroglossia/util/log"
)

const (
	domainIPSetRulesFileURL          = "https://github.com/floating-cat/domain-ip-set-rules/raw/release/domain-ip-set-rules.db"
	domainIPSetRulesFileSHA256SumURL = "https://github.com/floating-cat/domain-ip-set-rules/raw/release/domain-ip-set-rules.db.sha256sum"

	ruleFileNeedUpdateInterval = 15 * 10 * time.Hour
)

func UpdateRuleFile(client *http.Client) (bool, error) {
	update, err := needUpdateFile(rule.DomainIPSetRulesDBFilename, ruleFileNeedUpdateInterval)
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
	return updateFile(client, rule.DomainIPSetRulesDBFilename, domainIPSetRulesFileURL, domainIPSetRulesFileSHA256SumURL)
}
