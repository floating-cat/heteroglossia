package updater

import (
	"net/http"
	"time"

	"github.com/floating-cat/heteroglossia/util/log"
)

const (
	domainIPSetRulesFileURL          = "https://github.com/floating-cat/domain-ip-set-rules/raw/release/domain-ip-set-rules.db"
	domainIPSetRulesFileSHA256SumURL = "https://github.com/floating-cat/domain-ip-set-rules/raw/release/domain-ip-set-rules.db.sha256sum"

	ruleFileNeedUpdateInterval = 15 * 10 * time.Hour
)

func UpdateRuleDBFile(ruleDBFilePath string, client *http.Client) (bool, error) {
	update, err := needUpdateFile(ruleDBFilePath, ruleFileNeedUpdateInterval)
	if err != nil {
		return false, err
	}
	if !update {
		return false, nil
	}

	log.Info("start to update rules' files")
	err = updateFile(client, ruleDBFilePath, domainIPSetRulesFileURL, domainIPSetRulesFileSHA256SumURL)
	if err != nil {
		return false, err
	}
	return true, nil
}
