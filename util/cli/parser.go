package cli

import (
	"os"

	"github.com/alexflint/go-arg"
	"github.com/floating-cat/heteroglossia/util/osutil"
)

func Parse() Args {
	args := Args{}
	parser := arg.MustParse(&args)
	if len(os.Args) == 1 {
		parser.WriteHelp(os.Stdout)
		osutil.Exit(0)
	}
	return args
}

type Args struct {
	ConfigFile string `arg:"positional" help:"config file to use"`
}

const AppName = "heteroglossia"

// without the v prefix
const version = "(unknown version)"

func (Args) Version() string {
	return AppName + "(hg) " + version
}

func VersionWithVPrefix() string {
	return "v" + version
}
