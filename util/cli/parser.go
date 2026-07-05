package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/floating-cat/heteroglossia/util/osutil"
)

func Parse() Args {
	fs := flag.NewFlagSet(AppName, flag.ExitOnError)
	var showVersion bool
	fs.BoolVar(&showVersion, "version", false, "")
	fs.BoolVar(&showVersion, "v", false, "")
	var rulesDBFile string
	fs.StringVar(&rulesDBFile, "db", "", "")
	fs.Usage = func() {
		usage := fmt.Sprintf(`%v
Usage: %v [CONFIG_FILE]

Positional arguments:
  CONFIG_FILE            config file to use

Options:
  -db DB_FILE            domain & IP set rules database file to use
  -h, --help             display this help and exit
  -v, --version          display version and exit`, AppName+"(hg) "+Version, AppName)
		_, _ = fmt.Fprintln(fs.Output(), usage)
	}

	_ = fs.Parse(os.Args[1:])
	if showVersion {
		fmt.Println(AppName + "(hg) " + Version)
		osutil.Exit(0)
	}
	if len(fs.Args()) == 0 {
		fs.Usage()
		osutil.Exit(0)
	}

	return Args{ConfigFile: fs.Arg(0), RulesDBFile: rulesDBFile}
}

type Args struct {
	ConfigFile  string
	RulesDBFile string
}

const AppName = "heteroglossia"

// Version needs to be a variable to be used with -ldflags
var Version = "(unknown version)" // without the v prefix
