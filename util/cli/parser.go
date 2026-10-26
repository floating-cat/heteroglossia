package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/floating-cat/heteroglossia/util/osutil"
)

func Parse() Args {
	fs := flag.NewFlagSet(appName, flag.ExitOnError)
	var rulesDBFile string
	fs.StringVar(&rulesDBFile, "database", "", "")
	fs.StringVar(&rulesDBFile, "db", "", "")
	var showInfo bool
	fs.BoolVar(&showInfo, "info", false, "")
	fs.BoolVar(&showInfo, "i", false, "")
	var showVersion bool
	fs.BoolVar(&showVersion, "version", false, "")
	fs.BoolVar(&showVersion, "v", false, "")
	fs.Usage = func() {
		usage := fmt.Sprintf(`%v
Usage: %[2]v CONFIG_FILE
       %[2]v --database DB_FILE CONFIG_FILE
       %[2]v --info CONFIG_FILE

Positional argument:
  CONFIG_FILE              config file to use

Options:
  -db, --database DB_FILE  domain & IP set rules database file to use
  -h, --help               display this help and exit
  -i, --info               display connection info of CONFIG_FILE and exit
  -v, --version            display version and exit`, appName+"(hg) "+Version, appName)
		_, _ = fmt.Fprintln(fs.Output(), usage)
	}

	_ = fs.Parse(os.Args[1:])
	if showVersion {
		fmt.Println(appName + "(hg) " + Version)
		osutil.Exit(0)
	}

	if len(fs.Args()) == 0 {
		if fs.NFlag() == 0 {
			fs.Usage()
			osutil.Exit(0)
		}
		// Flags like -i or -db were given without CONFIG_FILE, so report it as
		// a usage error with exit code 2, matching flag.ExitOnError.
		_, _ = fmt.Fprintln(fs.Output(), "missing CONFIG_FILE")
		fs.Usage()
		osutil.Exit(2)
	}
	return Args{ConfigFile: fs.Arg(0), RulesDBFile: rulesDBFile, ShowInfo: showInfo}
}

type Args struct {
	ConfigFile  string
	RulesDBFile string
	// ShowInfo reports whether to print ConfigFile's connection info and exit.
	ShowInfo bool
}

const appName = "heteroglossia"

// Version needs to be a variable to be used with -ldflags
var Version = "(unknown version)" // without the v prefix
