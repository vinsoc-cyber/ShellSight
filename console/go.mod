// The ShellSight analyst console.
//
// A SEPARATE MODULE from the scanner, deliberately. The scanner is a binary copied onto customer
// hosts that are assumed to be compromised, and its dependency surface is kept deliberately tiny --
// two direct dependencies. The console is an internal web service that needs a PostgreSQL driver
// and, later, a front-end build. Those are opposite problems, and putting them in one module put a
// database driver into the scanner's supply-chain review scope for no benefit: the console imports
// nothing from the scanner.
module shellsightconsole

go 1.26.4

require github.com/jackc/pgx/v5 v5.7.2

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)
