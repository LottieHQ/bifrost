package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LottieHQ/bifrost/internal/discovery"
	"github.com/LottieHQ/bifrost/internal/sso"
	"github.com/LottieHQ/bifrost/internal/ui"
	"github.com/atotto/clipboard"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/spf13/cobra"
)

// tailscaleAppCLI is the CLI inside the macOS app, used when `tailscale` is not on PATH.
const tailscaleAppCLI = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"

const (
	reachTimeout       = 2 * time.Second
	notReachableReason = "no grant, or your device fails the posture check"
	prdNotOnTailnet    = "Production databases are not on the tailnet yet"
)

// tailscaleCmd connects to a database served on the tailnet. Databases are found
// by the bifrost:tailnet-name tag on their RDS cluster or RDS Proxy endpoint, so
// no database names or hosts live in this repository.
var tailscaleCmd = &cobra.Command{
	Use:   "tailscale [database]",
	Short: "Connect to a database over the Tailscale tailnet",
	Long: `Connect to a database over the Tailscale tailnet, without a bastion or SSM tunnel.

Databases are those tagged bifrost:tailnet-name in the AWS accounts you hold an SSO role in.
With no database named, pick one from the databases your device can reach.

For example:
bifrost tailscale
bifrost tailscale <name> --print
bifrost tailscale --env stg --list`,
	Hidden: true,
	Args:   cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		envFlag, _ := cmd.Flags().GetString("env")
		printFlag, _ := cmd.Flags().GetBool("print")
		guiFlag, _ := cmd.Flags().GetBool("gui")
		listFlag, _ := cmd.Flags().GetBool("list")
		suFlag, _ := cmd.Flags().GetBool("su")
		ssoProfileFlag, _ := cmd.Flags().GetString("sso-profile")
		refreshFlag, _ := cmd.Flags().GetBool("refresh")

		var name string
		if len(args) == 1 {
			name = args[0]
		}
		env, err := resolveTailnetEnv(envFlag, name)
		if err != nil {
			fail("%v", err)
		}
		if printFlag && guiFlag {
			fail("use --print or --gui, not both")
		}
		if listFlag && name != "" {
			fail("--list takes no database name")
		}

		suffix, err := tailnetSuffix()
		if err != nil {
			fail("%v", err)
		}

		ctx := context.Background()
		ssoRegion, startURL, err := resolveSSOEndpoint(ssoProfileFlag)
		if err != nil {
			fail("%v", err)
		}
		ssoClient := sso.NewClient(ssoRegion, startURL)
		token, err := ssoClient.Authenticate(ctx)
		if err != nil {
			fail("Authentication failed: %v", err)
		}
		accounts, err := ssoClient.ListAccounts(ctx, token)
		if sso.IsUnauthorizedErr(err) {
			fmt.Println("⚠️ Cached SSO token was rejected, re-authenticating...")
			token, err = ssoClient.Reauthenticate(ctx)
			if err != nil {
				fail("Authentication failed: %v", err)
			}
			accounts, err = ssoClient.ListAccounts(ctx, token)
		}
		if err != nil {
			fail("Error listing accounts: %v", err)
		}

		// Shares bifrost connect's discovery cache; same default region.
		var resources []discovery.Resource
		if !refreshFlag {
			cache, _ := discovery.LoadCache(ssoProfileFlag)
			if discovery.IsCacheValid(cache) {
				resources = cache.Resources
			}
		}
		if resources == nil {
			fmt.Fprintln(os.Stderr, "🔍 Discovering databases...")
			resources, err = discovery.Discover(ctx, ssoRegion, token, accounts.AccountList, "eu-west-2")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: discovery failed: %v\n", err)
			}
			if len(resources) > 0 {
				_ = discovery.SaveCache(ssoProfileFlag, resources)
			}
		}

		dbs := tailnetDatabases(resources, env)
		if len(dbs) == 0 && env == "prd" {
			fail("%s", prdNotOnTailnet)
		}

		var db discovery.Resource
		if name == "" {
			if len(dbs) == 0 {
				fail("No databases are tagged %s in your AWS accounts", discovery.TailnetNameTag)
			}
			reachable := probeReachable(dbs, suffix)
			if listFlag {
				for _, d := range dbs {
					if reachable[d.TailnetName] {
						fmt.Println(d.TailnetName)
					} else {
						fmt.Fprintf(os.Stderr, "%s: not reachable: %s\n", d.TailnetName, notReachableReason)
					}
				}
				return
			}
			db = selectTailnetDatabase(ui.NewPrompt(), dbs, reachable)
		} else {
			db, err = namedTailnetDatabase(dbs, name, suffix)
			if err != nil {
				fail("%v", err)
			}
			if !reachable(tailnetHost(db, suffix), db.Port) {
				if !printFlag && !guiFlag {
					fail("%s is not reachable: %s", db.TailnetName, notReachableReason)
				}
				fmt.Fprintf(os.Stderr, "⚠️  %s is not reachable: %s\n", db.TailnetName, notReachableReason)
			}
		}

		host := tailnetHost(db, suffix)
		switch engineKind(db.Engine) {
		case "postgres":
			// --su skips the question; without a terminal, the default is your own IAM user.
			connectTailnetPostgres(ctx, db, host, ssoRegion, token, suFlag, !suFlag && stdinIsTerminal(), printFlag, guiFlag)
		case "mysql":
			if suFlag {
				fail("--su applies to Postgres databases only")
			}
			connectTailnetMySQL(host, db.Port, printFlag, guiFlag)
		default:
			fail("%s has engine %q, which bifrost tailscale does not support", db.TailnetName, db.Engine)
		}
	},
}

func init() {
	rootCmd.AddCommand(tailscaleCmd)

	tailscaleCmd.Flags().String("env", "", "Environment, stg or prd (default: from the database name)")
	tailscaleCmd.Flags().Bool("print", false, "Print the client command instead of running it")
	tailscaleCmd.Flags().Bool("gui", false, "Print connection fields for a GUI client and copy the Postgres token to the clipboard")
	tailscaleCmd.Flags().Bool("list", false, "List the databases reachable now, one per line")
	tailscaleCmd.Flags().Bool("su", false, "Postgres: connect as su-<user> without asking")
	tailscaleCmd.Flags().String("sso-profile", "", "SSO profile to use for authentication")
	tailscaleCmd.Flags().Bool("refresh", false, "Force re-discovery of databases (ignore cache)")
}

func fail(format string, a ...any) {
	fmt.Printf("❌ "+format+"\n", a...)
	os.Exit(1)
}

// tailnetEnv returns the environment a tailnet name belongs to: its prefix up to
// the first "-", e.g. "stg" for "stg-example-pg".
func tailnetEnv(name string) string {
	env, _, _ := strings.Cut(name, "-")
	return env
}

// resolveTailnetEnv checks --env and that it agrees with the name's prefix.
// Returns "" when neither narrows the environment.
func resolveTailnetEnv(envFlag, name string) (string, error) {
	if envFlag != "" && envFlag != "stg" && envFlag != "prd" {
		return "", fmt.Errorf("--env must be stg or prd, not %q", envFlag)
	}
	if name == "" {
		return envFlag, nil
	}
	nameEnv := tailnetEnv(name)
	if envFlag != "" && nameEnv != envFlag {
		return "", fmt.Errorf("%s is not a %s database", name, envFlag)
	}
	if nameEnv == "stg" || nameEnv == "prd" {
		return nameEnv, nil
	}
	return envFlag, nil
}

// tailnetDatabases returns the resources tagged bifrost:tailnet-name in env (all
// envs if empty), sorted by tailnet name, one per name.
func tailnetDatabases(resources []discovery.Resource, env string) []discovery.Resource {
	seen := map[string]bool{}
	var dbs []discovery.Resource
	for _, r := range resources {
		if r.TailnetName == "" || seen[r.TailnetName] {
			continue
		}
		if env != "" && tailnetEnv(r.TailnetName) != env {
			continue
		}
		seen[r.TailnetName] = true
		dbs = append(dbs, r)
	}
	sort.Slice(dbs, func(i, j int) bool { return dbs[i].TailnetName < dbs[j].TailnetName })
	return dbs
}

// engineKind maps an RDS engine ("aurora-postgresql", "mysql", ...) to the client it needs.
func engineKind(engine string) string {
	switch e := strings.ToLower(engine); {
	case strings.Contains(e, "postgres"):
		return "postgres"
	case strings.Contains(e, "mysql"):
		return "mysql"
	}
	return ""
}

func tailnetHost(db discovery.Resource, suffix string) string {
	return db.TailnetName + "." + suffix
}

// namedTailnetDatabase finds the database tagged with name. A MySQL database
// needs no AWS call to connect, so an untagged name whose host answers on 3306
// is treated as MySQL: an engineer without an SSO role in its account can still
// reach it.
func namedTailnetDatabase(dbs []discovery.Resource, name, suffix string) (discovery.Resource, error) {
	for _, d := range dbs {
		if d.TailnetName == name {
			return d, nil
		}
	}
	fallback := discovery.Resource{TailnetName: name, Engine: "mysql", Port: 3306}
	if reachable(tailnetHost(fallback, suffix), fallback.Port) {
		fmt.Fprintf(os.Stderr, "⚠️  %s is not tagged in your AWS accounts, but answers on port 3306; using the MySQL client.\n", name)
		return fallback, nil
	}
	return discovery.Resource{}, fmt.Errorf("no database named %s is tagged %s in your AWS accounts", name, discovery.TailnetNameTag)
}

// dialTCP opens and closes a TCP connection; replaced in tests.
var dialTCP = func(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, reachTimeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

func reachable(host string, port int32) bool {
	return dialTCP(net.JoinHostPort(host, fmt.Sprintf("%d", port))) == nil
}

// probeReachable dials every database at once, so the list costs one timeout at most.
func probeReachable(dbs []discovery.Resource, suffix string) map[string]bool {
	var mu sync.Mutex
	var wg sync.WaitGroup
	result := make(map[string]bool, len(dbs))
	for _, d := range dbs {
		wg.Add(1)
		go func(d discovery.Resource) {
			defer wg.Done()
			ok := reachable(tailnetHost(d, suffix), d.Port)
			mu.Lock()
			result[d.TailnetName] = ok
			mu.Unlock()
		}(d)
	}
	wg.Wait()
	return result
}

// tailnetSelectItems builds the picker: one line per reachable database, then a
// line naming the unreachable ones. The note is "" when all are reachable.
func tailnetSelectItems(dbs []discovery.Resource, reachableNames map[string]bool) (items []string, byItem map[string]discovery.Resource, note string) {
	byItem = map[string]discovery.Resource{}
	var unreachable []string
	for _, d := range dbs {
		if !reachableNames[d.TailnetName] {
			unreachable = append(unreachable, d.TailnetName)
			continue
		}
		item := fmt.Sprintf("%-22s %-9s %s", d.TailnetName, engineKind(d.Engine), tailnetEnv(d.TailnetName))
		items = append(items, item)
		byItem[item] = d
	}
	if len(unreachable) > 0 {
		note = fmt.Sprintf("── not reachable: %s (%s)", strings.Join(unreachable, ", "), notReachableReason)
	}
	return items, byItem, note
}

func selectTailnetDatabase(prompt *ui.Prompt, dbs []discovery.Resource, reachableNames map[string]bool) discovery.Resource {
	items, byItem, note := tailnetSelectItems(dbs, reachableNames)
	if len(items) == 0 {
		fail("No tagged database is reachable: %s", strings.TrimPrefix(note, "── "))
	}
	if note != "" {
		items = append(items, note)
	}
	for {
		selected, err := prompt.Select("Select a database", items)
		if err != nil {
			fail("%v", err)
		}
		// The note line is not a database; re-prompt.
		if db, ok := byItem[selected]; ok {
			return db
		}
	}
}

// tailscaleStatus holds the fields of `tailscale status --json` that Bifrost reads.
type tailscaleStatus struct {
	BackendState   string
	MagicDNSSuffix string
}

// tailnetSuffix returns the tailnet's MagicDNS suffix, so the tailnet name is
// read at run time rather than kept in the code.
func tailnetSuffix() (string, error) {
	cli, err := exec.LookPath("tailscale")
	if err != nil {
		if _, statErr := os.Stat(tailscaleAppCLI); statErr != nil {
			return "", fmt.Errorf("tailscale not found on PATH or at %s; install Tailscale and sign in", tailscaleAppCLI)
		}
		cli = tailscaleAppCLI
	}
	// status --json can exit non-zero while still printing the state; parse what it printed.
	out, err := exec.Command(cli, "status", "--json").Output()
	if len(out) == 0 && err != nil {
		return "", fmt.Errorf("tailscale is not connected (tailscale status: %v)", err)
	}
	return parseTailscaleStatus(out)
}

func parseTailscaleStatus(data []byte) (string, error) {
	var st tailscaleStatus
	if err := json.Unmarshal(data, &st); err != nil {
		return "", fmt.Errorf("could not read tailscale status: %w", err)
	}
	if st.BackendState != "Running" {
		return "", fmt.Errorf("tailscale is not connected (state: %s). Connect Tailscale and try again", st.BackendState)
	}
	suffix := strings.TrimSuffix(st.MagicDNSSuffix, ".")
	if suffix == "" {
		return "", errors.New("tailscale reports no MagicDNS suffix; MagicDNS must be on")
	}
	return suffix, nil
}

// clientCommand is a database client invocation: argv and the full child environment.
type clientCommand struct {
	Path string
	Args []string // argv, Args[0] is the program name
	Env  []string
}

// execClient replaces Bifrost with the client, so the client owns the terminal and signals.
func execClient(c clientCommand) {
	if err := syscall.Exec(c.Path, c.Args, c.Env); err != nil {
		fail("could not run %s: %v", c.Path, err)
	}
}

// environWithout returns os.Environ() minus the named variables.
func environWithout(names ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		drop := false
		for _, n := range names {
			if key == n {
				drop = true
				break
			}
		}
		if !drop {
			env = append(env, kv)
		}
	}
	return env
}

func postgresConninfo(host string, port int32, user string) string {
	return fmt.Sprintf("host=%s port=%d user=%s dbname=postgres sslmode=require", host, port, user)
}

// postgresPrintLine is the shell line --print shows: the token only in PGPASSWORD.
func postgresPrintLine(conninfo, token string) string {
	return fmt.Sprintf("PGPASSWORD='%s' psql \"%s\"", token, conninfo)
}

// homebrewPrefixes are where Homebrew keeps keg-only formulae (Apple silicon, then
// Intel). libpq and mysql-client are keg-only, so `brew install` does not put
// psql or mysql on PATH. A variable so tests can point it elsewhere.
var homebrewPrefixes = []string{"/opt/homebrew/opt", "/usr/local/opt"}

// findClient looks for a client on PATH, then in its Homebrew keg.
func findClient(name, keg string) (string, error) {
	path, err := exec.LookPath(name)
	if err == nil {
		return path, nil
	}
	for _, prefix := range homebrewPrefixes {
		candidate := filepath.Join(prefix, keg, "bin", name)
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", err
}

// postgresCommand runs psql with the IAM token in the child's environment only,
// never in argv, where other local users could read it from the process list.
func postgresCommand(conninfo, token string) (clientCommand, error) {
	path, err := findClient("psql", "libpq")
	if err != nil {
		return clientCommand{}, err
	}
	return clientCommand{
		Path: path,
		Args: []string{"psql", conninfo},
		Env:  append(environWithout("PGPASSWORD"), "PGPASSWORD="+token),
	}, nil
}

// promptTailnetSuperuser asks which IAM user to log in as, as `bifrost connect` does.
func promptTailnetSuperuser(prompt *ui.Prompt, user string) bool {
	superuser := fmt.Sprintf("🔑 IAM Superuser (su-%s)", user)
	choice, err := prompt.Select("Log in as", []string{fmt.Sprintf("🔑 IAM (%s)", user), superuser})
	if err != nil {
		fail("Error selecting a user: %v", err)
	}
	return choice == superuser
}

// stdinIsTerminal reports whether a person can answer a prompt.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func connectTailnetPostgres(ctx context.Context, db discovery.Resource, host, ssoRegion string, token *ssooidc.CreateTokenOutput, su, askUser, printOnly, gui bool) {
	awsCfg, err := discovery.BuildAWSConfig(ctx, ssoRegion, token, db.AccountID, db.RoleName, db.Region)
	if err != nil {
		fail("Error creating AWS config: %v", err)
	}
	user := getUsernameFromSTS(awsCfg)
	if user == "" {
		fail("could not read your user name from STS")
	}
	if askUser {
		su = promptTailnetSuperuser(ui.NewPrompt(), user)
	}
	if su {
		fmt.Fprintln(os.Stderr, superuserWarning(db.AccountID))
		fmt.Fprintln(os.Stderr)
		user = "su-" + user
	}
	if !db.IAMAuthEnabled {
		fmt.Fprintf(os.Stderr, "⚠️  %s is not tagged bifrost:iam-auth=true; the IAM token may be rejected.\n", db.TailnetName)
	}

	// The token is signed for the real RDS endpoint; one for the tailnet name is rejected.
	iamToken, err := auth.BuildAuthToken(ctx, fmt.Sprintf("%s:%d", db.Endpoint, db.Port), db.Region, user, awsCfg.Credentials)
	if err != nil {
		fail("Failed to generate IAM auth token: %v", err)
	}
	expires := time.Now().Add(15 * time.Minute).Format("15:04")
	conninfo := postgresConninfo(host, db.Port, user)

	if gui {
		// The token goes only to the clipboard, never to the terminal or a log.
		tokenNote := fmt.Sprintf("(copied; expires %s)", expires)
		if err := clipboard.WriteAll(iamToken); err != nil {
			tokenNote = "(clipboard unavailable; run again with --print)"
		}
		printGUIFields([][2]string{
			{"Host", host},
			{"Port", fmt.Sprintf("%d", db.Port)},
			{"User", user},
			{"Database", "postgres"},
			{"Password", tokenNote},
			{"SSL", "require"},
		})
		return
	}

	if printOnly {
		fmt.Println(postgresPrintLine(conninfo, iamToken))
		return
	}
	c, err := postgresCommand(conninfo, iamToken)
	if err != nil {
		fmt.Println(postgresPrintLine(conninfo, iamToken))
		fmt.Println("💡 psql is not installed: brew install libpq")
		return
	}
	fmt.Fprintf(os.Stderr, "🐘 %s as %s (token expires %s)\n", db.TailnetName, user, expires)
	execClient(c)
}

// mysqlArgs prompts for the root password: -p with no value. Bifrost never reads,
// fetches or passes it.
func mysqlArgs(host string, port int32) []string {
	return []string{"mysql", "-h", host, "-P", fmt.Sprintf("%d", port), "-u", "root", "-p", "--ssl-mode=REQUIRED"}
}

var errMariaDBClient = errors.New("mariadb client")

// mysqlCommand runs the MySQL client. MYSQL_PWD is dropped so a stray value
// cannot log in silently. A MariaDB client is refused, since it may reject --ssl-mode.
func mysqlCommand(host string, port int32) (clientCommand, error) {
	path, err := findClient("mysql", "mysql-client")
	if err != nil {
		return clientCommand{}, err
	}
	version, err := exec.Command(path, "--version").Output()
	if err == nil && strings.Contains(strings.ToLower(string(version)), "mariadb") {
		return clientCommand{Path: path}, errMariaDBClient
	}
	return clientCommand{
		Path: path,
		Args: mysqlArgs(host, port),
		Env:  environWithout("MYSQL_PWD"),
	}, nil
}

func connectTailnetMySQL(host string, port int32, printOnly, gui bool) {
	if gui {
		printGUIFields([][2]string{
			{"Host", host},
			{"Port", fmt.Sprintf("%d", port)},
			{"User", "root"},
			{"Password", "(the root password; Bifrost does not supply it)"},
			{"SSL", "REQUIRED"},
		})
		return
	}
	line := strings.Join(mysqlArgs(host, port), " ")
	if printOnly {
		fmt.Println(line)
		return
	}
	c, err := mysqlCommand(host, port)
	switch {
	case errors.Is(err, errMariaDBClient):
		fail("%s is a MariaDB client, which may reject --ssl-mode. Install the MySQL client: brew install mysql-client", c.Path)
	case err != nil:
		fmt.Println(line)
		fmt.Println("💡 mysql is not installed: brew install mysql-client")
		return
	}
	fmt.Fprintln(os.Stderr, "🐬 Enter the root password when mysql asks for it.")
	execClient(c)
}

func printGUIFields(fields [][2]string) {
	for _, f := range fields {
		fmt.Printf("%-9s %s\n", f[0], f[1])
	}
}
