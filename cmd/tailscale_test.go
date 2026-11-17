package cmd

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/LottieHQ/bifrost/internal/discovery"
)

// Placeholders only: the repository is public.
const (
	testSuffix = "tailnet-0000.example"
	testToken  = "fake-iam-token-Signature=abc123"
)

// fakeClient writes an executable that prints each argument and the environment.
// --version prints versionLine, so the MySQL client check can be faked too.
func fakeClient(t *testing.T, dir, name, versionLine string) {
	t.Helper()
	// The test's PATH holds only the fakes, so the script finds env and sed itself.
	script := "#!/bin/sh\nPATH=/usr/bin:/bin\n" +
		"if [ \"$1\" = \"--version\" ]; then echo '" + versionLine + "'; exit 0; fi\n" +
		"for a in \"$@\"; do echo \"ARG:$a\"; done\n" +
		"env | sed 's/^/ENV:/'\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// runFake runs c the way execClient would, and splits the fake's output.
func runFake(t *testing.T, c clientCommand) (args, env []string) {
	t.Helper()
	run := exec.Command(c.Path, c.Args[1:]...)
	run.Env = c.Env
	out, err := run.Output()
	if err != nil {
		t.Fatalf("fake client failed: %v", err)
	}
	t.Logf("fake %s output:\n%s", c.Args[0], out)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch {
		case strings.HasPrefix(line, "ARG:"):
			args = append(args, strings.TrimPrefix(line, "ARG:"))
		case strings.HasPrefix(line, "ENV:"):
			env = append(env, strings.TrimPrefix(line, "ENV:"))
		}
	}
	return args, env
}

func TestPostgresCommandKeepsTokenOutOfArgv(t *testing.T) {
	dir := t.TempDir()
	fakeClient(t, dir, "psql", "psql (PostgreSQL) 17.0")
	t.Setenv("PATH", dir)
	t.Setenv("PGPASSWORD", "stale-value")

	conninfo := postgresConninfo("stg-example-pg."+testSuffix, 5432, "someone@example.org")
	c, err := postgresCommand(conninfo, testToken)
	if err != nil {
		t.Fatal(err)
	}
	args, env := runFake(t, c)

	if want := []string{conninfo}; !reflect.DeepEqual(args, want) {
		t.Errorf("psql argv = %q, want %q", args, want)
	}
	for _, a := range append(args, c.Args...) {
		if strings.Contains(a, testToken) {
			t.Errorf("token found in argv: %q", a)
		}
	}
	var pgpass []string
	for _, kv := range env {
		if strings.HasPrefix(kv, "PGPASSWORD=") {
			pgpass = append(pgpass, kv)
		}
	}
	if want := []string{"PGPASSWORD=" + testToken}; !reflect.DeepEqual(pgpass, want) {
		t.Errorf("child PGPASSWORD = %q, want %q", pgpass, want)
	}
	if got := os.Getenv("PGPASSWORD"); got != "stale-value" {
		t.Errorf("Bifrost's own PGPASSWORD changed to %q", got)
	}
}

func TestPostgresConninfoAndPrintLine(t *testing.T) {
	conninfo := postgresConninfo("stg-example-pg."+testSuffix, 5432, "someone@example.org")
	want := "host=stg-example-pg." + testSuffix + " port=5432 user=someone@example.org dbname=postgres sslmode=require"
	if conninfo != want {
		t.Errorf("conninfo = %q, want %q", conninfo, want)
	}
	if got, want := postgresPrintLine(conninfo, testToken), "PGPASSWORD='"+testToken+"' psql \""+want+"\""; got != want {
		t.Errorf("print line = %q, want %q", got, want)
	}
}

func TestPostgresCommandWithoutPsql(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := postgresCommand("host=x", testToken); err == nil {
		t.Error("want an error when psql is not on PATH, so the command is printed instead")
	}
}

func TestMySQLCommandPromptsForRootPassword(t *testing.T) {
	dir := t.TempDir()
	fakeClient(t, dir, "mysql", "mysql  Ver 9.0.0 for macos on arm64 (Homebrew)")
	t.Setenv("PATH", dir)
	t.Setenv("MYSQL_PWD", "stray-value")

	host := "stg-example-mysql." + testSuffix
	c, err := mysqlCommand(host, 3306)
	if err != nil {
		t.Fatal(err)
	}
	args, env := runFake(t, c)

	want := []string{"-h", host, "-P", "3306", "-u", "root", "-p", "--ssl-mode=REQUIRED"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("mysql argv = %q, want %q", args, want)
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--password") || (strings.HasPrefix(a, "-p") && a != "-p") {
			t.Errorf("mysql argv carries a password: %q", a)
		}
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "MYSQL_PWD=") {
			t.Errorf("child environment carries %q", kv)
		}
	}
}

func TestMySQLCommandRefusesMariaDB(t *testing.T) {
	dir := t.TempDir()
	fakeClient(t, dir, "mysql", "mysql  Ver 15.1 Distrib 10.11.6-MariaDB, for osx10.19 (arm64)")
	t.Setenv("PATH", dir)
	if _, err := mysqlCommand("stg-example-mysql."+testSuffix, 3306); !errors.Is(err, errMariaDBClient) {
		t.Errorf("err = %v, want errMariaDBClient", err)
	}
}

func TestParseTailscaleStatus(t *testing.T) {
	got, err := parseTailscaleStatus([]byte(`{"BackendState":"Running","MagicDNSSuffix":"` + testSuffix + `."}`))
	if err != nil || got != testSuffix {
		t.Errorf("running: got %q, %v; want %q", got, err, testSuffix)
	}
	if _, err := parseTailscaleStatus([]byte(`{"BackendState":"Stopped","MagicDNSSuffix":"` + testSuffix + `"}`)); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Errorf("stopped: err = %v, want not connected", err)
	}
	if _, err := parseTailscaleStatus([]byte(`{"BackendState":"Running"}`)); err == nil {
		t.Error("running without MagicDNS suffix: want an error")
	}
}

func TestResolveTailnetEnv(t *testing.T) {
	cases := []struct {
		flag, name, want string
		wantErr          bool
	}{
		{"", "", "", false},
		{"stg", "", "stg", false},
		{"prd", "", "prd", false},
		{"dev", "", "", true},
		{"", "stg-example-pg", "stg", false},
		{"stg", "stg-example-pg", "stg", false},
		{"prd", "stg-example-pg", "", true},
		{"", "example", "", false},
	}
	for _, c := range cases {
		got, err := resolveTailnetEnv(c.flag, c.name)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("resolveTailnetEnv(%q, %q) = %q, %v; want %q, err %v", c.flag, c.name, got, err, c.want, c.wantErr)
		}
	}
}

func testResources() []discovery.Resource {
	return []discovery.Resource{
		{Name: "untagged", Engine: "aurora-postgresql", Port: 5432},
		{Name: "b", TailnetName: "stg-example-pg", Engine: "aurora-postgresql", Port: 5432},
		{Name: "a", TailnetName: "stg-example-mysql", Engine: "mysql", Port: 3306, ServiceType: "rds-proxy"},
		{Name: "dup", TailnetName: "stg-example-pg", Engine: "aurora-postgresql", Port: 5432},
		{Name: "redis", ServiceType: "redis", Engine: "redis", Port: 6379},
	}
}

func TestTailnetDatabases(t *testing.T) {
	got := tailnetDatabases(testResources(), "stg")
	var names []string
	for _, d := range got {
		names = append(names, d.Name)
	}
	if want := []string{"a", "b"}; !reflect.DeepEqual(names, want) {
		t.Errorf("stg databases = %q, want %q (sorted by tailnet name, deduplicated, tagged only)", names, want)
	}
	if got := tailnetDatabases(testResources(), "prd"); len(got) != 0 {
		t.Errorf("prd databases = %v, want none, so the command says %q", got, prdNotOnTailnet)
	}
}

func TestEngineKind(t *testing.T) {
	for engine, want := range map[string]string{"aurora-postgresql": "postgres", "postgres": "postgres", "aurora-mysql": "mysql", "mysql": "mysql", "redis": ""} {
		if got := engineKind(engine); got != want {
			t.Errorf("engineKind(%q) = %q, want %q", engine, got, want)
		}
	}
}

// fakeDial answers only for the given host:port addresses.
func fakeDial(t *testing.T, open ...string) {
	t.Helper()
	orig := dialTCP
	t.Cleanup(func() { dialTCP = orig })
	dialTCP = func(addr string) error {
		for _, o := range open {
			if addr == o {
				return nil
			}
		}
		return errors.New("timeout")
	}
}

func TestSelectItemsNameUnreachable(t *testing.T) {
	fakeDial(t, "stg-example-pg."+testSuffix+":5432")
	dbs := tailnetDatabases(testResources(), "")
	reach := probeReachable(dbs, testSuffix)
	if !reach["stg-example-pg"] || reach["stg-example-mysql"] {
		t.Fatalf("reachability = %v, want only stg-example-pg", reach)
	}

	items, byItem, note := tailnetSelectItems(dbs, reach)
	if len(items) != 1 || !strings.HasPrefix(items[0], "stg-example-pg ") || !strings.Contains(items[0], "postgres") || !strings.HasSuffix(items[0], "stg") {
		t.Errorf("items = %q, want one line with name, engine and env", items)
	}
	if byItem[items[0]].Name != "b" {
		t.Errorf("item maps to %+v, want resource b", byItem[items[0]])
	}
	if !strings.Contains(note, "stg-example-mysql") || !strings.Contains(note, notReachableReason) {
		t.Errorf("note = %q, want it to name stg-example-mysql and the reason", note)
	}
}

func TestNamedTailnetDatabase(t *testing.T) {
	dbs := tailnetDatabases(testResources(), "stg")

	fakeDial(t)
	got, err := namedTailnetDatabase(dbs, "stg-example-pg", testSuffix)
	if err != nil || got.Name != "b" {
		t.Errorf("tagged name: got %+v, %v; want resource b", got, err)
	}
	if _, err := namedTailnetDatabase(dbs, "stg-missing", testSuffix); err == nil {
		t.Error("untagged, unreachable name: want an error")
	}

	// An untagged name answering on 3306 runs the MySQL client without AWS.
	fakeDial(t, "stg-other-mysql."+testSuffix+":3306")
	got, err = namedTailnetDatabase(dbs, "stg-other-mysql", testSuffix)
	if err != nil || engineKind(got.Engine) != "mysql" || got.Port != 3306 {
		t.Errorf("MySQL fallback: got %+v, %v; want mysql on 3306", got, err)
	}
}

func TestTailscaleCommandHidden(t *testing.T) {
	if !tailscaleCmd.Hidden {
		t.Error("tailscale must stay hidden from bifrost --help until ring 1")
	}
}

func TestWithoutServiceType(t *testing.T) {
	got := withoutServiceType(testResources(), "rds-proxy")
	for _, r := range got {
		if r.ServiceType == "rds-proxy" {
			t.Errorf("connect would list proxy endpoint %+v", r)
		}
	}
	if len(got) != len(testResources())-1 {
		t.Errorf("got %d resources, want all but the proxy endpoint", len(got))
	}
}
