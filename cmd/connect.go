/*
Copyright © 2025 Ben Szabo me@benszabo.co.uk
*/
package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"strings"

	"github.com/atotto/clipboard"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/LottieHQ/bifrost/internal/config"
	"github.com/LottieHQ/bifrost/internal/discovery"
	"github.com/LottieHQ/bifrost/internal/sso"
	"github.com/LottieHQ/bifrost/internal/ui"
	ssosdk "github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/spf13/cobra"
)

const defaultSSORegion = "us-east-1"
const defaultSSOStartURL = "https://d-906785ee68.awsapps.com/start"

// connectCmd represents the connect command
var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Initiate a connection to an AWS RDS/Redis instance",
	Long: `Initiate a connection to an AWS RDS/Redis instance through a bastion host with AWS SSM Session Manager.

For example:
bifrost connect --service rds --port 3306 --bastion-instance-id i-1234567890abcdef0`,
	Run: func(cmd *cobra.Command, args []string) {
		prompt := ui.NewPrompt()
		cfgManager := config.NewManager()

		profileFlag, _ := cmd.Flags().GetString("profile")
		ssoProfileFlag, _ := cmd.Flags().GetString("sso-profile")
		accountIdFlag, _ := cmd.Flags().GetString("account-id")
		roleNameFlag, _ := cmd.Flags().GetString("role-name")
		regionFlag, _ := cmd.Flags().GetString("region")
		serviceTypeFlag, _ := cmd.Flags().GetString("service")
		portFlag, _ := cmd.Flags().GetString("port")
		bastionInstanceIDFlag, _ := cmd.Flags().GetString("bastion-instance-id")
		keepAliveFlag, _ := cmd.Flags().GetBool("keep-alive")
		keepAliveInterval, _ := cmd.Flags().GetDuration("keep-alive-interval")
		refreshFlag, _ := cmd.Flags().GetBool("refresh")

		// Default region to eu-west-2 if not provided
		if regionFlag == "" {
			regionFlag = "eu-west-2"
		}

		// --- Profile flag: use existing profile flow directly ---
		if profileFlag != "" {
			profile, err := cfgManager.GetConnectionProfile(profileFlag)
			if err != nil {
				fmt.Printf("Error loading connection profile '%s': %v\n", profileFlag, err)
				os.Exit(1)
			}
			fmt.Printf("🔗 Using connection profile: %s\n", profileFlag)
			runProfileConnect(profile, prompt, regionFlag, keepAliveFlag, keepAliveInterval)
			return
		}

		// --- SSO authenticate (for discovery + later use) ---
		var ssoRegion string
		var ssoClient *sso.Client
		if ssoProfileFlag != "" {
			// Explicit profile override
			profile, err := cfgManager.GetSSOProfile(ssoProfileFlag)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			ssoRegion = profile.SSORegion
			ssoClient = sso.NewClient(profile.SSORegion, profile.StartURL)
		} else {
			// Default Lottie SSO endpoint
			ssoRegion = defaultSSORegion
			ssoClient = sso.NewClient(ssoRegion, defaultSSOStartURL)
		}
		ctx := context.Background()
		token, err := ssoClient.Authenticate(ctx)
		if err != nil {
			fmt.Printf("Authentication failed: %v\n", err)
			os.Exit(1)
		}

		// --- Discovery flow (unless manual flags are set) ---
		manualMode := accountIdFlag != "" || serviceTypeFlag != "" // user passed manual flags
		if !manualMode {
			accounts, err := ssoClient.ListAccounts(ctx, token)
			if err != nil {
				fmt.Printf("Error listing accounts: %v\n", err)
				os.Exit(1)
			}

			// Load or refresh discovery cache
			var resources []discovery.Resource
			if !refreshFlag {
				cache, _ := discovery.LoadCache(ssoProfileFlag)
				if discovery.IsCacheValid(cache) {
					resources = cache.Resources
				}
			}
			if resources == nil {
				fmt.Println("🔍 Discovering resources...")
				resources, err = discovery.Discover(ctx, ssoRegion, token, accounts.AccountList, regionFlag)
				if err != nil {
					fmt.Printf("Warning: discovery failed: %v\n", err)
				}
				if len(resources) > 0 {
					_ = discovery.SaveCache(ssoProfileFlag, resources)
				}
			}

			if len(resources) > 0 {
				// Get saved connection profile names
				cfg, _ := cfgManager.Load()
				var profileNames []string
				if cfg != nil {
					for name := range cfg.ConnectionProfiles {
						profileNames = append(profileNames, name)
					}
				}

				selected, selectedProfileName, err := prompt.SelectResource(resources, profileNames)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
					os.Exit(1)
				}

				// Handle saved profile selection
				if selectedProfileName != "" {
					profile, err := cfgManager.GetConnectionProfile(selectedProfileName)
					if err != nil {
						fmt.Printf("Error loading profile '%s': %v\n", selectedProfileName, err)
						os.Exit(1)
					}
					fmt.Printf("🔗 Using connection profile: %s\n", selectedProfileName)
					runProfileConnect(profile, prompt, regionFlag, keepAliveFlag, keepAliveInterval)
					return
				}

				// Handle discovered resource selection
				if selected != nil {
					runDiscoveredConnect(selected, ssoRegion, token, prompt, regionFlag, keepAliveFlag, keepAliveInterval)
					return
				}

				// Manual setup selected — fall through
			}
		}

		// --- Manual flow (existing behavior) ---
		session, err := getAWSConfigWithToken(ssoProfileFlag, ssoRegion, token, regionFlag, accountIdFlag, roleNameFlag, prompt)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		awsCfg := session.Config

		if serviceTypeFlag == "" {
			result, err := prompt.Select("Select service type", []string{"rds", "redis"})
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				return
			}
			serviceTypeFlag = result
		} else if serviceTypeFlag != "rds" && serviceTypeFlag != "redis" {
			fmt.Println("Invalid service type. Please choose either 'rds' or 'redis'.")
			return
		}
		fmt.Printf("🛠️ Service type: %s\n", serviceTypeFlag)

		if portFlag == "" {
			defaultPort := "5432"
			if serviceTypeFlag == "redis" {
				defaultPort = "6379"
			}
			result, err := prompt.Input("Enter local port to use for forwarding", validatePort, defaultPort)
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				return
			}
			portFlag = result
		} else if err := validatePort(portFlag); err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("🌐 Port: %s\n", portFlag)

		bastionInstanceIDFlag = resolveBastionID(awsCfg, bastionInstanceIDFlag, prompt)

		var endpoint string
		var port int32
		if serviceTypeFlag == "redis" {
			var clusterName string
			clusterName, err = promptForRedis(awsCfg, prompt)
			if err == nil {
				endpoint, port, err = getRedisEndpoint(awsCfg, clusterName)
			}
		} else {
			var dbName string
			dbName, err = promptForRDS(awsCfg, prompt)
			if err == nil {
				endpoint, port, err = getRDSEndpoint(awsCfg, dbName)
			}
		}
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		iamEnabled := serviceTypeFlag == "rds" && session.isKubernetesAccount()
		runConnection(awsCfg, endpoint, port, portFlag, bastionInstanceIDFlag, regionFlag, iamEnabled, session.Username, prompt, keepAliveFlag, keepAliveInterval)
	},
}

func init() {
	rootCmd.AddCommand(connectCmd)

	connectCmd.Flags().StringP("service", "s", "", "Service type (rds or redis)")
	connectCmd.Flags().StringP("port", "p", "", "Local port to use for forwarding")
	connectCmd.Flags().StringP("account-id", "a", "", "AWS account ID")
	connectCmd.Flags().StringP("role-name", "r", "", "AWS role name")
	connectCmd.Flags().String("sso-profile", "", "SSO profile to use for authentication")
	connectCmd.Flags().String("region", "", "AWS region where workloads are deployed")
	connectCmd.Flags().StringP("profile", "P", "", "Connection profile to use")
	connectCmd.Flags().String("bastion-instance-id", "", "EC2 instance ID of bastion host (required)")
	connectCmd.Flags().Bool("keep-alive", true, "Enable keep alive to maintain SSM connection")
	connectCmd.Flags().Duration("keep-alive-interval", 30*time.Second, "Interval between keep alive checks")
	connectCmd.Flags().Bool("refresh", false, "Force re-discovery of available resources (ignore cache)")
}

// runDiscoveredConnect handles connection to a discovered resource.
func runDiscoveredConnect(
	res *discovery.Resource,
	ssoRegion string,
	token *ssooidc.CreateTokenOutput,
	prompt *ui.Prompt,
	region string,
	keepAlive bool,
	keepAliveInterval time.Duration,
) {
	fmt.Printf("🪪 Account: %s\n", res.AccountName)
	fmt.Printf("🎯 %s: %s (%s)\n", res.ServiceType, res.Name, res.Engine)

	// Get credentials for the resource's account
	ctx := context.Background()
	awsCfg, err := discovery.BuildAWSConfig(ctx, ssoRegion, token, res.AccountID, res.RoleName, region)
	if err != nil {
		fmt.Printf("Error creating AWS config: %v\n", err)
		os.Exit(1)
	}

	// Prompt for local port with sensible default
	defaultPort := fmt.Sprintf("%d", res.Port)
	portFlag, err := prompt.Input("Local port", validatePort, defaultPort)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Validate bastion
	bastionID := resolveBastionID(awsCfg, res.BastionID, prompt)

	// Resolve username for IAM auth
	username := getUsernameFromSTS(awsCfg)
	iamEnabled := res.IAMAuthEnabled && res.ServiceType == "rds"

	runConnection(awsCfg, res.Endpoint, res.Port, portFlag, bastionID, region, iamEnabled, username, prompt, keepAlive, keepAliveInterval)
}

// runProfileConnect handles connection using a saved profile.
func runProfileConnect(
	profile *config.ConnectionProfile,
	prompt *ui.Prompt,
	regionFlag string,
	keepAlive bool,
	keepAliveInterval time.Duration,
) {
	ssoProfileFlag := profile.SSOProfile
	accountIdFlag := profile.AccountID
	roleNameFlag := profile.RoleName
	if profile.Region != "" {
		regionFlag = profile.Region
	}

	session, err := getAWSConfig(ssoProfileFlag, regionFlag, accountIdFlag, roleNameFlag)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	awsCfg := session.Config

	serviceType := profile.ServiceType
	portFlag := profile.Port
	bastionID := resolveBastionID(awsCfg, profile.BastionInstanceID, prompt)

	var endpoint string
	var port int32
	if serviceType == "redis" && profile.RedisClusterName != "" {
		fmt.Printf("🔗 Using Redis cluster: %s\n", profile.RedisClusterName)
		endpoint, port, err = getRedisEndpoint(awsCfg, profile.RedisClusterName)
	} else if profile.RDSInstanceName != "" {
		fmt.Printf("🔗 Using RDS instance: %s\n", profile.RDSInstanceName)
		endpoint, port, err = getRDSEndpoint(awsCfg, profile.RDSInstanceName)
	} else {
		fmt.Println("Error: profile is missing resource name")
		os.Exit(1)
	}
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	iamEnabled := serviceType == "rds" && session.isKubernetesAccount()
	runConnection(awsCfg, endpoint, port, portFlag, bastionID, regionFlag, iamEnabled, session.Username, prompt, keepAlive, keepAliveInterval)
}

// runConnection starts the SSM tunnel, waits for it to be ready, then optionally
// prompts for IAM auth and generates a token. This order makes it clear to the
// user that the tunnel is open before asking about authentication.
func runConnection(awsCfg aws.Config, endpoint string, port int32, localPort string, bastionID string, region string, iamAuthEnabled bool, username string, prompt *ui.Prompt, keepAlive bool, keepAliveInterval time.Duration) {
	// Start SSM tunnel in background
	ssmCmd, errChan, ctx, cancel, sigChan := startSSMTunnel(awsCfg, bastionID, endpoint, port, localPort, region)
	defer cancel()

	// Wait for tunnel to be ready
	fmt.Println("\n⏳ Waiting for tunnel...")
	ready := waitForTunnelReady(ctx, localPort)
	if !ready {
		fmt.Println("❌ Tunnel did not become ready within 30 seconds")
		os.Exit(1)
	}

	fmt.Printf("\n✅ Tunnel open on localhost:%s\n", localPort)
	fmt.Println()

	// Now that the tunnel is visibly open, offer IAM token generation
	if iamAuthEnabled && username != "" {
		fmt.Println("With this tunnel you can connect using any database credentials.")
		fmt.Println("This database supports IAM authentication — you can optionally")
		fmt.Println("generate a 15-minute short-lived token by selecting an option below.")
		fmt.Println()
		iamAuthUser := promptForAuthMethod(username, prompt)
		if iamAuthUser != "" {
			token, err := auth.BuildAuthToken(
				context.Background(),
				fmt.Sprintf("%s:%d", endpoint, port),
				region,
				iamAuthUser,
				awsCfg.Credentials,
			)
			if err != nil {
				fmt.Printf("❌ Failed to generate IAM auth token: %v\n", err)
			} else {
				fmt.Printf("\n🔑 IAM token for %s (expires in ~15 min):\n\n", iamAuthUser)
				safeUser := strings.ReplaceAll(iamAuthUser, "'", "'\\''")
			psqlCmd := fmt.Sprintf("PGPASSWORD='%s' psql -h localhost -p %s -U '%s' -d postgres", token, localPort, safeUser)
				fmt.Printf("  %s\n\n", psqlCmd)
				if err := clipboard.WriteAll(token); err == nil {
					fmt.Println("📋 Token copied to clipboard — use as the password in your database client")
				}
				fmt.Println()
			}
		}
	}

	fmt.Printf("📝 Press Ctrl+C to stop the connection\n\n")

	// Start keep alive
	if keepAlive {
		fmt.Printf("💓 Keep alive enabled (interval: %v)\n", keepAliveInterval)
		go startKeepAlive(ctx, localPort, keepAliveInterval)
	}

	// Wait for SSM to finish or signal
	select {
	case err := <-errChan:
		if err != nil {
			fmt.Printf("Error: SSM session ended: %v\n", err)
			os.Exit(1)
		}
	case <-sigChan:
		fmt.Println("\n🛑 Shutting down connection...")
		cancel()
		if ssmCmd.Process != nil {
			_ = ssmCmd.Process.Signal(syscall.SIGTERM)
		}
		time.Sleep(1 * time.Second)
	}
}

// startSSMTunnel launches the SSM port forwarding subprocess and returns
// the command, error channel, context, cancel func, and signal channel.
func startSSMTunnel(cfg aws.Config, instanceID, endpoint string, port int32, localPort string, region string) (*exec.Cmd, chan error, context.Context, context.CancelFunc, chan os.Signal) {
	ssmArgs := []string{
		"ssm", "start-session",
		"--target", instanceID,
		"--region", region,
		"--document-name", "AWS-StartPortForwardingSessionToRemoteHost",
		"--parameters", fmt.Sprintf("host=%s,portNumber=%d,localPortNumber=%s", endpoint, port, localPort),
	}

	cmd := exec.Command("aws", ssmArgs...)

	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		fmt.Printf("Failed to get credentials: %v\n", err)
		os.Exit(1)
	}

	cmd.Env = append(os.Environ(),
		"AWS_ACCESS_KEY_ID="+creds.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY="+creds.SecretAccessKey,
		"AWS_SESSION_TOKEN="+creds.SessionToken,
		"AWS_REGION="+region,
	)

	cmd.Stdin = os.Stdin
	cmd.Stdout = nil // suppress SSM session output (Starting session, Waiting for connections, etc.)
	cmd.Stderr = os.Stderr

	ctx, cancel := context.WithCancel(context.Background())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	errChan := make(chan error, 1)
	go func() {
		errChan <- cmd.Run()
	}()

	return cmd, errChan, ctx, cancel, sigChan
}

// waitForTunnelReady polls the local port until the SSM tunnel is accepting connections.
func waitForTunnelReady(ctx context.Context, localPort string) bool {
	for range 60 { // 30 seconds at 500ms intervals
		select {
		case <-ctx.Done():
			return false
		default:
		}
		if err := performKeepAlive(localPort); err == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
	return false
}

// promptForAuthMethod asks the user to pick IAM / IAM Admin / Password.
func promptForAuthMethod(username string, prompt *ui.Prompt) string {
	authOptions := []string{
		fmt.Sprintf("🔑 IAM (%s)", username),
		fmt.Sprintf("🔑 IAM Superuser (su-%s)", username),
		"⏭️  Skip — I'll use my own credentials",
	}
	authMethod, err := prompt.Select("Generate a token", authOptions)
	if err != nil {
		fmt.Printf("Error selecting auth method: %v\n", err)
		os.Exit(1)
	}
	switch {
	case strings.HasPrefix(authMethod, "🔑 IAM Superuser"):
		fmt.Println()
		fmt.Println("  ⚠️  ┌──────────────────────────────────────────────────────────────────────────────────────┐")
		fmt.Println("  ⚠️  │  Superuser requires the infra-aws-database-admins Google group.                      │")
		fmt.Println("  ⚠️  │  If you are not a member, a token will still be generated but the su- database       │")
		fmt.Println("  ⚠️  │  user won't exist and authentication will fail.                                      │")
		fmt.Println("  ⚠️  │                                                                                      │")
		fmt.Println("  ⚠️  │  Check: https://groups.google.com/a/lottie.org/g/infra-aws-database-admins/members   │")
		fmt.Println("  ⚠️  └──────────────────────────────────────────────────────────────────────────────────────┘")
		fmt.Println()
		confirmed, err := prompt.Confirm("Continue with superuser?")
		if err != nil || !confirmed {
			fmt.Println("Using standard IAM auth instead")
			return username
		}
		return "su-" + username
	case strings.HasPrefix(authMethod, "🔑 IAM ("):
		return username
	}
	return ""
}

// resolveBastionID validates a bastion ID or discovers one.
func resolveBastionID(awsCfg aws.Config, bastionID string, prompt *ui.Prompt) string {
	if bastionID != "" {
		if isBastionConnected(awsCfg, bastionID) {
			fmt.Printf("🏰 Using bastion: %s\n", bastionID)
			return bastionID
		}
		fmt.Printf("⚠️  Bastion %s is not connected, discovering...\n", bastionID)
	}

	instances, instanceMap, err := listSSMManagedInstances(awsCfg)
	if err != nil {
		fmt.Printf("Error listing SSM instances: %v\n", err)
		os.Exit(1)
	}
	if len(instances) == 0 {
		fmt.Println("No SSM managed instances found.")
		os.Exit(1)
	}
	if len(instances) == 1 {
		id := instanceMap[instances[0]]
		fmt.Printf("🏰 Auto-selected bastion: %s\n", instances[0])
		return id
	}
	selected, err := prompt.Select("Select bastion instance", instances)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	return instanceMap[selected]
}

// promptForRDS prompts for an RDS instance name or lists available ones.
func promptForRDS(awsCfg aws.Config, prompt *ui.Prompt) (string, error) {
	dbName, err := prompt.Input("Enter RDS DB instance name (or leave empty to browse)", nil)
	if err != nil {
		return "", err
	}
	if dbName != "" {
		return dbName, nil
	}
	instances, err := listRDSInstances(awsCfg)
	if err != nil {
		return "", err
	}
	if len(instances) == 0 {
		return "", fmt.Errorf("no RDS instances found")
	}
	return prompt.Select("Select RDS instance", instances)
}

// promptForRedis prompts for a Redis cluster name or lists available ones.
func promptForRedis(awsCfg aws.Config, prompt *ui.Prompt) (string, error) {
	clusterName, err := prompt.Input("Enter Redis cluster name (or leave empty to browse)", nil)
	if err != nil {
		return "", err
	}
	if clusterName != "" {
		return clusterName, nil
	}
	clusters, err := listRedisClusters(awsCfg)
	if err != nil {
		return "", err
	}
	if len(clusters) == 0 {
		return "", fmt.Errorf("no Redis clusters found")
	}
	return prompt.Select("Select Redis cluster", clusters)
}

// getAWSConfigWithToken uses an already-obtained SSO token to get AWS credentials.
func getAWSConfigWithToken(ssoProfileName, ssoRegion string, token *ssooidc.CreateTokenOutput, region, accountId, roleName string, prompt *ui.Prompt) (*awsSession, error) {
	ctx := context.Background()
	ssoSvc := ssosdk.NewFromConfig(aws.Config{Region: ssoRegion})

	accounts, err := ssoSvc.ListAccounts(ctx, &ssosdk.ListAccountsInput{
		AccessToken: token.AccessToken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list accounts: %v", err)
	}

	var accountName string
	if accountId == "" {
		_, accountId, err = prompt.SelectAccount(accounts)
		if err != nil {
			return nil, fmt.Errorf("failed to select account: %v", err)
		}
	}
	for _, acc := range accounts.AccountList {
		if *acc.AccountId == accountId {
			accountName = *acc.AccountName
			break
		}
	}
	fmt.Printf("🪪 Account: %s (%s)\n", accountName, accountId)

	if roleName == "" {
		roles, err := ssoSvc.ListAccountRoles(ctx, &ssosdk.ListAccountRolesInput{
			AccountId:   aws.String(accountId),
			AccessToken: token.AccessToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list roles: %v", err)
		}
		roleNames := make([]string, 0, len(roles.RoleList))
		for _, role := range roles.RoleList {
			roleNames = append(roleNames, *role.RoleName)
		}
		roleName, err = prompt.Select("Select a role", roleNames)
		if err != nil {
			return nil, fmt.Errorf("failed to select role: %v", err)
		}
	}
	fmt.Printf("👤 Role: %s\n", roleName)

	awsCfg, err := discovery.BuildAWSConfig(ctx, ssoRegion, token, accountId, roleName, region)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS config: %v", err)
	}

	return &awsSession{
		Config:      awsCfg,
		AccountID:   accountId,
		AccountName: accountName,
		RoleName:    roleName,
		Username:    getUsernameFromSTS(awsCfg),
	}, nil
}

// awsSession holds the result of SSO authentication
type awsSession struct {
	Config      aws.Config
	AccountID   string
	AccountName string
	RoleName    string
	Username    string // email from STS GetCallerIdentity (e.g. dan.williams@lottie.org)
}

// isKubernetesAccount returns true if the account name indicates a kubernetes account
func (s *awsSession) isKubernetesAccount() bool {
	return strings.Contains(strings.ToLower(s.AccountName), "kubernetes")
}

// getAWSConfig authenticates via SSO and returns an AWS session.
// It authenticates first, then delegates to getAWSConfigWithToken.
func getAWSConfig(ssoProfileName, region, accountId, roleName string) (*awsSession, error) {
	ctx := context.Background()
	cfgManager := config.NewManager()
	prompt := ui.NewPrompt()

	var ssoRegion, startURL string
	if ssoProfileName != "" {
		ssoProfile, err := cfgManager.GetSSOProfile(ssoProfileName)
		if err != nil {
			return nil, fmt.Errorf("failed to get SSO profile '%s': %v", ssoProfileName, err)
		}
		ssoRegion = ssoProfile.SSORegion
		startURL = ssoProfile.StartURL
	} else {
		ssoRegion = defaultSSORegion
		startURL = defaultSSOStartURL
	}

	ssoClient := sso.NewClient(ssoRegion, startURL)
	token, err := ssoClient.Authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %v", err)
	}

	return getAWSConfigWithToken(ssoProfileName, ssoRegion, token, region, accountId, roleName, prompt)
}

// getUsernameFromSTS extracts the username from the STS caller identity ARN.
// ARN format: arn:aws:sts::ACCOUNT:assumed-role/ROLE/username@domain.com
func getUsernameFromSTS(cfg aws.Config) string {
	stsSvc := sts.NewFromConfig(cfg)
	identity, err := stsSvc.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil || identity.Arn == nil {
		return ""
	}
	parts := strings.Split(*identity.Arn, "/")
	if len(parts) >= 3 {
		return parts[len(parts)-1]
	}
	return ""
}

// isBastionConnected checks if a bastion instance is reachable via SSM
func isBastionConnected(cfg aws.Config, instanceID string) bool {
	ssmSvc := ssm.NewFromConfig(cfg)
	result, err := ssmSvc.DescribeInstanceInformation(context.Background(), &ssm.DescribeInstanceInformationInput{
		Filters: []types.InstanceInformationStringFilter{
			{
				Key:    aws.String("InstanceIds"),
				Values: []string{instanceID},
			},
		},
	})
	if err != nil || len(result.InstanceInformationList) == 0 {
		return false
	}
	return result.InstanceInformationList[0].PingStatus == types.PingStatusOnline
}

// List all SSM managed instances that can be used as bastion hosts
func listSSMManagedInstances(cfg aws.Config) ([]string, map[string]string, error) {
	ssmSvc := ssm.NewFromConfig(cfg)
	ec2Svc := ec2.NewFromConfig(cfg)

	// Get all SSM managed instances
	ssmResult, err := ssmSvc.DescribeInstanceInformation(context.Background(), &ssm.DescribeInstanceInformationInput{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list SSM managed instances: %w", err)
	}

	if len(ssmResult.InstanceInformationList) == 0 {
		return []string{}, map[string]string{}, nil
	}

	// Get instance IDs that are online or connection lost (still manageable)
	var instanceIds []string
	for _, instance := range ssmResult.InstanceInformationList {
		if instance.InstanceId != nil &&
		   (instance.PingStatus == types.PingStatusOnline || instance.PingStatus == types.PingStatusConnectionLost) {
			instanceIds = append(instanceIds, *instance.InstanceId)
		}
	}

	if len(instanceIds) == 0 {
		return []string{}, map[string]string{}, nil
	}

	// Get EC2 instance details to fetch Name tags
	ec2Result, err := ec2Svc.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{
		InstanceIds: instanceIds,
	})
	if err != nil {
		// If EC2 call fails, just return instance IDs without names
		displayNames := make([]string, len(instanceIds))
		instanceMap := make(map[string]string)
		for i, id := range instanceIds {
			displayNames[i] = id
			instanceMap[id] = id
		}
		return displayNames, instanceMap, nil
	}

	// Build display names and mapping
	displayNames := make([]string, 0, len(instanceIds))
	instanceMap := make(map[string]string)

	for _, reservation := range ec2Result.Reservations {
		for _, instance := range reservation.Instances {
			if instance.InstanceId == nil {
				continue
			}

			instanceId := *instance.InstanceId

			// Find Name tag
			var name string
			for _, tag := range instance.Tags {
				if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
					name = *tag.Value
					break
				}
			}

			// Create display name
			var displayName string
			if name != "" {
				displayName = fmt.Sprintf("%s (%s)", name, instanceId)
			} else {
				displayName = instanceId
			}

			displayNames = append(displayNames, displayName)
			instanceMap[displayName] = instanceId
		}
	}

	return displayNames, instanceMap, nil
}

// List all RDS instances in the region
func listRDSInstances(cfg aws.Config) ([]string, error) {
	svc := rds.NewFromConfig(cfg)

	result, err := svc.DescribeDBInstances(context.Background(), &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list RDS instances: %w", err)
	}

	if len(result.DBInstances) == 0 {
		return []string{}, nil
	}

	instances := make([]string, 0, len(result.DBInstances))
	for _, db := range result.DBInstances {
		if db.DBInstanceIdentifier != nil {
			instances = append(instances, *db.DBInstanceIdentifier)
		}
	}

	return instances, nil
}

// Get the RDS database endpoint by DB instance name
func getRDSEndpoint(cfg aws.Config, dbInstanceName string) (string, int32, error) {
	if dbInstanceName == "" {
		return "", 0, fmt.Errorf("RDS instance name cannot be empty")
	}
	svc := rds.NewFromConfig(cfg)

	// Get specific DB instance by name
	result, err := svc.DescribeDBInstances(context.Background(), &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: &dbInstanceName,
	})
	if err != nil {
		return "", 0, fmt.Errorf("failed to describe DB instance '%s': %w", dbInstanceName, err)
	}

	if len(result.DBInstances) == 0 {
		return "", 0, fmt.Errorf("DB instance '%s' not found", dbInstanceName)
	}

	db := result.DBInstances[0]
	if db.Endpoint == nil {
		return "", 0, fmt.Errorf("DB instance '%s' does not have an endpoint (may not be available)", dbInstanceName)
	}

	fmt.Printf("🎯 Connecting to RDS instance: %s\n", *db.DBInstanceIdentifier)
	return *db.Endpoint.Address, int32(*db.Endpoint.Port), nil
}

// List all Redis clusters in the region
func listRedisClusters(cfg aws.Config) ([]string, error) {
	svc := elasticache.NewFromConfig(cfg)

	result, err := svc.DescribeReplicationGroups(context.Background(), &elasticache.DescribeReplicationGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list Redis clusters: %w", err)
	}

	if len(result.ReplicationGroups) == 0 {
		return []string{}, nil
	}

	clusters := make([]string, 0, len(result.ReplicationGroups))
	for _, cluster := range result.ReplicationGroups {
		if cluster.ReplicationGroupId != nil {
			clusters = append(clusters, *cluster.ReplicationGroupId)
		}
	}

	return clusters, nil
}

// Get the Redis cluster endpoint by replication group name
func getRedisEndpoint(cfg aws.Config, clusterName string) (string, int32, error) {
	if clusterName == "" {
		return "", 0, fmt.Errorf("redis cluster name cannot be empty")
	}
	svc := elasticache.NewFromConfig(cfg)

	ctx := context.Background()
	result, err := svc.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{
		ReplicationGroupId: &clusterName,
	})
	if err != nil {
		return "", 0, fmt.Errorf("failed to describe Redis cluster '%s': %w", clusterName, err)
	}

	if len(result.ReplicationGroups) == 0 {
		return "", 0, fmt.Errorf("redis cluster '%s' not found", clusterName)
	}

	cluster := result.ReplicationGroups[0]

	// Ensure NodeGroups is non-empty and PrimaryEndpoint is not nil
	if len(cluster.NodeGroups) == 0 {
		return "", 0, fmt.Errorf("redis cluster '%s' has no node groups", clusterName)
	}

	if cluster.NodeGroups[0].PrimaryEndpoint == nil {
		return "", 0, fmt.Errorf("redis cluster '%s' does not have a primary endpoint (may not be available)", clusterName)
	}

	fmt.Printf("🎯 Connecting to Redis cluster: %s\n", *cluster.ReplicationGroupId)
	return *cluster.NodeGroups[0].PrimaryEndpoint.Address, int32(*cluster.NodeGroups[0].PrimaryEndpoint.Port), nil
}

// Keep alive functionality
func startKeepAlive(ctx context.Context, localPort string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := performKeepAlive(localPort); err != nil {
				// Log error but continue - keep alive failures shouldn't stop the connection
				fmt.Printf("⚠️ Keep alive check failed: %v\n", err)
			}
		}
	}
}

// Perform a keep alive check by attempting a TCP connection to the local port
func performKeepAlive(localPort string) error {
	// Simple TCP connection test to keep the SSM tunnel alive
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%s", localPort), 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to local port %s: %w", localPort, err)
	}
	defer func() {
		_ = conn.Close() // Ignore error - this is cleanup
	}()

	// Connection successful - SSM tunnel is alive
	return nil
}

func validatePort(input string) error {
	inputPort, err := strconv.Atoi(input)
	if err != nil {
		return fmt.Errorf("invalid port number: %s", input)
	}
	if inputPort < 1 || inputPort > 65535 {
		return fmt.Errorf("port number must be between 1 and 65535")
	}
	// Check if the port is already in use
	if isPortInUse(inputPort) {
		return fmt.Errorf("port %d is already in use", inputPort)
	}
	return nil
}

func isPortInUse(port int) bool {
	conn, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return true
	}
	if err := conn.Close(); err != nil {
		// Log the error but don't affect the port check result
		fmt.Fprintf(os.Stderr, "Warning: failed to close connection: %v\n", err)
	}
	return false
}

