<div align="center">
<h1>🌈 Bifrost </h1>
A command-line utility to simplify connecting to AWS RDS/Redis instances through bastion hosts utilising AWS SSM Session Manager.
</div>

## Features

- **Interactive Resource Discovery**: Browse and select from available AWS resources (RDS instances, Redis clusters, SSM-managed bastion hosts)
- **Direct Resource Access**: Connect to specific resources by name/ID when you know exactly what you want
- **SSO Integration**: Seamless AWS SSO authentication with token caching
- **Connection Profiles**: Save and reuse connection configurations (local or global)
- **Keep Alive**: Maintains stable connections with periodic health checks (like TablePlus)
- **Smart Filtering**: Only shows usable resources (SSM-managed instances, reachable databases)

## Installation

### Using Homebrew

Bifrost is distributed via a private Homebrew tap. Choose one of the following options:

#### Option 1: HTTPS with GitHub PAT
```bash
# Set up a GitHub PAT with repo read access
export HOMEBREW_GITHUB_API_TOKEN=your_token_here
# Add this to your shell config (~/.zshrc or ~/.bashrc) to persist

brew install LottieHQ/tap/bifrost
```

#### Option 2: SSH
```bash
brew tap LottieHQ/tap git@github.com:LottieHQ/homebrew-tap.git
brew install bifrost
```

## Quick Start

### 1. Configure SSO Profile
```bash
# Set up your AWS SSO profile
bifrost auth configure --profile work

# Login with SSO
bifrost auth login --profile work
```

### 2. Connect to Database
```bash
# Interactive mode with resource discovery (recommended)
bifrost connect
# Choose "Manual setup", then leave resource fields empty to browse available options

# Using a saved profile
bifrost connect --profile dev-rds

# Direct connection when you know the resource names
bifrost connect --service rds --port 3306 --bastion-instance-id i-1234567890abcdef0

# With custom keep alive interval
bifrost connect --profile dev-redis --keep-alive-interval 60s

# Disable keep alive
bifrost connect --profile dev-rds --keep-alive=false
```

#### 🔍 Resource Discovery
When using interactive mode, you can leave any resource field empty to browse available options:
- **Bastion Hosts**: Shows SSM-managed EC2 instances with names like "bastion-prod (i-1234567890abcdef0)"
- **RDS Instances**: Lists all RDS database instances in the selected region
- **Redis Clusters**: Shows all ElastiCache Redis clusters in the selected region

### 3. Manage Profiles
```bash
# Create a connection profile (resource names optional)
bifrost profile create --name staging-db --service rds
# Leave bastion/RDS/Redis fields empty during creation to browse during connection

# Create with specific resource names
bifrost profile create --name staging-db --service rds --bastion-id i-1234567890abcdef0

# List profiles
bifrost profile list

# Help
bifrost help
```

## How It Works

**Keep Alive**: Bifrost automatically sends lightweight health checks to your database connections (Redis `PING`, RDS `SELECT 1`) every 30 seconds by default. This prevents timeout disconnections, similar to how TablePlus maintains stable connections.

**Interactive Discovery**: When resource fields are left empty, Bifrost automatically discovers available options using AWS APIs. Only shows usable resources (SSM-managed instances for bastions, reachable databases).

**Flexible Resource Access**: Choose between browsing available resources interactively or specifying exact names/IDs when you know them. Profiles can store specific resource names or leave them empty for discovery during connection.

**Profile System**: Save connection settings locally (`.bifrost.config.yaml`) or globally (`~/.bifrost/config.yaml`). SSO profiles are always global, connection profiles can be either. Profiles can include bastion instance IDs for direct connections.
## Updating
### Using Homebrew

To update bifrost to the latest version:

1. Update Homebrew's formulae:
   ```bash
   brew update
   ```

2. Upgrade bifrost:
   ```bash
   brew upgrade bifrost
   ```


## Upcoming features

- [ ] Optional tag-based resource discovery
- [ ] Multiple simultaneous connections
- [ ] Terminal UI (TUI) interface

## Developing
### Requirements

- Go 1.24
- AWS CLI [brew install awscli](https://formulae.brew.sh/formula/awscli) or [official docs](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- AWS CLI SSM plugin [brew install --cask session-manager-plugin](https://formulae.brew.sh/cask/session-manager-plugin#default) or [official docs](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)


## Contributing

Still working out a few things, so unless for fixing a straightforward bug or updating docs, please drop me a message or open an issue before opening a PR. Thank you! 🙏🏻

## License

MIT - see [LICENSE.md](LICENSE.md)

## Acknowledgements

Inspiration taken from `aws-sso-utils` and `common-fate/granted`.

Special thanks to @diosdavid for the initial idea.
