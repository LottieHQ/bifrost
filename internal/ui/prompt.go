package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/LottieHQ/bifrost/internal/discovery"
)

// Prompt handles user interactions
type Prompt struct{}

// NewPrompt creates a new prompt handler
func NewPrompt() *Prompt {
	return &Prompt{}
}

// Select prompts the user to select from a list of items
func (p *Prompt) Select(label string, items []string) (string, error) {
	var selected string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title(label).
				Options(huh.NewOptions(items...)...).
				Value(&selected),
		),
	)

	if err := form.Run(); err != nil {
		return "", fmt.Errorf("select failed: %w", err)
	}
	return selected, nil
}

// Input prompts the user for input
func (p *Prompt) Input(label string, validate func(string) error, defaultValue ...string) (string, error) {
	var result string
	
	// Set default value if provided
	if len(defaultValue) > 0 && defaultValue[0] != "" {
		result = defaultValue[0]
	}
	
	input := huh.NewInput().
		Title(label).
		Validate(func(s string) error {
			if validate != nil {
				return validate(s)
			}
			return nil
		}).
		Value(&result)

	form := huh.NewForm(
		huh.NewGroup(input),
	)

	if err := form.Run(); err != nil {
		return "", fmt.Errorf("input failed: %w", err)
	}
	return result, nil
}

// SelectAccount prompts the user to select an AWS account
func (p *Prompt) SelectAccount(accounts *sso.ListAccountsOutput) (string, string, error) {
	accountMap := make(map[string]string)
	accountNames := make([]string, 0, len(accounts.AccountList))

	for _, acc := range accounts.AccountList {
		display := fmt.Sprintf("%s (%s)", *acc.AccountName, *acc.AccountId)
		accountNames = append(accountNames, display)
		accountMap[display] = *acc.AccountId
	}

	selected, err := p.Select("Select an AWS account", accountNames)
	if err != nil {
		return "", "", err
	}

	return selected, accountMap[selected], nil
}

const manualSetupKey = "__manual__"

var dimStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("248"))

// SelectResource presents discovered resources grouped by service type,
// plus any saved connection profiles and a "Manual setup" option.
// Returns the selected resource (nil if manual/profile chosen) and the
// selected profile name (empty if a resource or manual was chosen).
func (p *Prompt) SelectResource(resources []discovery.Resource, profiles []string) (*discovery.Resource, string, error) {
	// Sort resources: databases first, then redis, each sorted by account name then name
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].ServiceType != resources[j].ServiceType {
			return resources[i].ServiceType == "rds"
		}
		if resources[i].AccountName != resources[j].AccountName {
			return resources[i].AccountName < resources[j].AccountName
		}
		return resources[i].Name < resources[j].Name
	})

	// Build options: value is index into resources array, or special sentinel
	var options []huh.Option[string]

	// Add resources with section headers when service type changes
	var currentType string
	for i, r := range resources {
		if r.ServiceType != currentType {
			currentType = r.ServiceType
			switch currentType {
			case "rds":
				options = append(options, huh.NewOption(dimStyle.Render("── Databases ─────────────────────"), "__sep_db__"))
			case "redis":
				options = append(options, huh.NewOption(dimStyle.Render("── Redis ─────────────────────────"), "__sep_redis__"))
			}
		}
		var label string
		if r.ServiceType == "redis" {
			label = fmt.Sprintf("  🔶 %s — %s (redis:%d)", r.AccountName, r.Name, r.Port)
		} else {
			label = fmt.Sprintf("  📦 %s — %s (%s:%d)", r.AccountName, r.Name, r.Engine, r.Port)
		}
		options = append(options, huh.NewOption(label, fmt.Sprintf("resource:%d", i)))
	}

	// Add saved profiles
	if len(profiles) > 0 {
		options = append(options, huh.NewOption(dimStyle.Render("── Saved Profiles ────────────────"), "__sep_profiles__"))
		for _, name := range profiles {
			label := fmt.Sprintf("  🔗 %s", name)
			options = append(options, huh.NewOption(label, "profile:"+name))
		}
	}

	// Manual setup
	options = append(options, huh.NewOption(dimStyle.Render("──────────────────────────────────"), "__sep_manual__"))
	options = append(options, huh.NewOption("  ⚙️  Manual setup", manualSetupKey))

	for {
		var selected string
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("Select a connection (press / to filter)").
					Options(options...).
					Value(&selected),
			),
		)

		if err := form.Run(); err != nil {
			return nil, "", fmt.Errorf("select failed: %w", err)
		}

		// If a separator was selected, re-prompt
		if strings.HasPrefix(selected, "__sep_") {
			continue
		}

		// Parse selection
		if selected == manualSetupKey {
			return nil, "", nil
		}

		var idx int
		if _, err := fmt.Sscanf(selected, "resource:%d", &idx); err == nil {
			r := resources[idx]
			return &r, "", nil
		}

		var profileName string
		if _, err := fmt.Sscanf(selected, "profile:%s", &profileName); err == nil {
			return nil, profileName, nil
		}

		return nil, "", nil
	}
}

// Confirm prompts the user for a yes/no confirmation
func (p *Prompt) Confirm(label string) (bool, error) {
	var confirm bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(label).
				Affirmative("Yes!").
				Negative("No.").
				Value(&confirm),
		),
	)

	if err := form.Run(); err != nil {
		return false, fmt.Errorf("confirmation failed: %w", err)
	}
	return confirm, nil
}
