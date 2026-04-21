package sso

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/pkg/browser"
)

type Client struct {
	region   string
	startURL string
}

func NewClient(region, startURL string) *Client {
	return &Client{
		region:   region,
		startURL: startURL,
	}
}

func (c *Client) Authenticate(ctx context.Context) (*ssooidc.CreateTokenOutput, error) {
	cachedToken, err := LoadTokenCache(c.startURL)
	if err != nil {
		log.Printf("⚠️ Warning: Failed to load cached token: %v", err)
	}

	if cachedToken.IsFresh() {
		fmt.Println("🔄 Using cached SSO token...")
		return &ssooidc.CreateTokenOutput{
			AccessToken: aws.String(cachedToken.AccessToken),
		}, nil
	}

	ssoOidc := ssooidc.NewFromConfig(aws.Config{Region: c.region})

	if cachedToken.CanRefresh() {
		token, err := c.refreshToken(ctx, ssoOidc, cachedToken)
		if err == nil {
			fmt.Println("🔄 Refreshed SSO token...")
			return token, nil
		}
		log.Printf("⚠️ Token refresh failed, falling back to device flow: %v", err)
		if delErr := DeleteTokenCache(c.startURL); delErr != nil {
			log.Printf("⚠️ Warning: Failed to remove stale token cache: %v", delErr)
		}
	}

	return c.deviceFlow(ctx, ssoOidc)
}

func (c *Client) Reauthenticate(ctx context.Context) (*ssooidc.CreateTokenOutput, error) {
	if err := DeleteTokenCache(c.startURL); err != nil {
		log.Printf("⚠️ Warning: Failed to remove token cache: %v", err)
	}
	return c.Authenticate(ctx)
}

func IsUnauthorizedErr(err error) bool {
	if err == nil {
		return false
	}
	var ue *ssotypes.UnauthorizedException
	return errors.As(err, &ue)
}

func (c *Client) refreshToken(ctx context.Context, ssoOidc *ssooidc.Client, cached *TokenCache) (*ssooidc.CreateTokenOutput, error) {
	token, err := ssoOidc.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     aws.String(cached.ClientId),
		ClientSecret: aws.String(cached.ClientSecret),
		GrantType:    aws.String("refresh_token"),
		RefreshToken: aws.String(cached.RefreshToken),
	})
	if err != nil {
		return nil, err
	}

	c.persistToken(token, cached.ClientId, cached.ClientSecret)
	return token, nil
}

func (c *Client) deviceFlow(ctx context.Context, ssoOidc *ssooidc.Client) (*ssooidc.CreateTokenOutput, error) {
	register, err := ssoOidc.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("bifrost"),
		ClientType: aws.String("public"),
	})
	if err != nil {
		return nil, fmt.Errorf("RegisterClient: %w", err)
	}

	deviceAuth, err := ssoOidc.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     register.ClientId,
		ClientSecret: register.ClientSecret,
		StartUrl:     aws.String(c.startURL),
	})
	if err != nil {
		return nil, fmt.Errorf("StartDeviceAuthorization: %w", err)
	}

	verificationURL := *deviceAuth.VerificationUriComplete

	if err := browser.OpenURL(verificationURL); err != nil {
		fmt.Println("❌ Error opening browser:", err)
	}

	fmt.Println("\n🔐 Please complete the AWS SSO login in your browser")
	fmt.Printf("🔑 Code: %s\n", *deviceAuth.UserCode)
	fmt.Printf("🌐 URL: %s\n", verificationURL)

	maxRetries := 300
	fmt.Printf("🔄 Polling every %d seconds (timeout after %d attempts)\n\n", deviceAuth.Interval, maxRetries)

	var token *ssooidc.CreateTokenOutput
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled while waiting for token: %w", ctx.Err())
		default:
		}

		time.Sleep(time.Duration(deviceAuth.Interval) * time.Second)
		token, err = ssoOidc.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     register.ClientId,
			ClientSecret: register.ClientSecret,
			DeviceCode:   deviceAuth.DeviceCode,
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
		})
		if err == nil {
			c.persistToken(token, *register.ClientId, *register.ClientSecret)
			return token, nil
		}

		if (retryCount+1)%10 == 0 {
			fmt.Printf("⏳ Still waiting for authentication... (%d/%d attempts)\n", retryCount+1, maxRetries)
		}
	}
	return nil, fmt.Errorf("maximum retry count exceeded while waiting for token")
}

func (c *Client) persistToken(token *ssooidc.CreateTokenOutput, clientID, clientSecret string) {
	ttl := time.Duration(token.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	cache := &TokenCache{
		AccessToken:  aws.ToString(token.AccessToken),
		RefreshToken: aws.ToString(token.RefreshToken),
		ExpiresAt:    time.Now().Add(ttl),
		ClientId:     clientID,
		ClientSecret: clientSecret,
		StartUrl:     c.startURL,
		Region:       c.region,
	}
	if err := SaveTokenCache(cache); err != nil {
		log.Printf("⚠️ Warning: Failed to cache token: %v", err)
	}
}

func (c *Client) ListAccounts(ctx context.Context, token *ssooidc.CreateTokenOutput) (*sso.ListAccountsOutput, error) {
	ssoClient := sso.NewFromConfig(aws.Config{Region: c.region})
	return ssoClient.ListAccounts(ctx, &sso.ListAccountsInput{
		AccessToken: token.AccessToken,
	})
}

func (c *Client) ListAccountRoles(ctx context.Context, token *ssooidc.CreateTokenOutput, accountId string) (*sso.ListAccountRolesOutput, error) {
	ssoClient := sso.NewFromConfig(aws.Config{Region: c.region})
	return ssoClient.ListAccountRoles(ctx, &sso.ListAccountRolesInput{
		AccountId:   aws.String(accountId),
		AccessToken: token.AccessToken,
	})
}

func (c *Client) GetRoleCredentials(ctx context.Context, token *ssooidc.CreateTokenOutput, accountId, roleName string) (*sso.GetRoleCredentialsOutput, error) {
	ssoClient := sso.NewFromConfig(aws.Config{Region: c.region})
	return ssoClient.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: token.AccessToken,
		AccountId:   aws.String(accountId),
		RoleName:    aws.String(roleName),
	})
}
