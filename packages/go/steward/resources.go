package steward

import (
	"context"
	"net/url"
)

type CreateUserInput struct {
	TenantID       string         `json:"tenantId"`
	Email          string         `json:"email,omitempty"`
	WalletAddress  string         `json:"walletAddress,omitempty"`
	CustomMetadata map[string]any `json:"customMetadata,omitempty"`
}

type User map[string]any

type PushSubscriptionInput struct {
	Provider string         `json:"provider"`
	Token    string         `json:"token"`
	Platform string         `json:"platform,omitempty"`
	TenantID string         `json:"tenantId,omitempty"`
	DeviceID string         `json:"deviceId,omitempty"`
	AppID    string         `json:"appId,omitempty"`
	Locale   string         `json:"locale,omitempty"`
	Timezone string         `json:"timezone,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type PushSubscriptionResult struct {
	Subscription map[string]any `json:"subscription"`
}

type PushSubscriptionList struct {
	Subscriptions []map[string]any `json:"subscriptions"`
}

func (c *Client) CreateUser(ctx context.Context, input CreateUserInput) (User, error) {
	var out User
	err := c.Post(ctx, "/platform/users", input, &out)
	return out, err
}

func (c *Client) GetUser(ctx context.Context, userID string) (User, error) {
	var out User
	err := c.Get(ctx, "/platform/users/"+url.PathEscape(userID), nil, &out)
	return out, err
}

func (c *Client) LookupUser(ctx context.Context, query url.Values) (User, error) {
	var out User
	err := c.Get(ctx, "/platform/users/lookup", query, &out)
	return out, err
}

func (c *Client) ListUserPushSubscriptions(ctx context.Context) (PushSubscriptionList, error) {
	var out PushSubscriptionList
	err := c.Get(ctx, "/user/me/push-subscriptions", nil, &out)
	return out, err
}

func (c *Client) RegisterUserPushSubscription(ctx context.Context, input PushSubscriptionInput) (PushSubscriptionResult, error) {
	var out PushSubscriptionResult
	err := c.Post(ctx, "/user/me/push-subscriptions", input, &out)
	return out, err
}

func (c *Client) RevokeUserPushSubscription(ctx context.Context, subscriptionID string) (PushSubscriptionResult, error) {
	var out PushSubscriptionResult
	err := c.Delete(ctx, "/user/me/push-subscriptions/"+url.PathEscape(subscriptionID), &out)
	return out, err
}
