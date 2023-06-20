// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/go-autorest/autorest"
)

// AzureProvider is an interface to access underlying Azure Client objects and supporting services.
// Where practical the original function signature is preserved. Client provides higher
// level operations atop AzureProvider.
type AzureProvider interface {
	ApplicationsClient
	GroupsClient
	ServicePrincipalClient

	CreateRoleAssignment(
		ctx context.Context,
		scope string,
		roleAssignmentName string,
		parameters armauthorization.RoleAssignmentCreateParameters) (armauthorization.RoleAssignment, error)
	DeleteRoleAssignmentByID(ctx context.Context, roleID string) (armauthorization.RoleAssignment, error)

	ListRoleDefinitions(ctx context.Context, scope string, filter string) ([]armauthorization.RoleDefinition, error)
	GetRoleDefinitionByID(ctx context.Context, roleID string) (armauthorization.RoleDefinition, error)
}

type ApplicationsClient interface {
	GetApplication(ctx context.Context, applicationObjectID string) (ApplicationResult, error)
	CreateApplication(ctx context.Context, displayName string) (ApplicationResult, error)
	DeleteApplication(ctx context.Context, applicationObjectID string, permanentlyDelete bool) error
	ListApplications(ctx context.Context, filter string) ([]ApplicationResult, error)
	AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime time.Time) (PasswordCredentialResult, error)
	RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) error
}

type PasswordCredential struct {
	DisplayName *string    `json:"displayName"`
	StartDate   *time.Time `json:"startDateTime,omitempty"`
	EndDate     *time.Time `json:"endDateTime,omitempty"`
	KeyID       *string    `json:"keyId,omitempty"`
	SecretText  *string    `json:"secretText,omitempty"`
}

type PasswordCredentialResult struct {
	autorest.Response `json:"-"`

	PasswordCredential
}

type ApplicationResult struct {
	autorest.Response `json:"-"`

	AppID               *string               `json:"appId,omitempty"`
	ID                  *string               `json:"id,omitempty"`
	PasswordCredentials []*PasswordCredential `json:"passwordCredentials,omitempty"`
}
