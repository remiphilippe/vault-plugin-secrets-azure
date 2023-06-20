// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	_ "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/applications"
	"github.com/microsoftgraph/msgraph-sdk-go/directory"
	"github.com/microsoftgraph/msgraph-sdk-go/groups"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
)

var _ ApplicationsClient = (*AppClient)(nil)
var _ GroupsClient = (*AppClient)(nil)
var _ ServicePrincipalClient = (*AppClient)(nil)

type AppClient struct {
	client   *msgraphsdk.GraphServiceClient
	graphURI string
}

func GetGraphCloudConfig(env string) (cloud.Configuration, error) {
	// Germany cloud is discontinued
	switch env {
	case "AzurePublicCloud", "":
		return cloud.AzurePublic, nil
	case "AzureUSGovernmentCloud":
		return cloud.AzureGovernment, nil
	case "AzureChinaCloud":
		return cloud.AzureChina, nil
	default:
		return cloud.AzurePublic, fmt.Errorf("environment '%s' unknown", env)
	}
}

// Reference: https://docs.microsoft.com/en-us/graph/deployments#microsoft-graph-and-graph-explorer-service-root-endpoints
func GetGraphURI(env string) (string, error) {
	switch env {
	case "AzurePublicCloud", "":
		return "https://graph.microsoft.com", nil
	case "AzureUSGovernmentCloud":
		return "https://graph.microsoft.us", nil
	case "AzureGermanCloud":
		return "https://graph.microsoft.de", nil
	case "AzureChinaCloud":
		return "https://microsoftgraph.chinacloudapi.cn", nil
	default:
		return "", fmt.Errorf("environment '%s' unknown", env)
	}
}

func NewMSGraphApplicationClient(subscriptionId string, userAgentExtension string, graphURI string, creds azcore.TokenCredential) (*AppClient, error) {
	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(creds, []string{"Application.ReadWrite.All"})
	if err != nil {
		return nil, err
	}

	// if userAgentExtension != "" {
	// 	err := client.AddToUserAgent(userAgentExtension)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to add extension to user agent")
	// 	}
	// }

	ac := &AppClient{
		client:   client,
		graphURI: graphURI,
	}
	return ac, nil
}

// func (c *AppClient) AddToUserAgent(extension string) error {
// 	return c.client.AddToUserAgent(extension)
// }

func azurePasswordCredentiableToPasswordCredential(cred models.PasswordCredentialable) PasswordCredential {
	keyId := cred.GetKeyId().String()
	return PasswordCredential{
		DisplayName: cred.GetDisplayName(),
		KeyID:       &keyId,
		StartDate:   cred.GetStartDateTime(),
		EndDate:     cred.GetEndDateTime(),
		SecretText:  cred.GetSecretText(),
	}
}

func azureApplicationableToApplicationResult(app models.Applicationable) ApplicationResult {
	var result ApplicationResult
	result.ID = app.GetId()
	result.AppID = app.GetAppId()

	passCreds := app.GetPasswordCredentials()
	for _, cred := range passCreds {
		passwordCreds := azurePasswordCredentiableToPasswordCredential(cred)
		result.PasswordCredentials = append(result.PasswordCredentials, &passwordCreds)
	}

	return result
}

func (c *AppClient) GetApplication(ctx context.Context, applicationObjectID string) (ApplicationResult, error) {
	req := applications.ApplicationItemRequestBuilderGetRequestConfiguration{
		QueryParameters: &applications.ApplicationItemRequestBuilderGetQueryParameters{},
	}
	app, err := c.client.Applications().ByApplicationId(applicationObjectID).Get(ctx, &req)
	if err != nil {
		return ApplicationResult{}, err
	}

	return azureApplicationableToApplicationResult(app), nil
}

type listApplicationsResponse struct {
	Value []ApplicationResult `json:"value"`
}

func (c *AppClient) ListApplications(ctx context.Context, filter string) ([]ApplicationResult, error) {
	qp := applications.ApplicationsRequestBuilderGetQueryParameters{}
	if filter != "" {
		qp.Filter = &filter
	}

	req := applications.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &qp,
	}
	resp, err := c.client.Applications().Get(ctx, &req)
	if err != nil {
		return nil, err
	}
	res := []ApplicationResult{}
	for _, v := range resp.GetValue() {
		res = append(res, azureApplicationableToApplicationResult(v))
	}

	return res, nil
}

// CreateApplication create a new Azure application object.
func (c *AppClient) CreateApplication(ctx context.Context, displayName string) (ApplicationResult, error) {
	req := applications.ApplicationsRequestBuilderPostRequestConfiguration{}
	newApp := new(models.Application)
	newApp.SetDisplayName(&displayName)

	resp, err := c.client.Applications().Post(ctx, newApp, &req)
	if err != nil {
		return ApplicationResult{}, err
	}

	return azureApplicationableToApplicationResult(resp), nil
}

// DeleteApplication deletes an Azure application object.
// This will in turn remove the service principal (but not the role assignments).
func (c *AppClient) DeleteApplication(ctx context.Context, applicationObjectID string, permanentlyDelete bool) error {
	req := applications.ApplicationItemRequestBuilderDeleteRequestConfiguration{}
	err := c.client.Applications().ByApplicationId(applicationObjectID).Delete(ctx, &req)

	if err != nil {
		return err
	}

	if permanentlyDelete {
		err = c.deleteDeletedItem(ctx, applicationObjectID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *AppClient) AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime time.Time) (PasswordCredentialResult, error) {
	req := applications.ItemAddPasswordRequestBuilderPostRequestConfiguration{}

	newPassword := new(models.PasswordCredential)
	newPassword.SetDisplayName(&displayName)
	newPassword.SetEndDateTime(&endDateTime)

	passwordReqBody := new(serviceprincipals.ItemAddPasswordPostRequestBody)
	passwordReqBody.SetPasswordCredential(newPassword)

	resp, err := c.client.Applications().ByApplicationId(applicationObjectID).AddPassword().Post(ctx, passwordReqBody, &req)
	if err != nil {
		return PasswordCredentialResult{}, err
	}

	return PasswordCredentialResult{
		PasswordCredential: azurePasswordCredentiableToPasswordCredential(resp),
	}, nil
}

func (c *AppClient) RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) error {
	req := applications.ItemRemovePasswordRequestBuilderPostRequestConfiguration{}

	passwordToRemove := new(models.PasswordCredential)
	keyUUID, err := uuid.Parse(keyID)
	if err != nil {
		return err
	}

	passwordToRemove.SetKeyId(&keyUUID)
	err = c.client.Applications().ByApplicationId(applicationObjectID).RemovePassword().Post(ctx, passwordToRemove, &req)
	if err != nil {
		return err
	}

	return nil
}

func (c AppClient) AddGroupMember(ctx context.Context, groupObjectID string, memberObjectID string) error {
	if groupObjectID == "" {
		return fmt.Errorf("missing groupObjectID")
	}

	odataId := fmt.Sprintf("%s/v1.0/directoryObjects/%s", c.graphURI, memberObjectID)
	memberReqBody := models.NewReferenceCreate()
	memberReqBody.SetOdataId(&odataId)

	req := groups.ItemMembersRefRequestBuilderPostRequestConfiguration{}
	return c.client.Groups().ByGroupId(groupObjectID).Members().Ref().Post(ctx, memberReqBody, &req)
}

func (c AppClient) RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) error {
	if groupObjectID == "" {
		return fmt.Errorf("missing groupObjectID")
	}
	if memberObjectID == "" {
		return fmt.Errorf("missing memberObjectID")
	}
	req := groups.ItemMembersItemRefRequestBuilderDeleteRequestConfiguration{}
	return c.client.Groups().ByGroupId(groupObjectID).Members().ByDirectoryObjectId(memberObjectID).Ref().Delete(ctx, &req)
}

func azureGroupableToGroup(group models.Groupable) Group {
	return Group{
		ID:          *group.GetId(),
		DisplayName: *group.GetDisplayName(),
	}
}

func (c AppClient) GetGroup(ctx context.Context, groupID string) (Group, error) {
	if groupID == "" {
		return Group{}, fmt.Errorf("missing groupID")
	}
	req := groups.GroupItemRequestBuilderGetRequestConfiguration{}
	resp, err := c.client.Groups().ByGroupId(groupID).Get(ctx, &req)
	if err != nil {
		return Group{}, err
	}

	return azureGroupableToGroup(resp), nil
}

func (c AppClient) ListGroups(ctx context.Context, filter string) ([]Group, error) {
	qp := groups.GroupsRequestBuilderGetQueryParameters{}
	if filter != "" {
		qp.Filter = &filter
	}

	req := groups.GroupsRequestBuilderGetRequestConfiguration{
		QueryParameters: &qp,
	}
	resp, err := c.client.Groups().Get(ctx, &req)
	if err != nil {
		return nil, err
	}
	res := []Group{}
	for _, v := range resp.GetValue() {
		res = append(res, azureGroupableToGroup(v))
	}

	return res, nil
}

func (c *AppClient) CreateServicePrincipal(ctx context.Context, appID string, startDate time.Time, endDate time.Time) (string, string, error) {
	spID, err := c.createServicePrincipal(ctx, appID)
	if err != nil {
		return "", "", err
	}
	password, err := c.setPasswordForServicePrincipal(ctx, spID, startDate, endDate)
	if err != nil {
		dErr := c.deleteServicePrincipal(ctx, spID)
		merr := multierror.Append(err, dErr)
		return "", "", merr.ErrorOrNil()
	}
	return spID, password, nil
}
func azureServicePrincipalableToServicePrincipal(sp models.ServicePrincipalable) ServicePrincipal {
	return ServicePrincipal{
		ObjectID: *sp.GetId(),
		AppID:    *sp.GetAppId(),
	}
}

func (c *AppClient) createServicePrincipal(ctx context.Context, appID string) (string, error) {
	req := serviceprincipals.ServicePrincipalsRequestBuilderPostRequestConfiguration{}
	newSp := new(models.ServicePrincipal)
	newSp.SetAppId(&appID)
	newSp.SetAccountEnabled(to.BoolPtr(true))

	resp, err := c.client.ServicePrincipals().Post(ctx, newSp, &req)
	if err != nil {
		return "", err
	}

	sp := azureServicePrincipalableToServicePrincipal(resp)
	return sp.ObjectID, nil
}

func (c *AppClient) setPasswordForServicePrincipal(ctx context.Context, spID string, startDate time.Time, endDate time.Time) (string, error) {
	req := serviceprincipals.ItemAddPasswordRequestBuilderPostRequestConfiguration{}

	newPassword := new(models.PasswordCredential)
	newPassword.SetStartDateTime(&startDate)
	newPassword.SetEndDateTime(&endDate)

	passwordReqBody := new(serviceprincipals.ItemAddPasswordPostRequestBody)
	passwordReqBody.SetPasswordCredential(newPassword)

	resp, err := c.client.ServicePrincipals().ByServicePrincipalId(spID).AddPassword().Post(ctx, passwordReqBody, &req)
	if err != nil {
		return "", err
	}

	passwordCredential := azurePasswordCredentiableToPasswordCredential(resp)
	return *passwordCredential.SecretText, nil
}

type createServicePrincipalResponse struct {
	ID string `json:"id"`
}

func (c *AppClient) DeleteServicePrincipal(ctx context.Context, spObjectID string, permanentlyDelete bool) error {
	err := c.deleteServicePrincipal(ctx, spObjectID)
	if err != nil {
		return err
	}

	if permanentlyDelete {
		err = c.deleteDeletedItem(ctx, spObjectID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *AppClient) deleteServicePrincipal(ctx context.Context, spID string) error {
	req := serviceprincipals.ServicePrincipalItemRequestBuilderDeleteRequestConfiguration{}

	return c.client.ServicePrincipals().ByServicePrincipalId(spID).Delete(ctx, &req)
}

func (c *AppClient) deleteDeletedItem(ctx context.Context, id string) error {
	req := directory.DeletedItemsDirectoryObjectItemRequestBuilderDeleteRequestConfiguration{}

	err := c.client.Directory().DeletedItems().ByDirectoryObjectId(id).Delete(ctx, &req)
	if err != nil {
		return err
	}
	return nil
}

func (c *AppClient) GetServicePrincipalByAppId(ctx context.Context, appId string) (string, error) {
	req := serviceprincipals.ServicePrincipalsRequestBuilderGetRequestConfiguration{}
	req.QueryParameters.Filter = to.StringPtr(fmt.Sprintf("appId eq '%s'", appId))

	resp, err := c.client.ServicePrincipals().Get(ctx, &req)
	if err != nil {
		return "", err
	}

	if len(resp.GetValue()) == 0 {
		return "", nil
	}

	return *resp.GetValue()[0].GetId(), nil
}

func (c *AppClient) GetServicePrincipal(ctx context.Context, spID string) (*ServicePrincipal, error) {
	req := serviceprincipals.ServicePrincipalItemRequestBuilderGetRequestConfiguration{}
	resp, err := c.client.ServicePrincipals().ByServicePrincipalId(spID).Get(ctx, &req)
	if err != nil {
		return nil, err
	}

	sp := azureServicePrincipalableToServicePrincipal(resp)
	if sp.ObjectID == "" {
		return nil, nil
	}
	return &sp, nil
}
