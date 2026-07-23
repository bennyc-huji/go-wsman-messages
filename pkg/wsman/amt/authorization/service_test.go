/*********************************************************************
 * Copyright (c) Intel Corporation 2023
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package authorization

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/device-management-toolkit/go-wsman-messages/v2/internal/message"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/common"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/wsmantesting"
)

func TestJson(t *testing.T) {
	response := Response{
		Body: Body{
			GetResponse: AuthorizationOccurrence{},
		},
	}
	expectedResult := "{\"XMLName\":{\"Space\":\"\",\"Local\":\"\"},\"GetResponse\":{\"XMLName\":{\"Space\":\"\",\"Local\":\"\"},\"AllowHttpQopAuthOnly\":0,\"CreationClassName\":\"\",\"ElementName\":\"\",\"EnabledState\":0,\"Name\":\"\",\"RequestedState\":0,\"SystemCreationClassName\":\"\",\"SystemName\":\"\"},\"EnumerateResponse\":{\"EnumerationContext\":\"\"},\"PullResponse\":{\"XMLName\":{\"Space\":\"\",\"Local\":\"\"},\"AuthorizationOccurrenceItems\":null},\"SetAdminResponse\":{\"ReturnValue\":0}}"
	result := response.JSON()
	assert.Equal(t, expectedResult, result)
}

func TestYaml(t *testing.T) {
	response := Response{
		Body: Body{
			GetResponse: AuthorizationOccurrence{},
		},
	}
	expectedResult := "xmlname:\n    space: \"\"\n    local: \"\"\ngetresponse:\n    xmlname:\n        space: \"\"\n        local: \"\"\n    allowhttpqopauthonly: 0\n    creationclassname: \"\"\n    elementname: \"\"\n    enabledstate: 0\n    name: \"\"\n    requestedstate: 0\n    systemcreationclassname: \"\"\n    systemname: \"\"\nenumerateresponse:\n    enumerationcontext: \"\"\npullresponse:\n    xmlname:\n        space: \"\"\n        local: \"\"\n    authorizationoccurrenceitems: []\nsetadminresponse:\n    returnvalue: 0\n"
	result := response.YAML()
	assert.Equal(t, expectedResult, result)
}

func TestPositiveAMT_AuthorizationService(t *testing.T) {
	messageID := 0
	resourceURIBase := wsmantesting.AMTResourceURIBase
	wsmanMessageCreator := message.NewWSManMessageCreator(resourceURIBase)
	client := wsmantesting.MockClient{
		PackageUnderTest: "amt/authorization",
	}
	elementUnderTest := NewServiceWithClient(wsmanMessageCreator, &client)

	t.Run("amt_AuthorizationService Tests", func(t *testing.T) {
		tests := []struct {
			name             string
			method           string
			action           string
			body             string
			responseFunc     func() (Response, error)
			expectedResponse interface{}
		}{
			{
				"should create a valid AMT_AuthorizationService Get wsman message",
				AMTAuthorizationService,
				wsmantesting.Get,
				"",
				func() (Response, error) {
					client.CurrentMessage = wsmantesting.CurrentMessageGet

					return elementUnderTest.Get()
				},
				Body{
					XMLName: xml.Name{Space: message.XMLBodySpace, Local: "Body"},
					GetResponse: AuthorizationOccurrence{
						XMLName:                 xml.Name{Space: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService", Local: "AMT_AuthorizationService"},
						AllowHttpQopAuthOnly:    1,
						CreationClassName:       AMTAuthorizationService,
						ElementName:             "Intel(r) AMT Authorization Service",
						EnabledState:            5,
						Name:                    "Intel(r) AMT Authorization Service",
						RequestedState:          12,
						SystemCreationClassName: "CIM_ComputerSystem",
						SystemName:              "Intel(r) AMT",
					},
				},
			},

			{
				"should create a valid AMT_AuthorizationService Enumerate wsman message",
				AMTAuthorizationService,
				wsmantesting.Enumerate,
				wsmantesting.EnumerateBody,
				func() (Response, error) {
					client.CurrentMessage = wsmantesting.CurrentMessageEnumerate

					return elementUnderTest.Enumerate()
				},
				Body{
					XMLName: xml.Name{Space: message.XMLBodySpace, Local: "Body"},
					EnumerateResponse: common.EnumerateResponse{
						EnumerationContext: "5C000000-0000-0000-0000-000000000000",
					},
				},
			},
			// PULLS
			{
				"should create a valid AMT_AuthorizationService Pull wsman message",
				AMTAuthorizationService,
				wsmantesting.Pull,
				wsmantesting.PullBody,
				func() (Response, error) {
					client.CurrentMessage = wsmantesting.CurrentMessagePull

					return elementUnderTest.Pull(wsmantesting.EnumerationContext)
				},
				Body{
					XMLName: xml.Name{Space: message.XMLBodySpace, Local: "Body"},
					PullResponse: PullResponse{
						XMLName: xml.Name{Space: "http://schemas.xmlsoap.org/ws/2004/09/enumeration", Local: "PullResponse"},
						AuthorizationOccurrenceItems: []AuthorizationOccurrence{
							{
								XMLName:                 xml.Name{Space: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService", Local: "AMT_AuthorizationService"},
								AllowHttpQopAuthOnly:    1,
								CreationClassName:       AMTAuthorizationService,
								ElementName:             "Intel(r) AMT Authorization Service",
								EnabledState:            5,
								Name:                    "Intel(r) AMT Authorization Service",
								RequestedState:          12,
								SystemCreationClassName: "CIM_ComputerSystem",
								SystemName:              "Intel(r) AMT",
							},
						},
					},
				},
			},
			// AUTHORIZATION SERVICE
			{
				"should create a valid amt_AuthorizationService AddUserAclEntryEx wsman message using digest",
				AMTAuthorizationService,
				`http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService/AddUserAclEntryEx`,
				`<h:AddUserAclEntryEx_INPUT xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService"><h:AccessPermission>2</h:AccessPermission><h:DigestPassword>P@ssw0rd</h:DigestPassword><h:DigestUsername>test</h:DigestUsername><h:Realms>3</h:Realms></h:AddUserAclEntryEx_INPUT>`,
				func() (Response, error) {
					client.CurrentMessage = "AddUserAclEntryEx"
					return elementUnderTest.AddUserAclEntryEx("test", "P@ssw0rd", AccessPermissionLocalAndNetworkAccess, []RealmValues{RealmValuesPTAdministrationRealm})
				},
				Body{
					XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Body"},
					AddUserResponse: AddUserAclEntryEx_OUTPUT{
						ReturnValue: 0,
						Handle:      1,
					},
				},
			},
			{
				"should return a valid amt_AuthorizationService EnumerateUserAclEntries wsman message when startIndex is 0 (defaults to 1)",
				AMTAuthorizationService,
				`http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService/EnumerateUserAclEntries`,
				`<h:EnumerateUserAclEntries_INPUT xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService"><h:StartIndex>1</h:StartIndex></h:EnumerateUserAclEntries_INPUT>`,
				func() (Response, error) {
					client.CurrentMessage = "EnumerateUserAclEntries"
					return elementUnderTest.EnumerateUserACLEntries(0)
				},
				Body{
					XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Body"},
					EnumerateUserResponse: EnumerateUserAclEntries_OUTPUT{
						TotalCount:   2,
						HandlesCount: 2,
						Handles:      []int{1, 2},
						ReturnValue:  0,
					},
				},
			},
			{
				"should return a valid amt_AuthorizationService EnumerateUserAclEntries wsman message when startIndex is not 1",
				AMTAuthorizationService,
				`http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService/EnumerateUserAclEntries`,
				`<h:EnumerateUserAclEntries_INPUT xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService"><h:StartIndex>50</h:StartIndex></h:EnumerateUserAclEntries_INPUT>`,
				func() (Response, error) {
					client.CurrentMessage = "EnumerateUserAclEntries"
					return elementUnderTest.EnumerateUserACLEntries(50)
				},
				Body{
					XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Body"},
					EnumerateUserResponse: EnumerateUserAclEntries_OUTPUT{
						TotalCount:   2,
						HandlesCount: 2,
						Handles:      []int{1, 2},
						ReturnValue:  0,
					},
				},
			},
			{
				"should return a valid amt_AuthorizationService GetUserAclEntryEx wsman message",
				AMTAuthorizationService,
				`http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService/GetUserAclEntryEx`,
				`<h:GetUserAclEntryEx_INPUT xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService"><h:Handle>1</h:Handle></h:GetUserAclEntryEx_INPUT>`,
				func() (Response, error) {
					client.CurrentMessage = "GetUserAclEntryEx"
					return elementUnderTest.GetUserACLEntryEx(1)
				},
				Body{
					XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Body"},
					GetUserResponse: GetUserAclEntryEx_OUTPUT{
						DigestUsername:   "$$uns",
						AccessPermission: 0,
						Realms:           []RealmValues{16},
						ReturnValue:      0,
					},
				},
			},
			{
				"should return a valid amt_AuthorizationService RemoveUserAclEntry wsman message",
				AMTAuthorizationService,
				`http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService/RemoveUserAclEntry`,
				`<h:RemoveUserAclEntry_INPUT xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService"><h:Handle>1</h:Handle></h:RemoveUserAclEntry_INPUT>`,
				func() (Response, error) {
					client.CurrentMessage = "RemoveUserAclEntry"
					return elementUnderTest.RemoveUserACLEntry(1)
				},
				Body{
					XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Body"},
					RemoveUserResponse: RemoveUserAclEntry_OUTPUT{
						ReturnValue: 0,
					},
				},
			},
			{
				"should return a valid amt_AuthorizationService GetAdminAclEntry wsman message",
				AMTAuthorizationService,
				`http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService/GetAdminAclEntry`,
				`<h:GetAdminAclEntry xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService"></h:GetAdminAclEntry>`,
				func() (Response, error) {
					client.CurrentMessage = "GetAdminAclEntry"
					return elementUnderTest.GetAdminACLEntry()
				},
				Body{
					XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Body"},
					GetAdminResponse: GetAdminAclEntry_OUTPUT{
						Username:    "admin",
						ReturnValue: 0,
					},
				},
			},
			{
				"should return a valid amt_AuthorizationService GetAdminAclEntryStatus wsman message",
				AMTAuthorizationService,
				`http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService/GetAdminAclEntryStatus`,
				`<h:GetAdminAclEntryStatus xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService"></h:GetAdminAclEntryStatus>`,
				func() (Response, error) {
					client.CurrentMessage = "GetAdminAclEntryStatus"
					return elementUnderTest.GetAdminACLEntryStatus()
				},
				Body{
					XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Body"},
					GetAdminStatusResponse: GetAdminAclEntryStatus_OUTPUT{
						IsDefault:   false,
						ReturnValue: 0,
					},
				},
			},
			{
				"should return a valid amt_AuthorizationService GetAdminNetAclEntryStatus wsman message",
				AMTAuthorizationService,
				`http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService/GetAdminNetAclEntryStatus`,
				`<h:GetAdminNetAclEntryStatus xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService"></h:GetAdminNetAclEntryStatus>`,
				func() (Response, error) {
					client.CurrentMessage = "GetAdminNetAclEntryStatus"
					return elementUnderTest.GetAdminNetACLEntryStatus()
				},
				Body{
					XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Body"},
					GetAdminNetStatusResponse: GetAdminNetAclEntryStatus_OUTPUT{
						IsDefault:   false,
						ReturnValue: 0,
					},
				},
			},
			{
				"should return a valid amt_AuthorizationService GetAclEnabledState wsman message",
				AMTAuthorizationService,
				`http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService/GetAclEnabledState`,
				`<h:GetAclEnabledState_INPUT xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService"><h:Handle>1</h:Handle></h:GetAclEnabledState_INPUT>`,
				func() (Response, error) {
					client.CurrentMessage = "GetAclEnabledState"
					return elementUnderTest.GetACLEnabledState(1)
				},
				Body{
					XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Body"},
					GetACLEnabledStateResponse: GetAclEnabledState_OUTPUT{
						Enabled:     true,
						ReturnValue: 0,
					},
				},
			},
			{
				"should return a valid amt_AuthorizationService SetAclEnabledState wsman message",
				AMTAuthorizationService,
				`http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService/SetAclEnabledState`,
				`<h:SetAclEnabledState_INPUT xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService"><h:Enabled>true</h:Enabled><h:Handle>1</h:Handle></h:SetAclEnabledState_INPUT>`,
				func() (Response, error) {
					client.CurrentMessage = "SetAclEnabledState"
					return elementUnderTest.SetACLEnabledState(1, true)
				},
				Body{
					XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Body"},
					SetACLEnabledStateResponse: SetAclEnabledState_OUTPUT{
						ReturnValue: 0,
					},
				},
			},
			{
				"should return a valid amt_AuthorizationService SetAdminAclEntryEx wsman message",
				AMTAuthorizationService,
				`http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService/SetAdminAclEntryEx`,
				`<h:SetAdminAclEntryEx_INPUT xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService"><h:DigestPassword>AMviB05zT+twP2E9Tn/hPA==</h:DigestPassword><h:Username>admin</h:Username></h:SetAdminAclEntryEx_INPUT>`,
				func() (Response, error) {
					client.CurrentMessage = "SetAdminAclEntryEx"

					return elementUnderTest.SetAdminAclEntryEx("admin", "AMviB05zT+twP2E9Tn/hPA==")
				},
				Body{
					XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Body"},
					SetAdminResponse: SetAdminAclEntryEx_OUTPUT{
						ReturnValue: 0,
					},
				},
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				expectedXMLInput := wsmantesting.ExpectedResponse(messageID, resourceURIBase, test.method, test.action, "", test.body)
				messageID++
				response, err := test.responseFunc()
				assert.NoError(t, err)
				assert.Equal(t, expectedXMLInput, response.XMLInput)
				assert.Equal(t, test.expectedResponse, response.Body)
			})
		}
	})
}

func TestNegativeAMT_AuthorizationService(t *testing.T) {
	messageID := 0
	resourceURIBase := wsmantesting.AMTResourceURIBase
	wsmanMessageCreator := message.NewWSManMessageCreator(resourceURIBase)
	client := wsmantesting.MockClient{
		PackageUnderTest: "amt/authorization",
	}
	elementUnderTest := NewServiceWithClient(wsmanMessageCreator, &client)

	t.Run("amt_AuthorizationService Tests", func(t *testing.T) {
		tests := []struct {
			name             string
			method           string
			action           string
			body             string
			extraHeader      string
			responseFunc     func() (Response, error)
			expectedResponse interface{}
		}{
			{
				"should create an invalid AMT_EthernetPortSettings Get wsman message",
				"AMT_EthernetPortSettings",
				wsmantesting.Get,
				"",
				"",
				func() (Response, error) {
					client.CurrentMessage = wsmantesting.CurrentMessageError

					return elementUnderTest.Get()
				},
				Body{
					XMLName: xml.Name{Space: message.XMLBodySpace, Local: "Body"},
					GetResponse: AuthorizationOccurrence{
						XMLName:                 xml.Name{Space: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService", Local: "AMT_AuthorizationService"},
						AllowHttpQopAuthOnly:    1,
						CreationClassName:       AMTAuthorizationService,
						ElementName:             "Intel(r) AMT Authorization Service",
						EnabledState:            5,
						Name:                    "Intel(r) AMT Authorization Service",
						RequestedState:          12,
						SystemCreationClassName: "CIM_ComputerSystem",
						SystemName:              "Intel(r) AMT",
					},
				},
			},
			{
				"should create an invalid AMT_EthernetPortSettings Pull wsman message",
				"AMT_EthernetPortSettings",
				wsmantesting.Pull,
				wsmantesting.PullBody,
				"",
				func() (Response, error) {
					client.CurrentMessage = wsmantesting.CurrentMessageError

					return elementUnderTest.Pull("")
				},
				Body{
					XMLName: xml.Name{Space: message.XMLBodySpace, Local: "Body"},
					PullResponse: PullResponse{
						XMLName: xml.Name{Space: "http://schemas.xmlsoap.org/ws/2004/09/enumeration", Local: "PullResponse"},
						AuthorizationOccurrenceItems: []AuthorizationOccurrence{
							{
								XMLName:                 xml.Name{Space: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService", Local: "AMT_AuthorizationService"},
								AllowHttpQopAuthOnly:    1,
								CreationClassName:       AMTAuthorizationService,
								ElementName:             "Intel(r) AMT Authorization Service",
								EnabledState:            5,
								Name:                    "Intel(r) AMT Authorization Service",
								RequestedState:          12,
								SystemCreationClassName: "CIM_ComputerSystem",
								SystemName:              "Intel(r) AMT",
							},
						},
					},
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				expectedXMLInput := wsmantesting.ExpectedResponse(messageID, resourceURIBase, test.method, test.action, test.extraHeader, test.body)
				messageID++
				response, err := test.responseFunc()
				assert.Error(t, err)
				assert.NotEqual(t, expectedXMLInput, response.XMLInput)
				assert.NotEqual(t, test.expectedResponse, response.Body)
			})
		}
	})
}
