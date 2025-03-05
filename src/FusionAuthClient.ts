/*
* Copyright (c) 2019-2023, FusionAuth, All Rights Reserved
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
* either express or implied. See the License for the specific
* language governing permissions and limitations under the License.
*/

import IRESTClient from "./IRESTClient"
import DefaultRESTClientBuilder from "./DefaultRESTClientBuilder";
import IRESTClientBuilder from "./IRESTClientBuilder";
import ClientResponse from "./ClientResponse";
import {RequestCredentials} from "node-fetch";
import {URLSearchParams} from "url";

export class FusionAuthClient {
  public clientBuilder: IRESTClientBuilder = new DefaultRESTClientBuilder();
  public credentials: RequestCredentials;

  constructor(
    public apiKey: string,
    public host: string,
    public tenantId?: string,
  ) { }

  /**
   * Sets the tenant id, that will be included in the X-FusionAuth-TenantId header.
   *
   * @param {string | null} tenantId The value of the X-FusionAuth-TenantId header.
   * @returns {FusionAuthClient}
   */
  setTenantId(tenantId: string | null): FusionAuthClient {
    this.tenantId = tenantId;
    return this;
  }

  /**
   * Sets whether and how cookies will be sent with each request.
   *
   * @param value The value that indicates whether and how cookies will be sent.
   * @returns {FusionAuthClient}
   */
  setRequestCredentials(value: RequestCredentials): FusionAuthClient {
    this.credentials = value;
    return this;
  }

  /**
   * Takes an action on a user. The user being actioned is called the "actionee" and the user taking the action is called the
   * "actioner". Both user ids are required in the request object.
   *
   * @param {ActionRequest} request The action request that includes all the information about the action being taken including
   *    the Id of the action, any options and the duration (if applicable).
   * @returns {Promise<ClientResponse<ActionResponse>>}
   */
  actionUser(request: ActionRequest): Promise<ClientResponse<ActionResponse>> {
    return this.start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Activates the FusionAuth Reactor using a license Id and optionally a license text (for air-gapped deployments)
   *
   * @param {ReactorRequest} request An optional request that contains the license text to activate Reactor (useful for air-gap deployments of FusionAuth).
   * @returns {Promise<ClientResponse<void>>}
   */
  activateReactor(request: ReactorRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/reactor')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Adds a user to an existing family. The family Id must be specified.
   *
   * @param {UUID} familyId The Id of the family.
   * @param {FamilyRequest} request The request object that contains all the information used to determine which user to add to the family.
   * @returns {Promise<ClientResponse<FamilyResponse>>}
   */
  addUserToFamily(familyId: UUID, request: FamilyRequest): Promise<ClientResponse<FamilyResponse>> {
    return this.start<FamilyResponse, Errors>()
        .withUri('/api/user/family')
        .withUriSegment(familyId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Approve a device grant.
   *
   * @param {string} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.
   * @param {string} client_secret (Optional) The client secret. This value will be required if client authentication is enabled.
   * @param {string} token The access token used to identify the user.
   * @param {string} user_code The end-user verification code.
   * @returns {Promise<ClientResponse<DeviceApprovalResponse>>}
   */
  approveDevice(client_id: string, client_secret: string, token: string, user_code: string): Promise<ClientResponse<DeviceApprovalResponse>> {
    let body = new URLSearchParams();

    body.append('client_id', client_id);
    body.append('client_secret', client_secret);
    body.append('token', token);
    body.append('user_code', user_code);
    return this.start<DeviceApprovalResponse, Errors>()
        .withUri('/oauth2/device/approve')
        .withFormData(body)
        .withMethod("POST")
        .go();
  }

  /**
   * Cancels the user action.
   *
   * @param {UUID} actionId The action Id of the action to cancel.
   * @param {ActionRequest} request The action request that contains the information about the cancellation.
   * @returns {Promise<ClientResponse<ActionResponse>>}
   */
  cancelAction(actionId: UUID, request: ActionRequest): Promise<ClientResponse<ActionResponse>> {
    return this.start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withUriSegment(actionId)
        .withJSONBody(request)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Changes a user's password using the change password Id. This usually occurs after an email has been sent to the user
   * and they clicked on a link to reset their password.
   * 
   * As of version 1.32.2, prefer sending the changePasswordId in the request body. To do this, omit the first parameter, and set
   * the value in the request body.
   *
   * @param {string} changePasswordId The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.
   * @param {ChangePasswordRequest} request The change password request that contains all the information used to change the password.
   * @returns {Promise<ClientResponse<ChangePasswordResponse>>}
   */
  changePassword(changePasswordId: string, request: ChangePasswordRequest): Promise<ClientResponse<ChangePasswordResponse>> {
    return this.startAnonymous<ChangePasswordResponse, Errors>()
        .withUri('/api/user/change-password')
        .withUriSegment(changePasswordId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Changes a user's password using their identity (loginId and password). Using a loginId instead of the changePasswordId
   * bypasses the email verification and allows a password to be changed directly without first calling the #forgotPassword
   * method.
   *
   * @param {ChangePasswordRequest} request The change password request that contains all the information used to change the password.
   * @returns {Promise<ClientResponse<void>>}
   */
  changePasswordByIdentity(request: ChangePasswordRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user/change-password')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
   * When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
   * your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
   * 
   * An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
   *
   * @param {string} changePasswordId The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.
   * @returns {Promise<ClientResponse<void>>}
   */
  checkChangePasswordUsingId(changePasswordId: string): Promise<ClientResponse<void>> {
    return this.startAnonymous<void, Errors>()
        .withUri('/api/user/change-password')
        .withUriSegment(changePasswordId)
        .withMethod("GET")
        .go();
  }

  /**
   * Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
   * When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
   * your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
   * 
   * An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
   *
   * @param {string} encodedJWT The encoded JWT (access token).
   * @returns {Promise<ClientResponse<void>>}
   */
  checkChangePasswordUsingJWT(encodedJWT: string): Promise<ClientResponse<void>> {
    return this.startAnonymous<void, Errors>()
        .withUri('/api/user/change-password')
        .withAuthorization('Bearer ' + encodedJWT)
        .withMethod("GET")
        .go();
  }

  /**
   * Check to see if the user must obtain a Trust Request Id in order to complete a change password request.
   * When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
   * your password, you must obtain a Trust Request Id by completing a Two-Factor Step-Up authentication.
   * 
   * An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
   *
   * @param {string} loginId The loginId of the User that you intend to change the password for.
   * @returns {Promise<ClientResponse<void>>}
   */
  checkChangePasswordUsingLoginId(loginId: string): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user/change-password')
        .withParameter('username', loginId)
        .withMethod("GET")
        .go();
  }

  /**
   * Make a Client Credentials grant request to obtain an access token.
   *
   * @param {string} client_id (Optional) The client identifier. The client Id is the Id of the FusionAuth Entity in which you are attempting to authenticate.
   *    This parameter is optional when Basic Authorization is used to authenticate this request.
   * @param {string} client_secret (Optional) The client secret used to authenticate this request.
   *    This parameter is optional when Basic Authorization is used to authenticate this request.
   * @param {string} scope (Optional) This parameter is used to indicate which target entity you are requesting access. To request access to an entity, use the format target-entity:&lt;target-entity-id&gt;:&lt;roles&gt;. Roles are an optional comma separated list.
   * @returns {Promise<ClientResponse<AccessToken>>}
   */
  clientCredentialsGrant(client_id: string, client_secret: string, scope: string): Promise<ClientResponse<AccessToken>> {
    let body = new URLSearchParams();

    body.append('client_id', client_id);
    body.append('client_secret', client_secret);
    body.append('grant_type', 'client_credentials');
    body.append('scope', scope);
    return this.startAnonymous<AccessToken, OAuthError>()
        .withUri('/oauth2/token')
        .withFormData(body)
        .withMethod("POST")
        .go();
  }

  /**
   * Adds a comment to the user's account.
   *
   * @param {UserCommentRequest} request The request object that contains all the information used to create the user comment.
   * @returns {Promise<ClientResponse<UserCommentResponse>>}
   */
  commentOnUser(request: UserCommentRequest): Promise<ClientResponse<UserCommentResponse>> {
    return this.start<UserCommentResponse, Errors>()
        .withUri('/api/user/comment')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Completes verification of an identity using verification codes from the Verify Start API.
   *
   * @param {VerifySendCompleteRequest} request The identity verify complete request that contains all the information used to verify the identity.
   * @returns {Promise<ClientResponse<void>>}
   */
  completeVerifyIdentity(request: VerifySendCompleteRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/identity/verify/complete')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge without logging the user in
   *
   * @param {WebAuthnLoginRequest} request An object containing data necessary for completing the authentication ceremony
   * @returns {Promise<ClientResponse<WebAuthnAssertResponse>>}
   */
  completeWebAuthnAssertion(request: WebAuthnLoginRequest): Promise<ClientResponse<WebAuthnAssertResponse>> {
    return this.startAnonymous<WebAuthnAssertResponse, Errors>()
        .withUri('/api/webauthn/assert')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge and then login the user in
   *
   * @param {WebAuthnLoginRequest} request An object containing data necessary for completing the authentication ceremony
   * @returns {Promise<ClientResponse<LoginResponse>>}
   */
  completeWebAuthnLogin(request: WebAuthnLoginRequest): Promise<ClientResponse<LoginResponse>> {
    return this.startAnonymous<LoginResponse, Errors>()
        .withUri('/api/webauthn/login')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Complete a WebAuthn registration ceremony by validating the client request and saving the new credential
   *
   * @param {WebAuthnRegisterCompleteRequest} request An object containing data necessary for completing the registration ceremony
   * @returns {Promise<ClientResponse<WebAuthnRegisterCompleteResponse>>}
   */
  completeWebAuthnRegistration(request: WebAuthnRegisterCompleteRequest): Promise<ClientResponse<WebAuthnRegisterCompleteResponse>> {
    return this.start<WebAuthnRegisterCompleteResponse, Errors>()
        .withUri('/api/webauthn/register/complete')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates an API key. You can optionally specify a unique Id for the key, if not provided one will be generated.
   * an API key can only be created with equal or lesser authority. An API key cannot create another API key unless it is granted 
   * to that API key.
   * 
   * If an API key is locked to a tenant, it can only create API Keys for that same tenant.
   *
   * @param {UUID} keyId (Optional) The unique Id of the API key. If not provided a secure random Id will be generated.
   * @param {APIKeyRequest} request The request object that contains all the information needed to create the APIKey.
   * @returns {Promise<ClientResponse<APIKeyResponse>>}
   */
  createAPIKey(keyId: UUID, request: APIKeyRequest): Promise<ClientResponse<APIKeyResponse>> {
    return this.start<APIKeyResponse, Errors>()
        .withUri('/api/api-key')
        .withUriSegment(keyId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates an application. You can optionally specify an Id for the application, if not provided one will be generated.
   *
   * @param {UUID} applicationId (Optional) The Id to use for the application. If not provided a secure random UUID will be generated.
   * @param {ApplicationRequest} request The request object that contains all the information used to create the application.
   * @returns {Promise<ClientResponse<ApplicationResponse>>}
   */
  createApplication(applicationId: UUID, request: ApplicationRequest): Promise<ClientResponse<ApplicationResponse>> {
    return this.start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a new role for an application. You must specify the Id of the application you are creating the role for.
   * You can optionally specify an Id for the role inside the ApplicationRole object itself, if not provided one will be generated.
   *
   * @param {UUID} applicationId The Id of the application to create the role on.
   * @param {UUID} roleId (Optional) The Id of the role. If not provided a secure random UUID will be generated.
   * @param {ApplicationRequest} request The request object that contains all the information used to create the application role.
   * @returns {Promise<ClientResponse<ApplicationResponse>>}
   */
  createApplicationRole(applicationId: UUID, roleId: UUID, request: ApplicationRequest): Promise<ClientResponse<ApplicationResponse>> {
    return this.start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("role")
        .withUriSegment(roleId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates an audit log with the message and user name (usually an email). Audit logs should be written anytime you
   * make changes to the FusionAuth database. When using the FusionAuth App web interface, any changes are automatically
   * written to the audit log. However, if you are accessing the API, you must write the audit logs yourself.
   *
   * @param {AuditLogRequest} request The request object that contains all the information used to create the audit log entry.
   * @returns {Promise<ClientResponse<AuditLogResponse>>}
   */
  createAuditLog(request: AuditLogRequest): Promise<ClientResponse<AuditLogResponse>> {
    return this.start<AuditLogResponse, Errors>()
        .withUri('/api/system/audit-log')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a connector.  You can optionally specify an Id for the connector, if not provided one will be generated.
   *
   * @param {UUID} connectorId (Optional) The Id for the connector. If not provided a secure random UUID will be generated.
   * @param {ConnectorRequest} request The request object that contains all the information used to create the connector.
   * @returns {Promise<ClientResponse<ConnectorResponse>>}
   */
  createConnector(connectorId: UUID, request: ConnectorRequest): Promise<ClientResponse<ConnectorResponse>> {
    return this.start<ConnectorResponse, Errors>()
        .withUri('/api/connector')
        .withUriSegment(connectorId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a user consent type. You can optionally specify an Id for the consent type, if not provided one will be generated.
   *
   * @param {UUID} consentId (Optional) The Id for the consent. If not provided a secure random UUID will be generated.
   * @param {ConsentRequest} request The request object that contains all the information used to create the consent.
   * @returns {Promise<ClientResponse<ConsentResponse>>}
   */
  createConsent(consentId: UUID, request: ConsentRequest): Promise<ClientResponse<ConsentResponse>> {
    return this.start<ConsentResponse, Errors>()
        .withUri('/api/consent')
        .withUriSegment(consentId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates an email template. You can optionally specify an Id for the template, if not provided one will be generated.
   *
   * @param {UUID} emailTemplateId (Optional) The Id for the template. If not provided a secure random UUID will be generated.
   * @param {EmailTemplateRequest} request The request object that contains all the information used to create the email template.
   * @returns {Promise<ClientResponse<EmailTemplateResponse>>}
   */
  createEmailTemplate(emailTemplateId: UUID, request: EmailTemplateRequest): Promise<ClientResponse<EmailTemplateResponse>> {
    return this.start<EmailTemplateResponse, Errors>()
        .withUri('/api/email/template')
        .withUriSegment(emailTemplateId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates an Entity. You can optionally specify an Id for the Entity. If not provided one will be generated.
   *
   * @param {UUID} entityId (Optional) The Id for the Entity. If not provided a secure random UUID will be generated.
   * @param {EntityRequest} request The request object that contains all the information used to create the Entity.
   * @returns {Promise<ClientResponse<EntityResponse>>}
   */
  createEntity(entityId: UUID, request: EntityRequest): Promise<ClientResponse<EntityResponse>> {
    return this.start<EntityResponse, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a Entity Type. You can optionally specify an Id for the Entity Type, if not provided one will be generated.
   *
   * @param {UUID} entityTypeId (Optional) The Id for the Entity Type. If not provided a secure random UUID will be generated.
   * @param {EntityTypeRequest} request The request object that contains all the information used to create the Entity Type.
   * @returns {Promise<ClientResponse<EntityTypeResponse>>}
   */
  createEntityType(entityTypeId: UUID, request: EntityTypeRequest): Promise<ClientResponse<EntityTypeResponse>> {
    return this.start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a new permission for an entity type. You must specify the Id of the entity type you are creating the permission for.
   * You can optionally specify an Id for the permission inside the EntityTypePermission object itself, if not provided one will be generated.
   *
   * @param {UUID} entityTypeId The Id of the entity type to create the permission on.
   * @param {UUID} permissionId (Optional) The Id of the permission. If not provided a secure random UUID will be generated.
   * @param {EntityTypeRequest} request The request object that contains all the information used to create the permission.
   * @returns {Promise<ClientResponse<EntityTypeResponse>>}
   */
  createEntityTypePermission(entityTypeId: UUID, permissionId: UUID, request: EntityTypeRequest): Promise<ClientResponse<EntityTypeResponse>> {
    return this.start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withUriSegment("permission")
        .withUriSegment(permissionId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a family with the user Id in the request as the owner and sole member of the family. You can optionally specify an Id for the
   * family, if not provided one will be generated.
   *
   * @param {UUID} familyId (Optional) The Id for the family. If not provided a secure random UUID will be generated.
   * @param {FamilyRequest} request The request object that contains all the information used to create the family.
   * @returns {Promise<ClientResponse<FamilyResponse>>}
   */
  createFamily(familyId: UUID, request: FamilyRequest): Promise<ClientResponse<FamilyResponse>> {
    return this.start<FamilyResponse, Errors>()
        .withUri('/api/user/family')
        .withUriSegment(familyId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a form.  You can optionally specify an Id for the form, if not provided one will be generated.
   *
   * @param {UUID} formId (Optional) The Id for the form. If not provided a secure random UUID will be generated.
   * @param {FormRequest} request The request object that contains all the information used to create the form.
   * @returns {Promise<ClientResponse<FormResponse>>}
   */
  createForm(formId: UUID, request: FormRequest): Promise<ClientResponse<FormResponse>> {
    return this.start<FormResponse, Errors>()
        .withUri('/api/form')
        .withUriSegment(formId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a form field.  You can optionally specify an Id for the form, if not provided one will be generated.
   *
   * @param {UUID} fieldId (Optional) The Id for the form field. If not provided a secure random UUID will be generated.
   * @param {FormFieldRequest} request The request object that contains all the information used to create the form field.
   * @returns {Promise<ClientResponse<FormFieldResponse>>}
   */
  createFormField(fieldId: UUID, request: FormFieldRequest): Promise<ClientResponse<FormFieldResponse>> {
    return this.start<FormFieldResponse, Errors>()
        .withUri('/api/form/field')
        .withUriSegment(fieldId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a group. You can optionally specify an Id for the group, if not provided one will be generated.
   *
   * @param {UUID} groupId (Optional) The Id for the group. If not provided a secure random UUID will be generated.
   * @param {GroupRequest} request The request object that contains all the information used to create the group.
   * @returns {Promise<ClientResponse<GroupResponse>>}
   */
  createGroup(groupId: UUID, request: GroupRequest): Promise<ClientResponse<GroupResponse>> {
    return this.start<GroupResponse, Errors>()
        .withUri('/api/group')
        .withUriSegment(groupId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a member in a group.
   *
   * @param {MemberRequest} request The request object that contains all the information used to create the group member(s).
   * @returns {Promise<ClientResponse<MemberResponse>>}
   */
  createGroupMembers(request: MemberRequest): Promise<ClientResponse<MemberResponse>> {
    return this.start<MemberResponse, Errors>()
        .withUri('/api/group/member')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates an IP Access Control List. You can optionally specify an Id on this create request, if one is not provided one will be generated.
   *
   * @param {UUID} accessControlListId (Optional) The Id for the IP Access Control List. If not provided a secure random UUID will be generated.
   * @param {IPAccessControlListRequest} request The request object that contains all the information used to create the IP Access Control List.
   * @returns {Promise<ClientResponse<IPAccessControlListResponse>>}
   */
  createIPAccessControlList(accessControlListId: UUID, request: IPAccessControlListRequest): Promise<ClientResponse<IPAccessControlListResponse>> {
    return this.start<IPAccessControlListResponse, Errors>()
        .withUri('/api/ip-acl')
        .withUriSegment(accessControlListId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates an identity provider. You can optionally specify an Id for the identity provider, if not provided one will be generated.
   *
   * @param {UUID} identityProviderId (Optional) The Id of the identity provider. If not provided a secure random UUID will be generated.
   * @param {IdentityProviderRequest} request The request object that contains all the information used to create the identity provider.
   * @returns {Promise<ClientResponse<IdentityProviderResponse>>}
   */
  createIdentityProvider(identityProviderId: UUID, request: IdentityProviderRequest): Promise<ClientResponse<IdentityProviderResponse>> {
    return this.start<IdentityProviderResponse, Errors>()
        .withUri('/api/identity-provider')
        .withUriSegment(identityProviderId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a Lambda. You can optionally specify an Id for the lambda, if not provided one will be generated.
   *
   * @param {UUID} lambdaId (Optional) The Id for the lambda. If not provided a secure random UUID will be generated.
   * @param {LambdaRequest} request The request object that contains all the information used to create the lambda.
   * @returns {Promise<ClientResponse<LambdaResponse>>}
   */
  createLambda(lambdaId: UUID, request: LambdaRequest): Promise<ClientResponse<LambdaResponse>> {
    return this.start<LambdaResponse, Errors>()
        .withUri('/api/lambda')
        .withUriSegment(lambdaId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates an message template. You can optionally specify an Id for the template, if not provided one will be generated.
   *
   * @param {UUID} messageTemplateId (Optional) The Id for the template. If not provided a secure random UUID will be generated.
   * @param {MessageTemplateRequest} request The request object that contains all the information used to create the message template.
   * @returns {Promise<ClientResponse<MessageTemplateResponse>>}
   */
  createMessageTemplate(messageTemplateId: UUID, request: MessageTemplateRequest): Promise<ClientResponse<MessageTemplateResponse>> {
    return this.start<MessageTemplateResponse, Errors>()
        .withUri('/api/message/template')
        .withUriSegment(messageTemplateId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a messenger.  You can optionally specify an Id for the messenger, if not provided one will be generated.
   *
   * @param {UUID} messengerId (Optional) The Id for the messenger. If not provided a secure random UUID will be generated.
   * @param {MessengerRequest} request The request object that contains all the information used to create the messenger.
   * @returns {Promise<ClientResponse<MessengerResponse>>}
   */
  createMessenger(messengerId: UUID, request: MessengerRequest): Promise<ClientResponse<MessengerResponse>> {
    return this.start<MessengerResponse, Errors>()
        .withUri('/api/messenger')
        .withUriSegment(messengerId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a new custom OAuth scope for an application. You must specify the Id of the application you are creating the scope for.
   * You can optionally specify an Id for the OAuth scope on the URL, if not provided one will be generated.
   *
   * @param {UUID} applicationId The Id of the application to create the OAuth scope on.
   * @param {UUID} scopeId (Optional) The Id of the OAuth scope. If not provided a secure random UUID will be generated.
   * @param {ApplicationOAuthScopeRequest} request The request object that contains all the information used to create the OAuth OAuth scope.
   * @returns {Promise<ClientResponse<ApplicationOAuthScopeResponse>>}
   */
  createOAuthScope(applicationId: UUID, scopeId: UUID, request: ApplicationOAuthScopeRequest): Promise<ClientResponse<ApplicationOAuthScopeResponse>> {
    return this.start<ApplicationOAuthScopeResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("scope")
        .withUriSegment(scopeId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a tenant. You can optionally specify an Id for the tenant, if not provided one will be generated.
   *
   * @param {UUID} tenantId (Optional) The Id for the tenant. If not provided a secure random UUID will be generated.
   * @param {TenantRequest} request The request object that contains all the information used to create the tenant.
   * @returns {Promise<ClientResponse<TenantResponse>>}
   */
  createTenant(tenantId: UUID, request: TenantRequest): Promise<ClientResponse<TenantResponse>> {
    return this.start<TenantResponse, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a Theme. You can optionally specify an Id for the theme, if not provided one will be generated.
   *
   * @param {UUID} themeId (Optional) The Id for the theme. If not provided a secure random UUID will be generated.
   * @param {ThemeRequest} request The request object that contains all the information used to create the theme.
   * @returns {Promise<ClientResponse<ThemeResponse>>}
   */
  createTheme(themeId: UUID, request: ThemeRequest): Promise<ClientResponse<ThemeResponse>> {
    return this.start<ThemeResponse, Errors>()
        .withUri('/api/theme')
        .withUriSegment(themeId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a user. You can optionally specify an Id for the user, if not provided one will be generated.
   *
   * @param {UUID} userId (Optional) The Id for the user. If not provided a secure random UUID will be generated.
   * @param {UserRequest} request The request object that contains all the information used to create the user.
   * @returns {Promise<ClientResponse<UserResponse>>}
   */
  createUser(userId: UUID, request: UserRequest): Promise<ClientResponse<UserResponse>> {
    return this.start<UserResponse, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a user action. This action cannot be taken on a user until this call successfully returns. Anytime after
   * that the user action can be applied to any user.
   *
   * @param {UUID} userActionId (Optional) The Id for the user action. If not provided a secure random UUID will be generated.
   * @param {UserActionRequest} request The request object that contains all the information used to create the user action.
   * @returns {Promise<ClientResponse<UserActionResponse>>}
   */
  createUserAction(userActionId: UUID, request: UserActionRequest): Promise<ClientResponse<UserActionResponse>> {
    return this.start<UserActionResponse, Errors>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a user reason. This user action reason cannot be used when actioning a user until this call completes
   * successfully. Anytime after that the user action reason can be used.
   *
   * @param {UUID} userActionReasonId (Optional) The Id for the user action reason. If not provided a secure random UUID will be generated.
   * @param {UserActionReasonRequest} request The request object that contains all the information used to create the user action reason.
   * @returns {Promise<ClientResponse<UserActionReasonResponse>>}
   */
  createUserActionReason(userActionReasonId: UUID, request: UserActionReasonRequest): Promise<ClientResponse<UserActionReasonResponse>> {
    return this.start<UserActionReasonResponse, Errors>()
        .withUri('/api/user-action-reason')
        .withUriSegment(userActionReasonId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a single User consent.
   *
   * @param {UUID} userConsentId (Optional) The Id for the User consent. If not provided a secure random UUID will be generated.
   * @param {UserConsentRequest} request The request that contains the user consent information.
   * @returns {Promise<ClientResponse<UserConsentResponse>>}
   */
  createUserConsent(userConsentId: UUID, request: UserConsentRequest): Promise<ClientResponse<UserConsentResponse>> {
    return this.start<UserConsentResponse, Errors>()
        .withUri('/api/user/consent')
        .withUriSegment(userConsentId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Link an external user from a 3rd party identity provider to a FusionAuth user.
   *
   * @param {IdentityProviderLinkRequest} request The request object that contains all the information used to link the FusionAuth user.
   * @returns {Promise<ClientResponse<IdentityProviderLinkResponse>>}
   */
  createUserLink(request: IdentityProviderLinkRequest): Promise<ClientResponse<IdentityProviderLinkResponse>> {
    return this.start<IdentityProviderLinkResponse, Errors>()
        .withUri('/api/identity-provider/link')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Creates a webhook. You can optionally specify an Id for the webhook, if not provided one will be generated.
   *
   * @param {UUID} webhookId (Optional) The Id for the webhook. If not provided a secure random UUID will be generated.
   * @param {WebhookRequest} request The request object that contains all the information used to create the webhook.
   * @returns {Promise<ClientResponse<WebhookResponse>>}
   */
  createWebhook(webhookId: UUID, request: WebhookRequest): Promise<ClientResponse<WebhookResponse>> {
    return this.start<WebhookResponse, Errors>()
        .withUri('/api/webhook')
        .withUriSegment(webhookId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Deactivates the application with the given Id.
   *
   * @param {UUID} applicationId The Id of the application to deactivate.
   * @returns {Promise<ClientResponse<void>>}
   */
  deactivateApplication(applicationId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deactivates the FusionAuth Reactor.
   *
   * @returns {Promise<ClientResponse<void>>}
   */
  deactivateReactor(): Promise<ClientResponse<void>> {
    return this.start<void, void>()
        .withUri('/api/reactor')
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deactivates the user with the given Id.
   *
   * @param {UUID} userId The Id of the user to deactivate.
   * @returns {Promise<ClientResponse<void>>}
   */
  deactivateUser(userId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deactivates the user action with the given Id.
   *
   * @param {UUID} userActionId The Id of the user action to deactivate.
   * @returns {Promise<ClientResponse<void>>}
   */
  deactivateUserAction(userActionId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deactivates the users with the given ids.
   *
   * @param {Array<string>} userIds The ids of the users to deactivate.
   * @returns {Promise<ClientResponse<UserDeleteResponse>>}
   *
   * @deprecated This method has been renamed to deactivateUsersByIds, use that method instead.
   */
  deactivateUsers(userIds: Array<string>): Promise<ClientResponse<UserDeleteResponse>> {
    return this.start<UserDeleteResponse, Errors>()
        .withUri('/api/user/bulk')
        .withParameter('userId', userIds)
        .withParameter('dryRun', false)
        .withParameter('hardDelete', false)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deactivates the users with the given ids.
   *
   * @param {Array<string>} userIds The ids of the users to deactivate.
   * @returns {Promise<ClientResponse<UserDeleteResponse>>}
   */
  deactivateUsersByIds(userIds: Array<string>): Promise<ClientResponse<UserDeleteResponse>> {
    return this.start<UserDeleteResponse, Errors>()
        .withUri('/api/user/bulk')
        .withParameter('userId', userIds)
        .withParameter('dryRun', false)
        .withParameter('hardDelete', false)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the API key for the given Id.
   *
   * @param {UUID} keyId The Id of the authentication API key to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteAPIKey(keyId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/api-key')
        .withUriSegment(keyId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Hard deletes an application. This is a dangerous operation and should not be used in most circumstances. This will
   * delete the application, any registrations for that application, metrics and reports for the application, all the
   * roles for the application, and any other data associated with the application. This operation could take a very
   * long time, depending on the amount of data in your database.
   *
   * @param {UUID} applicationId The Id of the application to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteApplication(applicationId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withParameter('hardDelete', true)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Hard deletes an application role. This is a dangerous operation and should not be used in most circumstances. This
   * permanently removes the given role from all users that had it.
   *
   * @param {UUID} applicationId The Id of the application that the role belongs to.
   * @param {UUID} roleId The Id of the role to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteApplicationRole(applicationId: UUID, roleId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("role")
        .withUriSegment(roleId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the connector for the given Id.
   *
   * @param {UUID} connectorId The Id of the connector to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteConnector(connectorId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/connector')
        .withUriSegment(connectorId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the consent for the given Id.
   *
   * @param {UUID} consentId The Id of the consent to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteConsent(consentId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/consent')
        .withUriSegment(consentId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the email template for the given Id.
   *
   * @param {UUID} emailTemplateId The Id of the email template to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteEmailTemplate(emailTemplateId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/email/template')
        .withUriSegment(emailTemplateId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the Entity for the given Id.
   *
   * @param {UUID} entityId The Id of the Entity to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteEntity(entityId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes an Entity Grant for the given User or Entity.
   *
   * @param {UUID} entityId The Id of the Entity that the Entity Grant is being deleted for.
   * @param {UUID} recipientEntityId (Optional) The Id of the Entity that the Entity Grant is for.
   * @param {UUID} userId (Optional) The Id of the User that the Entity Grant is for.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteEntityGrant(entityId: UUID, recipientEntityId: UUID, userId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withUriSegment("grant")
        .withParameter('recipientEntityId', recipientEntityId)
        .withParameter('userId', userId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the Entity Type for the given Id.
   *
   * @param {UUID} entityTypeId The Id of the Entity Type to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteEntityType(entityTypeId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Hard deletes a permission. This is a dangerous operation and should not be used in most circumstances. This
   * permanently removes the given permission from all grants that had it.
   *
   * @param {UUID} entityTypeId The Id of the entityType the the permission belongs to.
   * @param {UUID} permissionId The Id of the permission to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteEntityTypePermission(entityTypeId: UUID, permissionId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withUriSegment("permission")
        .withUriSegment(permissionId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the form for the given Id.
   *
   * @param {UUID} formId The Id of the form to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteForm(formId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/form')
        .withUriSegment(formId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the form field for the given Id.
   *
   * @param {UUID} fieldId The Id of the form field to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteFormField(fieldId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/form/field')
        .withUriSegment(fieldId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the group for the given Id.
   *
   * @param {UUID} groupId The Id of the group to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteGroup(groupId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/group')
        .withUriSegment(groupId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Removes users as members of a group.
   *
   * @param {MemberDeleteRequest} request The member request that contains all the information used to remove members to the group.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteGroupMembers(request: MemberDeleteRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/group/member')
        .withJSONBody(request)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the IP Access Control List for the given Id.
   *
   * @param {UUID} ipAccessControlListId The Id of the IP Access Control List to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteIPAccessControlList(ipAccessControlListId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/ip-acl')
        .withUriSegment(ipAccessControlListId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the identity provider for the given Id.
   *
   * @param {UUID} identityProviderId The Id of the identity provider to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteIdentityProvider(identityProviderId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/identity-provider')
        .withUriSegment(identityProviderId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the key for the given Id.
   *
   * @param {UUID} keyId The Id of the key to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteKey(keyId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/key')
        .withUriSegment(keyId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the lambda for the given Id.
   *
   * @param {UUID} lambdaId The Id of the lambda to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteLambda(lambdaId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/lambda')
        .withUriSegment(lambdaId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the message template for the given Id.
   *
   * @param {UUID} messageTemplateId The Id of the message template to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteMessageTemplate(messageTemplateId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/message/template')
        .withUriSegment(messageTemplateId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the messenger for the given Id.
   *
   * @param {UUID} messengerId The Id of the messenger to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteMessenger(messengerId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/messenger')
        .withUriSegment(messengerId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Hard deletes a custom OAuth scope.
   * OAuth workflows that are still requesting the deleted OAuth scope may fail depending on the application's unknown scope policy.
   *
   * @param {UUID} applicationId The Id of the application that the OAuth scope belongs to.
   * @param {UUID} scopeId The Id of the OAuth scope to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteOAuthScope(applicationId: UUID, scopeId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("scope")
        .withUriSegment(scopeId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the user registration for the given user and application.
   *
   * @param {UUID} userId The Id of the user whose registration is being deleted.
   * @param {UUID} applicationId The Id of the application to remove the registration for.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteRegistration(userId: UUID, applicationId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user/registration')
        .withUriSegment(userId)
        .withUriSegment(applicationId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the user registration for the given user and application along with the given JSON body that contains the event information.
   *
   * @param {UUID} userId The Id of the user whose registration is being deleted.
   * @param {UUID} applicationId The Id of the application to remove the registration for.
   * @param {RegistrationDeleteRequest} request The request body that contains the event information.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteRegistrationWithRequest(userId: UUID, applicationId: UUID, request: RegistrationDeleteRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user/registration')
        .withUriSegment(userId)
        .withUriSegment(applicationId)
        .withJSONBody(request)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the tenant based on the given Id on the URL. This permanently deletes all information, metrics, reports and data associated
   * with the tenant and everything under the tenant (applications, users, etc).
   *
   * @param {UUID} tenantId The Id of the tenant to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteTenant(tenantId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the tenant for the given Id asynchronously.
   * This method is helpful if you do not want to wait for the delete operation to complete.
   *
   * @param {UUID} tenantId The Id of the tenant to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteTenantAsync(tenantId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withParameter('async', true)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the tenant based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
   * with the tenant and everything under the tenant (applications, users, etc).
   *
   * @param {UUID} tenantId The Id of the tenant to delete.
   * @param {TenantDeleteRequest} request The request object that contains all the information used to delete the user.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteTenantWithRequest(tenantId: UUID, request: TenantDeleteRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withJSONBody(request)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the theme for the given Id.
   *
   * @param {UUID} themeId The Id of the theme to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteTheme(themeId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/theme')
        .withUriSegment(themeId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the user for the given Id. This permanently deletes all information, metrics, reports and data associated
   * with the user.
   *
   * @param {UUID} userId The Id of the user to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteUser(userId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withParameter('hardDelete', true)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the user action for the given Id. This permanently deletes the user action and also any history and logs of
   * the action being applied to any users.
   *
   * @param {UUID} userActionId The Id of the user action to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteUserAction(userActionId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withParameter('hardDelete', true)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the user action reason for the given Id.
   *
   * @param {UUID} userActionReasonId The Id of the user action reason to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteUserActionReason(userActionReasonId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user-action-reason')
        .withUriSegment(userActionReasonId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Remove an existing link that has been made from a 3rd party identity provider to a FusionAuth user.
   *
   * @param {UUID} identityProviderId The unique Id of the identity provider.
   * @param {string} identityProviderUserId The unique Id of the user in the 3rd party identity provider to unlink.
   * @param {UUID} userId The unique Id of the FusionAuth user to unlink.
   * @returns {Promise<ClientResponse<IdentityProviderLinkResponse>>}
   */
  deleteUserLink(identityProviderId: UUID, identityProviderUserId: string, userId: UUID): Promise<ClientResponse<IdentityProviderLinkResponse>> {
    return this.start<IdentityProviderLinkResponse, Errors>()
        .withUri('/api/identity-provider/link')
        .withParameter('identityProviderId', identityProviderId)
        .withParameter('identityProviderUserId', identityProviderUserId)
        .withParameter('userId', userId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the user based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
   * with the user.
   *
   * @param {UUID} userId The Id of the user to delete (required).
   * @param {UserDeleteSingleRequest} request The request object that contains all the information used to delete the user.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteUserWithRequest(userId: UUID, request: UserDeleteSingleRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the users with the given ids, or users matching the provided JSON query or queryString.
   * The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
   * 
   * This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
   * Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
   *
   * @param {UserDeleteRequest} request The UserDeleteRequest.
   * @returns {Promise<ClientResponse<UserDeleteResponse>>}
   *
   * @deprecated This method has been renamed to deleteUsersByQuery, use that method instead.
   */
  deleteUsers(request: UserDeleteRequest): Promise<ClientResponse<UserDeleteResponse>> {
    return this.start<UserDeleteResponse, Errors>()
        .withUri('/api/user/bulk')
        .withJSONBody(request)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the users with the given ids, or users matching the provided JSON query or queryString.
   * The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
   * 
   * This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
   * Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
   *
   * @param {UserDeleteRequest} request The UserDeleteRequest.
   * @returns {Promise<ClientResponse<UserDeleteResponse>>}
   */
  deleteUsersByQuery(request: UserDeleteRequest): Promise<ClientResponse<UserDeleteResponse>> {
    return this.start<UserDeleteResponse, Errors>()
        .withUri('/api/user/bulk')
        .withJSONBody(request)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the WebAuthn credential for the given Id.
   *
   * @param {UUID} id The Id of the WebAuthn credential to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteWebAuthnCredential(id: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/webauthn')
        .withUriSegment(id)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Deletes the webhook for the given Id.
   *
   * @param {UUID} webhookId The Id of the webhook to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  deleteWebhook(webhookId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/webhook')
        .withUriSegment(webhookId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Disable two-factor authentication for a user.
   *
   * @param {UUID} userId The Id of the User for which you're disabling two-factor authentication.
   * @param {string} methodId The two-factor method identifier you wish to disable
   * @param {string} code The two-factor code used verify the the caller knows the two-factor secret.
   * @returns {Promise<ClientResponse<void>>}
   */
  disableTwoFactor(userId: UUID, methodId: string, code: string): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user/two-factor')
        .withUriSegment(userId)
        .withParameter('methodId', methodId)
        .withParameter('code', code)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Disable two-factor authentication for a user using a JSON body rather than URL parameters.
   *
   * @param {UUID} userId The Id of the User for which you're disabling two-factor authentication.
   * @param {TwoFactorDisableRequest} request The request information that contains the code and methodId along with any event information.
   * @returns {Promise<ClientResponse<void>>}
   */
  disableTwoFactorWithRequest(userId: UUID, request: TwoFactorDisableRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user/two-factor')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Enable two-factor authentication for a user.
   *
   * @param {UUID} userId The Id of the user to enable two-factor authentication.
   * @param {TwoFactorRequest} request The two-factor enable request information.
   * @returns {Promise<ClientResponse<TwoFactorResponse>>}
   */
  enableTwoFactor(userId: UUID, request: TwoFactorRequest): Promise<ClientResponse<TwoFactorResponse>> {
    return this.start<TwoFactorResponse, Errors>()
        .withUri('/api/user/two-factor')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Exchanges an OAuth authorization code for an access token.
   * Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint for an access token.
   *
   * @param {string} code The authorization code returned on the /oauth2/authorize response.
   * @param {string} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.
   *    This parameter is optional when Basic Authorization is used to authenticate this request.
   * @param {string} client_secret (Optional) The client secret. This value will be required if client authentication is enabled.
   * @param {string} redirect_uri The URI to redirect to upon a successful request.
   * @returns {Promise<ClientResponse<AccessToken>>}
   */
  exchangeOAuthCodeForAccessToken(code: string, client_id: string, client_secret: string, redirect_uri: string): Promise<ClientResponse<AccessToken>> {
    let body = new URLSearchParams();

    body.append('code', code);
    body.append('client_id', client_id);
    body.append('client_secret', client_secret);
    body.append('grant_type', 'authorization_code');
    body.append('redirect_uri', redirect_uri);
    return this.startAnonymous<AccessToken, OAuthError>()
        .withUri('/oauth2/token')
        .withFormData(body)
        .withMethod("POST")
        .go();
  }

  /**
   * Exchanges an OAuth authorization code and code_verifier for an access token.
   * Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint and a code_verifier for an access token.
   *
   * @param {string} code The authorization code returned on the /oauth2/authorize response.
   * @param {string} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
   *    This parameter is optional when Basic Authorization is used to authenticate this request.
   * @param {string} client_secret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
   * @param {string} redirect_uri The URI to redirect to upon a successful request.
   * @param {string} code_verifier The random string generated previously. Will be compared with the code_challenge sent previously, which allows the OAuth provider to authenticate your app.
   * @returns {Promise<ClientResponse<AccessToken>>}
   */
  exchangeOAuthCodeForAccessTokenUsingPKCE(code: string, client_id: string, client_secret: string, redirect_uri: string, code_verifier: string): Promise<ClientResponse<AccessToken>> {
    let body = new URLSearchParams();

    body.append('code', code);
    body.append('client_id', client_id);
    body.append('client_secret', client_secret);
    body.append('grant_type', 'authorization_code');
    body.append('redirect_uri', redirect_uri);
    body.append('code_verifier', code_verifier);
    return this.startAnonymous<AccessToken, OAuthError>()
        .withUri('/oauth2/token')
        .withFormData(body)
        .withMethod("POST")
        .go();
  }

  /**
   * Exchange a Refresh Token for an Access Token.
   * If you will be using the Refresh Token Grant, you will make a request to the Token endpoint to exchange the user’s refresh token for an access token.
   *
   * @param {string} refresh_token The refresh token that you would like to use to exchange for an access token.
   * @param {string} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
   *    This parameter is optional when Basic Authorization is used to authenticate this request.
   * @param {string} client_secret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
   * @param {string} scope (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.
   * @param {string} user_code (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.
   * @returns {Promise<ClientResponse<AccessToken>>}
   */
  exchangeRefreshTokenForAccessToken(refresh_token: string, client_id: string, client_secret: string, scope: string, user_code: string): Promise<ClientResponse<AccessToken>> {
    let body = new URLSearchParams();

    body.append('refresh_token', refresh_token);
    body.append('client_id', client_id);
    body.append('client_secret', client_secret);
    body.append('grant_type', 'refresh_token');
    body.append('scope', scope);
    body.append('user_code', user_code);
    return this.startAnonymous<AccessToken, OAuthError>()
        .withUri('/oauth2/token')
        .withFormData(body)
        .withMethod("POST")
        .go();
  }

  /**
   * Exchange a refresh token for a new JWT.
   *
   * @param {RefreshRequest} request The refresh request.
   * @returns {Promise<ClientResponse<JWTRefreshResponse>>}
   */
  exchangeRefreshTokenForJWT(request: RefreshRequest): Promise<ClientResponse<JWTRefreshResponse>> {
    return this.startAnonymous<JWTRefreshResponse, Errors>()
        .withUri('/api/jwt/refresh')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Exchange User Credentials for a Token.
   * If you will be using the Resource Owner Password Credential Grant, you will make a request to the Token endpoint to exchange the user’s email and password for an access token.
   *
   * @param {string} username The login identifier of the user. The login identifier can be either the email or the username.
   * @param {string} password The user’s password.
   * @param {string} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
   *    This parameter is optional when Basic Authorization is used to authenticate this request.
   * @param {string} client_secret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
   * @param {string} scope (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.
   * @param {string} user_code (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.
   * @returns {Promise<ClientResponse<AccessToken>>}
   */
  exchangeUserCredentialsForAccessToken(username: string, password: string, client_id: string, client_secret: string, scope: string, user_code: string): Promise<ClientResponse<AccessToken>> {
    let body = new URLSearchParams();

    body.append('username', username);
    body.append('password', password);
    body.append('client_id', client_id);
    body.append('client_secret', client_secret);
    body.append('grant_type', 'password');
    body.append('scope', scope);
    body.append('user_code', user_code);
    return this.startAnonymous<AccessToken, OAuthError>()
        .withUri('/oauth2/token')
        .withFormData(body)
        .withMethod("POST")
        .go();
  }

  /**
   * Begins the forgot password sequence, which kicks off an email to the user so that they can reset their password.
   *
   * @param {ForgotPasswordRequest} request The request that contains the information about the user so that they can be emailed.
   * @returns {Promise<ClientResponse<ForgotPasswordResponse>>}
   */
  forgotPassword(request: ForgotPasswordRequest): Promise<ClientResponse<ForgotPasswordResponse>> {
    return this.start<ForgotPasswordResponse, Errors>()
        .withUri('/api/user/forgot-password')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Generate a new Email Verification Id to be used with the Verify Email API. This API will not attempt to send an
   * email to the User. This API may be used to collect the verificationId for use with a third party system.
   *
   * @param {string} email The email address of the user that needs a new verification email.
   * @returns {Promise<ClientResponse<VerifyEmailResponse>>}
   */
  generateEmailVerificationId(email: string): Promise<ClientResponse<VerifyEmailResponse>> {
    return this.start<VerifyEmailResponse, void>()
        .withUri('/api/user/verify-email')
        .withParameter('email', email)
        .withParameter('sendVerifyEmail', false)
        .withMethod("PUT")
        .go();
  }

  /**
   * Generate a new RSA or EC key pair or an HMAC secret.
   *
   * @param {UUID} keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
   * @param {KeyRequest} request The request object that contains all the information used to create the key.
   * @returns {Promise<ClientResponse<KeyResponse>>}
   */
  generateKey(keyId: UUID, request: KeyRequest): Promise<ClientResponse<KeyResponse>> {
    return this.start<KeyResponse, Errors>()
        .withUri('/api/key/generate')
        .withUriSegment(keyId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Generate a new Application Registration Verification Id to be used with the Verify Registration API. This API will not attempt to send an
   * email to the User. This API may be used to collect the verificationId for use with a third party system.
   *
   * @param {string} email The email address of the user that needs a new verification email.
   * @param {UUID} applicationId The Id of the application to be verified.
   * @returns {Promise<ClientResponse<VerifyRegistrationResponse>>}
   */
  generateRegistrationVerificationId(email: string, applicationId: UUID): Promise<ClientResponse<VerifyRegistrationResponse>> {
    return this.start<VerifyRegistrationResponse, void>()
        .withUri('/api/user/verify-registration')
        .withParameter('email', email)
        .withParameter('sendVerifyPasswordEmail', false)
        .withParameter('applicationId', applicationId)
        .withMethod("PUT")
        .go();
  }

  /**
   * Generate two-factor recovery codes for a user. Generating two-factor recovery codes will invalidate any existing recovery codes. 
   *
   * @param {UUID} userId The Id of the user to generate new Two Factor recovery codes.
   * @returns {Promise<ClientResponse<TwoFactorRecoveryCodeResponse>>}
   */
  generateTwoFactorRecoveryCodes(userId: UUID): Promise<ClientResponse<TwoFactorRecoveryCodeResponse>> {
    return this.start<TwoFactorRecoveryCodeResponse, Errors>()
        .withHeader('Content-Type', 'text/plain')
        .withUri('/api/user/two-factor/recovery-code')
        .withUriSegment(userId)
        .withMethod("POST")
        .go();
  }

  /**
   * Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
   * both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
   * application such as Google Authenticator.
   *
   * @returns {Promise<ClientResponse<SecretResponse>>}
   */
  generateTwoFactorSecret(): Promise<ClientResponse<SecretResponse>> {
    return this.start<SecretResponse, void>()
        .withUri('/api/two-factor/secret')
        .withMethod("GET")
        .go();
  }

  /**
   * Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
   * both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
   * application such as Google Authenticator.
   *
   * @param {string} encodedJWT The encoded JWT (access token).
   * @returns {Promise<ClientResponse<SecretResponse>>}
   */
  generateTwoFactorSecretUsingJWT(encodedJWT: string): Promise<ClientResponse<SecretResponse>> {
    return this.startAnonymous<SecretResponse, void>()
        .withUri('/api/two-factor/secret')
        .withAuthorization('Bearer ' + encodedJWT)
        .withMethod("GET")
        .go();
  }

  /**
   * Handles login via third-parties including Social login, external OAuth and OpenID Connect, and other
   * login systems.
   *
   * @param {IdentityProviderLoginRequest} request The third-party login request that contains information from the third-party login
   *    providers that FusionAuth uses to reconcile the user's account.
   * @returns {Promise<ClientResponse<LoginResponse>>}
   */
  identityProviderLogin(request: IdentityProviderLoginRequest): Promise<ClientResponse<LoginResponse>> {
    return this.startAnonymous<LoginResponse, Errors>()
        .withUri('/api/identity-provider/login')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Import an existing RSA or EC key pair or an HMAC secret.
   *
   * @param {UUID} keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
   * @param {KeyRequest} request The request object that contains all the information used to create the key.
   * @returns {Promise<ClientResponse<KeyResponse>>}
   */
  importKey(keyId: UUID, request: KeyRequest): Promise<ClientResponse<KeyResponse>> {
    return this.start<KeyResponse, Errors>()
        .withUri('/api/key/import')
        .withUriSegment(keyId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Bulk imports refresh tokens. This request performs minimal validation and runs batch inserts of refresh tokens with the
   * expectation that each token represents a user that already exists and is registered for the corresponding FusionAuth
   * Application. This is done to increases the insert performance.
   * 
   * Therefore, if you encounter an error due to a database key violation, the response will likely offer a generic
   * explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
   * body with specific validation errors. This will slow the request down but will allow you to identify the cause of
   * the failure. See the validateDbConstraints request parameter.
   *
   * @param {RefreshTokenImportRequest} request The request that contains all the information about all the refresh tokens to import.
   * @returns {Promise<ClientResponse<void>>}
   */
  importRefreshTokens(request: RefreshTokenImportRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user/refresh-token/import')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Bulk imports users. This request performs minimal validation and runs batch inserts of users with the expectation
   * that each user does not yet exist and each registration corresponds to an existing FusionAuth Application. This is done to
   * increases the insert performance.
   * 
   * Therefore, if you encounter an error due to a database key violation, the response will likely offer
   * a generic explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
   * body with specific validation errors. This will slow the request down but will allow you to identify the cause of the failure. See
   * the validateDbConstraints request parameter.
   *
   * @param {ImportRequest} request The request that contains all the information about all the users to import.
   * @returns {Promise<ClientResponse<void>>}
   */
  importUsers(request: ImportRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user/import')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Import a WebAuthn credential
   *
   * @param {WebAuthnCredentialImportRequest} request An object containing data necessary for importing the credential
   * @returns {Promise<ClientResponse<void>>}
   */
  importWebAuthnCredential(request: WebAuthnCredentialImportRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/webauthn/import')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Inspect an access token issued as the result of the User based grant such as the Authorization Code Grant, Implicit Grant, the User Credentials Grant or the Refresh Grant.
   *
   * @param {string} client_id The unique client identifier. The client Id is the Id of the FusionAuth Application for which this token was generated.
   * @param {string} token The access token returned by this OAuth provider as the result of a successful client credentials grant.
   * @returns {Promise<ClientResponse<IntrospectResponse>>}
   */
  introspectAccessToken(client_id: string, token: string): Promise<ClientResponse<IntrospectResponse>> {
    let body = new URLSearchParams();

    body.append('client_id', client_id);
    body.append('token', token);
    return this.startAnonymous<IntrospectResponse, OAuthError>()
        .withUri('/oauth2/introspect')
        .withFormData(body)
        .withMethod("POST")
        .go();
  }

  /**
   * Inspect an access token issued as the result of the Client Credentials Grant.
   *
   * @param {string} token The access token returned by this OAuth provider as the result of a successful client credentials grant.
   * @returns {Promise<ClientResponse<IntrospectResponse>>}
   */
  introspectClientCredentialsAccessToken(token: string): Promise<ClientResponse<IntrospectResponse>> {
    let body = new URLSearchParams();

    body.append('token', token);
    return this.startAnonymous<IntrospectResponse, OAuthError>()
        .withUri('/oauth2/introspect')
        .withFormData(body)
        .withMethod("POST")
        .go();
  }

  /**
   * Issue a new access token (JWT) for the requested Application after ensuring the provided JWT is valid. A valid
   * access token is properly signed and not expired.
   * <p>
   * This API may be used in an SSO configuration to issue new tokens for another application after the user has
   * obtained a valid token from authentication.
   *
   * @param {UUID} applicationId The Application Id for which you are requesting a new access token be issued.
   * @param {string} encodedJWT The encoded JWT (access token).
   * @param {string} refreshToken (Optional) An existing refresh token used to request a refresh token in addition to a JWT in the response.
   *    <p>The target application represented by the applicationId request parameter must have refresh
   *    tokens enabled in order to receive a refresh token in the response.</p>
   * @returns {Promise<ClientResponse<IssueResponse>>}
   */
  issueJWT(applicationId: UUID, encodedJWT: string, refreshToken: string): Promise<ClientResponse<IssueResponse>> {
    return this.startAnonymous<IssueResponse, Errors>()
        .withUri('/api/jwt/issue')
        .withAuthorization('Bearer ' + encodedJWT)
        .withParameter('applicationId', applicationId)
        .withParameter('refreshToken', refreshToken)
        .withMethod("GET")
        .go();
  }

  /**
   * Authenticates a user to FusionAuth. 
   * 
   * This API optionally requires an API key. See <code>Application.loginConfiguration.requireAuthentication</code>.
   *
   * @param {LoginRequest} request The login request that contains the user credentials used to log them in.
   * @returns {Promise<ClientResponse<LoginResponse>>}
   */
  login(request: LoginRequest): Promise<ClientResponse<LoginResponse>> {
    return this.start<LoginResponse, Errors>()
        .withUri('/api/login')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
   * FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
   * application where they no longer have a session. This helps correctly track login counts, times and helps with
   * reporting.
   *
   * @param {UUID} userId The Id of the user that was logged in.
   * @param {UUID} applicationId The Id of the application that they logged into.
   * @param {string} callerIPAddress (Optional) The IP address of the end-user that is logging in. If a null value is provided
   *    the IP address will be that of the client or last proxy that sent the request.
   * @returns {Promise<ClientResponse<LoginResponse>>}
   */
  loginPing(userId: UUID, applicationId: UUID, callerIPAddress: string): Promise<ClientResponse<LoginResponse>> {
    return this.start<LoginResponse, Errors>()
        .withUri('/api/login')
        .withUriSegment(userId)
        .withUriSegment(applicationId)
        .withParameter('ipAddress', callerIPAddress)
        .withMethod("PUT")
        .go();
  }

  /**
   * Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
   * FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
   * application where they no longer have a session. This helps correctly track login counts, times and helps with
   * reporting.
   *
   * @param {LoginPingRequest} request The login request that contains the user credentials used to log them in.
   * @returns {Promise<ClientResponse<LoginResponse>>}
   */
  loginPingWithRequest(request: LoginPingRequest): Promise<ClientResponse<LoginResponse>> {
    return this.start<LoginResponse, Errors>()
        .withUri('/api/login')
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
   * client and revoke the refresh token stored. This API does nothing if the request does not contain an access
   * token or refresh token cookies.
   *
   * @param {boolean} global When this value is set to true all the refresh tokens issued to the owner of the
   *    provided token will be revoked.
   * @param {string} refreshToken (Optional) The refresh_token as a request parameter instead of coming in via a cookie.
   *    If provided this takes precedence over the cookie.
   * @returns {Promise<ClientResponse<void>>}
   */
  logout(global: boolean, refreshToken: string): Promise<ClientResponse<void>> {
    return this.startAnonymous<void, void>()
        .withHeader('Content-Type', 'text/plain')
        .withUri('/api/logout')
        .withParameter('global', global)
        .withParameter('refreshToken', refreshToken)
        .withMethod("POST")
        .go();
  }

  /**
   * The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
   * client and revoke the refresh token stored. This API takes the refresh token in the JSON body.
   *
   * @param {LogoutRequest} request The request object that contains all the information used to logout the user.
   * @returns {Promise<ClientResponse<void>>}
   */
  logoutWithRequest(request: LogoutRequest): Promise<ClientResponse<void>> {
    return this.startAnonymous<void, void>()
        .withUri('/api/logout')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Retrieves the identity provider for the given domain. A 200 response code indicates the domain is managed
   * by a registered identity provider. A 404 indicates the domain is not managed.
   *
   * @param {string} domain The domain or email address to lookup.
   * @returns {Promise<ClientResponse<LookupResponse>>}
   */
  lookupIdentityProvider(domain: string): Promise<ClientResponse<LookupResponse>> {
    return this.start<LookupResponse, void>()
        .withUri('/api/identity-provider/lookup')
        .withParameter('domain', domain)
        .withMethod("GET")
        .go();
  }

  /**
   * Modifies a temporal user action by changing the expiration of the action and optionally adding a comment to the
   * action.
   *
   * @param {UUID} actionId The Id of the action to modify. This is technically the user action log id.
   * @param {ActionRequest} request The request that contains all the information about the modification.
   * @returns {Promise<ClientResponse<ActionResponse>>}
   */
  modifyAction(actionId: UUID, request: ActionRequest): Promise<ClientResponse<ActionResponse>> {
    return this.start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withUriSegment(actionId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Complete a login request using a passwordless code
   *
   * @param {PasswordlessLoginRequest} request The passwordless login request that contains all the information used to complete login.
   * @returns {Promise<ClientResponse<LoginResponse>>}
   */
  passwordlessLogin(request: PasswordlessLoginRequest): Promise<ClientResponse<LoginResponse>> {
    return this.startAnonymous<LoginResponse, Errors>()
        .withUri('/api/passwordless/login')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Updates an authentication API key by given id
   *
   * @param {UUID} keyId The Id of the authentication key. If not provided a secure random api key will be generated.
   * @param {APIKeyRequest} request The request object that contains all the information needed to create the APIKey.
   * @returns {Promise<ClientResponse<APIKeyResponse>>}
   */
  patchAPIKey(keyId: UUID, request: APIKeyRequest): Promise<ClientResponse<APIKeyResponse>> {
    return this.start<APIKeyResponse, Errors>()
        .withUri('/api/api-key')
        .withUriSegment(keyId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Updates, via PATCH, the application with the given Id.
   *
   * @param {UUID} applicationId The Id of the application to update.
   * @param {ApplicationRequest} request The request that contains just the new application information.
   * @returns {Promise<ClientResponse<ApplicationResponse>>}
   */
  patchApplication(applicationId: UUID, request: ApplicationRequest): Promise<ClientResponse<ApplicationResponse>> {
    return this.start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the application role with the given Id for the application.
   *
   * @param {UUID} applicationId The Id of the application that the role belongs to.
   * @param {UUID} roleId The Id of the role to update.
   * @param {ApplicationRequest} request The request that contains just the new role information.
   * @returns {Promise<ClientResponse<ApplicationResponse>>}
   */
  patchApplicationRole(applicationId: UUID, roleId: UUID, request: ApplicationRequest): Promise<ClientResponse<ApplicationResponse>> {
    return this.start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("role")
        .withUriSegment(roleId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the connector with the given Id.
   *
   * @param {UUID} connectorId The Id of the connector to update.
   * @param {ConnectorRequest} request The request that contains just the new connector information.
   * @returns {Promise<ClientResponse<ConnectorResponse>>}
   */
  patchConnector(connectorId: UUID, request: ConnectorRequest): Promise<ClientResponse<ConnectorResponse>> {
    return this.start<ConnectorResponse, Errors>()
        .withUri('/api/connector')
        .withUriSegment(connectorId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the consent with the given Id.
   *
   * @param {UUID} consentId The Id of the consent to update.
   * @param {ConsentRequest} request The request that contains just the new consent information.
   * @returns {Promise<ClientResponse<ConsentResponse>>}
   */
  patchConsent(consentId: UUID, request: ConsentRequest): Promise<ClientResponse<ConsentResponse>> {
    return this.start<ConsentResponse, Errors>()
        .withUri('/api/consent')
        .withUriSegment(consentId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the email template with the given Id.
   *
   * @param {UUID} emailTemplateId The Id of the email template to update.
   * @param {EmailTemplateRequest} request The request that contains just the new email template information.
   * @returns {Promise<ClientResponse<EmailTemplateResponse>>}
   */
  patchEmailTemplate(emailTemplateId: UUID, request: EmailTemplateRequest): Promise<ClientResponse<EmailTemplateResponse>> {
    return this.start<EmailTemplateResponse, Errors>()
        .withUri('/api/email/template')
        .withUriSegment(emailTemplateId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the Entity Type with the given Id.
   *
   * @param {UUID} entityTypeId The Id of the Entity Type to update.
   * @param {EntityTypeRequest} request The request that contains just the new Entity Type information.
   * @returns {Promise<ClientResponse<EntityTypeResponse>>}
   */
  patchEntityType(entityTypeId: UUID, request: EntityTypeRequest): Promise<ClientResponse<EntityTypeResponse>> {
    return this.start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the group with the given Id.
   *
   * @param {UUID} groupId The Id of the group to update.
   * @param {GroupRequest} request The request that contains just the new group information.
   * @returns {Promise<ClientResponse<GroupResponse>>}
   */
  patchGroup(groupId: UUID, request: GroupRequest): Promise<ClientResponse<GroupResponse>> {
    return this.start<GroupResponse, Errors>()
        .withUri('/api/group')
        .withUriSegment(groupId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the identity provider with the given Id.
   *
   * @param {UUID} identityProviderId The Id of the identity provider to update.
   * @param {IdentityProviderRequest} request The request object that contains just the updated identity provider information.
   * @returns {Promise<ClientResponse<IdentityProviderResponse>>}
   */
  patchIdentityProvider(identityProviderId: UUID, request: IdentityProviderRequest): Promise<ClientResponse<IdentityProviderResponse>> {
    return this.start<IdentityProviderResponse, Errors>()
        .withUri('/api/identity-provider')
        .withUriSegment(identityProviderId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the available integrations.
   *
   * @param {IntegrationRequest} request The request that contains just the new integration information.
   * @returns {Promise<ClientResponse<IntegrationResponse>>}
   */
  patchIntegrations(request: IntegrationRequest): Promise<ClientResponse<IntegrationResponse>> {
    return this.start<IntegrationResponse, Errors>()
        .withUri('/api/integration')
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the lambda with the given Id.
   *
   * @param {UUID} lambdaId The Id of the lambda to update.
   * @param {LambdaRequest} request The request that contains just the new lambda information.
   * @returns {Promise<ClientResponse<LambdaResponse>>}
   */
  patchLambda(lambdaId: UUID, request: LambdaRequest): Promise<ClientResponse<LambdaResponse>> {
    return this.start<LambdaResponse, Errors>()
        .withUri('/api/lambda')
        .withUriSegment(lambdaId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the message template with the given Id.
   *
   * @param {UUID} messageTemplateId The Id of the message template to update.
   * @param {MessageTemplateRequest} request The request that contains just the new message template information.
   * @returns {Promise<ClientResponse<MessageTemplateResponse>>}
   */
  patchMessageTemplate(messageTemplateId: UUID, request: MessageTemplateRequest): Promise<ClientResponse<MessageTemplateResponse>> {
    return this.start<MessageTemplateResponse, Errors>()
        .withUri('/api/message/template')
        .withUriSegment(messageTemplateId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the messenger with the given Id.
   *
   * @param {UUID} messengerId The Id of the messenger to update.
   * @param {MessengerRequest} request The request that contains just the new messenger information.
   * @returns {Promise<ClientResponse<MessengerResponse>>}
   */
  patchMessenger(messengerId: UUID, request: MessengerRequest): Promise<ClientResponse<MessengerResponse>> {
    return this.start<MessengerResponse, Errors>()
        .withUri('/api/messenger')
        .withUriSegment(messengerId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the custom OAuth scope with the given Id for the application.
   *
   * @param {UUID} applicationId The Id of the application that the OAuth scope belongs to.
   * @param {UUID} scopeId The Id of the OAuth scope to update.
   * @param {ApplicationOAuthScopeRequest} request The request that contains just the new OAuth scope information.
   * @returns {Promise<ClientResponse<ApplicationOAuthScopeResponse>>}
   */
  patchOAuthScope(applicationId: UUID, scopeId: UUID, request: ApplicationOAuthScopeRequest): Promise<ClientResponse<ApplicationOAuthScopeResponse>> {
    return this.start<ApplicationOAuthScopeResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("scope")
        .withUriSegment(scopeId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the registration for the user with the given Id and the application defined in the request.
   *
   * @param {UUID} userId The Id of the user whose registration is going to be updated.
   * @param {RegistrationRequest} request The request that contains just the new registration information.
   * @returns {Promise<ClientResponse<RegistrationResponse>>}
   */
  patchRegistration(userId: UUID, request: RegistrationRequest): Promise<ClientResponse<RegistrationResponse>> {
    return this.start<RegistrationResponse, Errors>()
        .withUri('/api/user/registration')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the system configuration.
   *
   * @param {SystemConfigurationRequest} request The request that contains just the new system configuration information.
   * @returns {Promise<ClientResponse<SystemConfigurationResponse>>}
   */
  patchSystemConfiguration(request: SystemConfigurationRequest): Promise<ClientResponse<SystemConfigurationResponse>> {
    return this.start<SystemConfigurationResponse, Errors>()
        .withUri('/api/system-configuration')
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the tenant with the given Id.
   *
   * @param {UUID} tenantId The Id of the tenant to update.
   * @param {TenantRequest} request The request that contains just the new tenant information.
   * @returns {Promise<ClientResponse<TenantResponse>>}
   */
  patchTenant(tenantId: UUID, request: TenantRequest): Promise<ClientResponse<TenantResponse>> {
    return this.start<TenantResponse, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the theme with the given Id.
   *
   * @param {UUID} themeId The Id of the theme to update.
   * @param {ThemeRequest} request The request that contains just the new theme information.
   * @returns {Promise<ClientResponse<ThemeResponse>>}
   */
  patchTheme(themeId: UUID, request: ThemeRequest): Promise<ClientResponse<ThemeResponse>> {
    return this.start<ThemeResponse, Errors>()
        .withUri('/api/theme')
        .withUriSegment(themeId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the user with the given Id.
   *
   * @param {UUID} userId The Id of the user to update.
   * @param {UserRequest} request The request that contains just the new user information.
   * @returns {Promise<ClientResponse<UserResponse>>}
   */
  patchUser(userId: UUID, request: UserRequest): Promise<ClientResponse<UserResponse>> {
    return this.start<UserResponse, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the user action with the given Id.
   *
   * @param {UUID} userActionId The Id of the user action to update.
   * @param {UserActionRequest} request The request that contains just the new user action information.
   * @returns {Promise<ClientResponse<UserActionResponse>>}
   */
  patchUserAction(userActionId: UUID, request: UserActionRequest): Promise<ClientResponse<UserActionResponse>> {
    return this.start<UserActionResponse, Errors>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, the user action reason with the given Id.
   *
   * @param {UUID} userActionReasonId The Id of the user action reason to update.
   * @param {UserActionReasonRequest} request The request that contains just the new user action reason information.
   * @returns {Promise<ClientResponse<UserActionReasonResponse>>}
   */
  patchUserActionReason(userActionReasonId: UUID, request: UserActionReasonRequest): Promise<ClientResponse<UserActionReasonResponse>> {
    return this.start<UserActionReasonResponse, Errors>()
        .withUri('/api/user-action-reason')
        .withUriSegment(userActionReasonId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Updates, via PATCH, a single User consent by Id.
   *
   * @param {UUID} userConsentId The User Consent Id
   * @param {UserConsentRequest} request The request that contains just the new user consent information.
   * @returns {Promise<ClientResponse<UserConsentResponse>>}
   */
  patchUserConsent(userConsentId: UUID, request: UserConsentRequest): Promise<ClientResponse<UserConsentResponse>> {
    return this.start<UserConsentResponse, Errors>()
        .withUri('/api/user/consent')
        .withUriSegment(userConsentId)
        .withJSONBody(request)
        .withMethod("PATCH")
        .go();
  }

  /**
   * Reactivates the application with the given Id.
   *
   * @param {UUID} applicationId The Id of the application to reactivate.
   * @returns {Promise<ClientResponse<ApplicationResponse>>}
   */
  reactivateApplication(applicationId: UUID): Promise<ClientResponse<ApplicationResponse>> {
    return this.start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withParameter('reactivate', true)
        .withMethod("PUT")
        .go();
  }

  /**
   * Reactivates the user with the given Id.
   *
   * @param {UUID} userId The Id of the user to reactivate.
   * @returns {Promise<ClientResponse<UserResponse>>}
   */
  reactivateUser(userId: UUID): Promise<ClientResponse<UserResponse>> {
    return this.start<UserResponse, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withParameter('reactivate', true)
        .withMethod("PUT")
        .go();
  }

  /**
   * Reactivates the user action with the given Id.
   *
   * @param {UUID} userActionId The Id of the user action to reactivate.
   * @returns {Promise<ClientResponse<UserActionResponse>>}
   */
  reactivateUserAction(userActionId: UUID): Promise<ClientResponse<UserActionResponse>> {
    return this.start<UserActionResponse, Errors>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withParameter('reactivate', true)
        .withMethod("PUT")
        .go();
  }

  /**
   * Reconcile a User to FusionAuth using JWT issued from another Identity Provider.
   *
   * @param {IdentityProviderLoginRequest} request The reconcile request that contains the data to reconcile the User.
   * @returns {Promise<ClientResponse<LoginResponse>>}
   */
  reconcileJWT(request: IdentityProviderLoginRequest): Promise<ClientResponse<LoginResponse>> {
    return this.startAnonymous<LoginResponse, Errors>()
        .withUri('/api/jwt/reconcile')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Request a refresh of the Entity search index. This API is not generally necessary and the search index will become consistent in a
   * reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be 
   * if you are using the Search API or Delete Tenant API immediately following a Entity Create etc, you may wish to request a refresh to
   *  ensure the index immediately current before making a query request to the search index.
   *
   * @returns {Promise<ClientResponse<void>>}
   */
  refreshEntitySearchIndex(): Promise<ClientResponse<void>> {
    return this.start<void, void>()
        .withUri('/api/entity/search')
        .withMethod("PUT")
        .go();
  }

  /**
   * Request a refresh of the User search index. This API is not generally necessary and the search index will become consistent in a
   * reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be 
   * if you are using the Search API or Delete Tenant API immediately following a User Create etc, you may wish to request a refresh to
   *  ensure the index immediately current before making a query request to the search index.
   *
   * @returns {Promise<ClientResponse<void>>}
   */
  refreshUserSearchIndex(): Promise<ClientResponse<void>> {
    return this.start<void, void>()
        .withUri('/api/user/search')
        .withMethod("PUT")
        .go();
  }

  /**
   * Regenerates any keys that are used by the FusionAuth Reactor.
   *
   * @returns {Promise<ClientResponse<void>>}
   */
  regenerateReactorKeys(): Promise<ClientResponse<void>> {
    return this.start<void, void>()
        .withUri('/api/reactor')
        .withMethod("PUT")
        .go();
  }

  /**
   * Registers a user for an application. If you provide the User and the UserRegistration object on this request, it
   * will create the user as well as register them for the application. This is called a Full Registration. However, if
   * you only provide the UserRegistration object, then the user must already exist and they will be registered for the
   * application. The user Id can also be provided and it will either be used to look up an existing user or it will be
   * used for the newly created User.
   *
   * @param {UUID} userId (Optional) The Id of the user being registered for the application and optionally created.
   * @param {RegistrationRequest} request The request that optionally contains the User and must contain the UserRegistration.
   * @returns {Promise<ClientResponse<RegistrationResponse>>}
   */
  register(userId: UUID, request: RegistrationRequest): Promise<ClientResponse<RegistrationResponse>> {
    return this.start<RegistrationResponse, Errors>()
        .withUri('/api/user/registration')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Requests Elasticsearch to delete and rebuild the index for FusionAuth users or entities. Be very careful when running this request as it will 
   * increase the CPU and I/O load on your database until the operation completes. Generally speaking you do not ever need to run this operation unless 
   * instructed by FusionAuth support, or if you are migrating a database another system and you are not brining along the Elasticsearch index. 
   * 
   * You have been warned.
   *
   * @param {ReindexRequest} request The request that contains the index name.
   * @returns {Promise<ClientResponse<void>>}
   */
  reindex(request: ReindexRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/system/reindex')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Removes a user from the family with the given id.
   *
   * @param {UUID} familyId The Id of the family to remove the user from.
   * @param {UUID} userId The Id of the user to remove from the family.
   * @returns {Promise<ClientResponse<void>>}
   */
  removeUserFromFamily(familyId: UUID, userId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user/family')
        .withUriSegment(familyId)
        .withUriSegment(userId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Re-sends the verification email to the user.
   *
   * @param {string} email The email address of the user that needs a new verification email.
   * @returns {Promise<ClientResponse<VerifyEmailResponse>>}
   */
  resendEmailVerification(email: string): Promise<ClientResponse<VerifyEmailResponse>> {
    return this.start<VerifyEmailResponse, Errors>()
        .withUri('/api/user/verify-email')
        .withParameter('email', email)
        .withMethod("PUT")
        .go();
  }

  /**
   * Re-sends the verification email to the user. If the Application has configured a specific email template this will be used
   * instead of the tenant configuration.
   *
   * @param {UUID} applicationId The unique Application Id to used to resolve an application specific email template.
   * @param {string} email The email address of the user that needs a new verification email.
   * @returns {Promise<ClientResponse<VerifyEmailResponse>>}
   */
  resendEmailVerificationWithApplicationTemplate(applicationId: UUID, email: string): Promise<ClientResponse<VerifyEmailResponse>> {
    return this.start<VerifyEmailResponse, Errors>()
        .withUri('/api/user/verify-email')
        .withParameter('applicationId', applicationId)
        .withParameter('email', email)
        .withMethod("PUT")
        .go();
  }

  /**
   * Re-sends the application registration verification email to the user.
   *
   * @param {string} email The email address of the user that needs a new verification email.
   * @param {UUID} applicationId The Id of the application to be verified.
   * @returns {Promise<ClientResponse<VerifyRegistrationResponse>>}
   */
  resendRegistrationVerification(email: string, applicationId: UUID): Promise<ClientResponse<VerifyRegistrationResponse>> {
    return this.start<VerifyRegistrationResponse, Errors>()
        .withUri('/api/user/verify-registration')
        .withParameter('email', email)
        .withParameter('applicationId', applicationId)
        .withMethod("PUT")
        .go();
  }

  /**
   * Retrieves an authentication API key for the given id
   *
   * @param {UUID} keyId The Id of the API key to retrieve.
   * @returns {Promise<ClientResponse<APIKeyResponse>>}
   */
  retrieveAPIKey(keyId: UUID): Promise<ClientResponse<APIKeyResponse>> {
    return this.start<APIKeyResponse, Errors>()
        .withUri('/api/api-key')
        .withUriSegment(keyId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves a single action log (the log of a user action that was taken on a user previously) for the given Id.
   *
   * @param {UUID} actionId The Id of the action to retrieve.
   * @returns {Promise<ClientResponse<ActionResponse>>}
   */
  retrieveAction(actionId: UUID): Promise<ClientResponse<ActionResponse>> {
    return this.start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withUriSegment(actionId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the actions for the user with the given Id. This will return all time based actions that are active,
   * and inactive as well as non-time based actions.
   *
   * @param {UUID} userId The Id of the user to fetch the actions for.
   * @returns {Promise<ClientResponse<ActionResponse>>}
   */
  retrieveActions(userId: UUID): Promise<ClientResponse<ActionResponse>> {
    return this.start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withParameter('userId', userId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the actions for the user with the given Id that are currently preventing the User from logging in.
   *
   * @param {UUID} userId The Id of the user to fetch the actions for.
   * @returns {Promise<ClientResponse<ActionResponse>>}
   */
  retrieveActionsPreventingLogin(userId: UUID): Promise<ClientResponse<ActionResponse>> {
    return this.start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withParameter('userId', userId)
        .withParameter('preventingLogin', true)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the actions for the user with the given Id that are currently active.
   * An active action means one that is time based and has not been canceled, and has not ended.
   *
   * @param {UUID} userId The Id of the user to fetch the actions for.
   * @returns {Promise<ClientResponse<ActionResponse>>}
   */
  retrieveActiveActions(userId: UUID): Promise<ClientResponse<ActionResponse>> {
    return this.start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withParameter('userId', userId)
        .withParameter('active', true)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the application for the given Id or all the applications if the Id is null.
   *
   * @param {UUID} applicationId (Optional) The application id.
   * @returns {Promise<ClientResponse<ApplicationResponse>>}
   */
  retrieveApplication(applicationId: UUID): Promise<ClientResponse<ApplicationResponse>> {
    return this.start<ApplicationResponse, void>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the applications.
   *
   * @returns {Promise<ClientResponse<ApplicationResponse>>}
   */
  retrieveApplications(): Promise<ClientResponse<ApplicationResponse>> {
    return this.start<ApplicationResponse, void>()
        .withUri('/api/application')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves a single audit log for the given Id.
   *
   * @param {number} auditLogId The Id of the audit log to retrieve.
   * @returns {Promise<ClientResponse<AuditLogResponse>>}
   */
  retrieveAuditLog(auditLogId: number): Promise<ClientResponse<AuditLogResponse>> {
    return this.start<AuditLogResponse, Errors>()
        .withUri('/api/system/audit-log')
        .withUriSegment(auditLogId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the connector with the given Id.
   *
   * @param {UUID} connectorId The Id of the connector.
   * @returns {Promise<ClientResponse<ConnectorResponse>>}
   */
  retrieveConnector(connectorId: UUID): Promise<ClientResponse<ConnectorResponse>> {
    return this.start<ConnectorResponse, void>()
        .withUri('/api/connector')
        .withUriSegment(connectorId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the connectors.
   *
   * @returns {Promise<ClientResponse<ConnectorResponse>>}
   */
  retrieveConnectors(): Promise<ClientResponse<ConnectorResponse>> {
    return this.start<ConnectorResponse, void>()
        .withUri('/api/connector')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the Consent for the given Id.
   *
   * @param {UUID} consentId The Id of the consent.
   * @returns {Promise<ClientResponse<ConsentResponse>>}
   */
  retrieveConsent(consentId: UUID): Promise<ClientResponse<ConsentResponse>> {
    return this.start<ConsentResponse, void>()
        .withUri('/api/consent')
        .withUriSegment(consentId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the consent.
   *
   * @returns {Promise<ClientResponse<ConsentResponse>>}
   */
  retrieveConsents(): Promise<ClientResponse<ConsentResponse>> {
    return this.start<ConsentResponse, void>()
        .withUri('/api/consent')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the daily active user report between the two instants. If you specify an application id, it will only
   * return the daily active counts for that application.
   *
   * @param {UUID} applicationId (Optional) The application id.
   * @param {number} start The start instant as UTC milliseconds since Epoch.
   * @param {number} end The end instant as UTC milliseconds since Epoch.
   * @returns {Promise<ClientResponse<DailyActiveUserReportResponse>>}
   */
  retrieveDailyActiveReport(applicationId: UUID, start: number, end: number): Promise<ClientResponse<DailyActiveUserReportResponse>> {
    return this.start<DailyActiveUserReportResponse, Errors>()
        .withUri('/api/report/daily-active-user')
        .withParameter('applicationId', applicationId)
        .withParameter('start', start)
        .withParameter('end', end)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the email template for the given Id. If you don't specify the id, this will return all the email templates.
   *
   * @param {UUID} emailTemplateId (Optional) The Id of the email template.
   * @returns {Promise<ClientResponse<EmailTemplateResponse>>}
   */
  retrieveEmailTemplate(emailTemplateId: UUID): Promise<ClientResponse<EmailTemplateResponse>> {
    return this.start<EmailTemplateResponse, void>()
        .withUri('/api/email/template')
        .withUriSegment(emailTemplateId)
        .withMethod("GET")
        .go();
  }

  /**
   * Creates a preview of the email template provided in the request. This allows you to preview an email template that
   * hasn't been saved to the database yet. The entire email template does not need to be provided on the request. This
   * will create the preview based on whatever is given.
   *
   * @param {PreviewRequest} request The request that contains the email template and optionally a locale to render it in.
   * @returns {Promise<ClientResponse<PreviewResponse>>}
   */
  retrieveEmailTemplatePreview(request: PreviewRequest): Promise<ClientResponse<PreviewResponse>> {
    return this.start<PreviewResponse, Errors>()
        .withUri('/api/email/template/preview')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Retrieves all the email templates.
   *
   * @returns {Promise<ClientResponse<EmailTemplateResponse>>}
   */
  retrieveEmailTemplates(): Promise<ClientResponse<EmailTemplateResponse>> {
    return this.start<EmailTemplateResponse, void>()
        .withUri('/api/email/template')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the Entity for the given Id.
   *
   * @param {UUID} entityId The Id of the Entity.
   * @returns {Promise<ClientResponse<EntityResponse>>}
   */
  retrieveEntity(entityId: UUID): Promise<ClientResponse<EntityResponse>> {
    return this.start<EntityResponse, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves an Entity Grant for the given Entity and User/Entity.
   *
   * @param {UUID} entityId The Id of the Entity.
   * @param {UUID} recipientEntityId (Optional) The Id of the Entity that the Entity Grant is for.
   * @param {UUID} userId (Optional) The Id of the User that the Entity Grant is for.
   * @returns {Promise<ClientResponse<EntityGrantResponse>>}
   */
  retrieveEntityGrant(entityId: UUID, recipientEntityId: UUID, userId: UUID): Promise<ClientResponse<EntityGrantResponse>> {
    return this.start<EntityGrantResponse, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withUriSegment("grant")
        .withParameter('recipientEntityId', recipientEntityId)
        .withParameter('userId', userId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the Entity Type for the given Id.
   *
   * @param {UUID} entityTypeId The Id of the Entity Type.
   * @returns {Promise<ClientResponse<EntityTypeResponse>>}
   */
  retrieveEntityType(entityTypeId: UUID): Promise<ClientResponse<EntityTypeResponse>> {
    return this.start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the Entity Types.
   *
   * @returns {Promise<ClientResponse<EntityTypeResponse>>}
   */
  retrieveEntityTypes(): Promise<ClientResponse<EntityTypeResponse>> {
    return this.start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves a single event log for the given Id.
   *
   * @param {number} eventLogId The Id of the event log to retrieve.
   * @returns {Promise<ClientResponse<EventLogResponse>>}
   */
  retrieveEventLog(eventLogId: number): Promise<ClientResponse<EventLogResponse>> {
    return this.start<EventLogResponse, Errors>()
        .withUri('/api/system/event-log')
        .withUriSegment(eventLogId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the families that a user belongs to.
   *
   * @param {UUID} userId The User's id
   * @returns {Promise<ClientResponse<FamilyResponse>>}
   */
  retrieveFamilies(userId: UUID): Promise<ClientResponse<FamilyResponse>> {
    return this.start<FamilyResponse, void>()
        .withUri('/api/user/family')
        .withParameter('userId', userId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the members of a family by the unique Family Id.
   *
   * @param {UUID} familyId The unique Id of the Family.
   * @returns {Promise<ClientResponse<FamilyResponse>>}
   */
  retrieveFamilyMembersByFamilyId(familyId: UUID): Promise<ClientResponse<FamilyResponse>> {
    return this.start<FamilyResponse, void>()
        .withUri('/api/user/family')
        .withUriSegment(familyId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the form with the given Id.
   *
   * @param {UUID} formId The Id of the form.
   * @returns {Promise<ClientResponse<FormResponse>>}
   */
  retrieveForm(formId: UUID): Promise<ClientResponse<FormResponse>> {
    return this.start<FormResponse, void>()
        .withUri('/api/form')
        .withUriSegment(formId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the form field with the given Id.
   *
   * @param {UUID} fieldId The Id of the form field.
   * @returns {Promise<ClientResponse<FormFieldResponse>>}
   */
  retrieveFormField(fieldId: UUID): Promise<ClientResponse<FormFieldResponse>> {
    return this.start<FormFieldResponse, void>()
        .withUri('/api/form/field')
        .withUriSegment(fieldId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the forms fields
   *
   * @returns {Promise<ClientResponse<FormFieldResponse>>}
   */
  retrieveFormFields(): Promise<ClientResponse<FormFieldResponse>> {
    return this.start<FormFieldResponse, void>()
        .withUri('/api/form/field')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the forms.
   *
   * @returns {Promise<ClientResponse<FormResponse>>}
   */
  retrieveForms(): Promise<ClientResponse<FormResponse>> {
    return this.start<FormResponse, void>()
        .withUri('/api/form')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the group for the given Id.
   *
   * @param {UUID} groupId The Id of the group.
   * @returns {Promise<ClientResponse<GroupResponse>>}
   */
  retrieveGroup(groupId: UUID): Promise<ClientResponse<GroupResponse>> {
    return this.start<GroupResponse, Errors>()
        .withUri('/api/group')
        .withUriSegment(groupId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the groups.
   *
   * @returns {Promise<ClientResponse<GroupResponse>>}
   */
  retrieveGroups(): Promise<ClientResponse<GroupResponse>> {
    return this.start<GroupResponse, void>()
        .withUri('/api/group')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the IP Access Control List with the given Id.
   *
   * @param {UUID} ipAccessControlListId The Id of the IP Access Control List.
   * @returns {Promise<ClientResponse<IPAccessControlListResponse>>}
   */
  retrieveIPAccessControlList(ipAccessControlListId: UUID): Promise<ClientResponse<IPAccessControlListResponse>> {
    return this.start<IPAccessControlListResponse, void>()
        .withUri('/api/ip-acl')
        .withUriSegment(ipAccessControlListId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the identity provider for the given Id or all the identity providers if the Id is null.
   *
   * @param {UUID} identityProviderId The identity provider Id.
   * @returns {Promise<ClientResponse<IdentityProviderResponse>>}
   */
  retrieveIdentityProvider(identityProviderId: UUID): Promise<ClientResponse<IdentityProviderResponse>> {
    return this.start<IdentityProviderResponse, Errors>()
        .withUri('/api/identity-provider')
        .withUriSegment(identityProviderId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves one or more identity provider for the given type. For types such as Google, Facebook, Twitter and LinkedIn, only a single 
   * identity provider can exist. For types such as OpenID Connect and SAMLv2 more than one identity provider can be configured so this request 
   * may return multiple identity providers.
   *
   * @param {IdentityProviderType} type The type of the identity provider.
   * @returns {Promise<ClientResponse<IdentityProviderResponse>>}
   */
  retrieveIdentityProviderByType(type: IdentityProviderType): Promise<ClientResponse<IdentityProviderResponse>> {
    return this.start<IdentityProviderResponse, Errors>()
        .withUri('/api/identity-provider')
        .withParameter('type', type)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the identity providers.
   *
   * @returns {Promise<ClientResponse<IdentityProviderResponse>>}
   */
  retrieveIdentityProviders(): Promise<ClientResponse<IdentityProviderResponse>> {
    return this.start<IdentityProviderResponse, void>()
        .withUri('/api/identity-provider')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the actions for the user with the given Id that are currently inactive.
   * An inactive action means one that is time based and has been canceled or has expired, or is not time based.
   *
   * @param {UUID} userId The Id of the user to fetch the actions for.
   * @returns {Promise<ClientResponse<ActionResponse>>}
   */
  retrieveInactiveActions(userId: UUID): Promise<ClientResponse<ActionResponse>> {
    return this.start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withParameter('userId', userId)
        .withParameter('active', false)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the applications that are currently inactive.
   *
   * @returns {Promise<ClientResponse<ApplicationResponse>>}
   */
  retrieveInactiveApplications(): Promise<ClientResponse<ApplicationResponse>> {
    return this.start<ApplicationResponse, void>()
        .withUri('/api/application')
        .withParameter('inactive', true)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the user actions that are currently inactive.
   *
   * @returns {Promise<ClientResponse<UserActionResponse>>}
   */
  retrieveInactiveUserActions(): Promise<ClientResponse<UserActionResponse>> {
    return this.start<UserActionResponse, void>()
        .withUri('/api/user-action')
        .withParameter('inactive', true)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the available integrations.
   *
   * @returns {Promise<ClientResponse<IntegrationResponse>>}
   */
  retrieveIntegration(): Promise<ClientResponse<IntegrationResponse>> {
    return this.start<IntegrationResponse, void>()
        .withUri('/api/integration')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the Public Key configured for verifying JSON Web Tokens (JWT) by the key Id (kid).
   *
   * @param {string} keyId The Id of the public key (kid).
   * @returns {Promise<ClientResponse<PublicKeyResponse>>}
   */
  retrieveJWTPublicKey(keyId: string): Promise<ClientResponse<PublicKeyResponse>> {
    return this.startAnonymous<PublicKeyResponse, void>()
        .withUri('/api/jwt/public-key')
        .withParameter('kid', keyId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the Public Key configured for verifying the JSON Web Tokens (JWT) issued by the Login API by the Application Id.
   *
   * @param {string} applicationId The Id of the Application for which this key is used.
   * @returns {Promise<ClientResponse<PublicKeyResponse>>}
   */
  retrieveJWTPublicKeyByApplicationId(applicationId: string): Promise<ClientResponse<PublicKeyResponse>> {
    return this.startAnonymous<PublicKeyResponse, void>()
        .withUri('/api/jwt/public-key')
        .withParameter('applicationId', applicationId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all Public Keys configured for verifying JSON Web Tokens (JWT).
   *
   * @returns {Promise<ClientResponse<PublicKeyResponse>>}
   */
  retrieveJWTPublicKeys(): Promise<ClientResponse<PublicKeyResponse>> {
    return this.startAnonymous<PublicKeyResponse, void>()
        .withUri('/api/jwt/public-key')
        .withMethod("GET")
        .go();
  }

  /**
   * Returns public keys used by FusionAuth to cryptographically verify JWTs using the JSON Web Key format.
   *
   * @returns {Promise<ClientResponse<JWKSResponse>>}
   */
  retrieveJsonWebKeySet(): Promise<ClientResponse<JWKSResponse>> {
    return this.startAnonymous<JWKSResponse, void>()
        .withUri('/.well-known/jwks.json')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the key for the given Id.
   *
   * @param {UUID} keyId The Id of the key.
   * @returns {Promise<ClientResponse<KeyResponse>>}
   */
  retrieveKey(keyId: UUID): Promise<ClientResponse<KeyResponse>> {
    return this.start<KeyResponse, Errors>()
        .withUri('/api/key')
        .withUriSegment(keyId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the keys.
   *
   * @returns {Promise<ClientResponse<KeyResponse>>}
   */
  retrieveKeys(): Promise<ClientResponse<KeyResponse>> {
    return this.start<KeyResponse, void>()
        .withUri('/api/key')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the lambda for the given Id.
   *
   * @param {UUID} lambdaId The Id of the lambda.
   * @returns {Promise<ClientResponse<LambdaResponse>>}
   */
  retrieveLambda(lambdaId: UUID): Promise<ClientResponse<LambdaResponse>> {
    return this.start<LambdaResponse, Errors>()
        .withUri('/api/lambda')
        .withUriSegment(lambdaId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the lambdas.
   *
   * @returns {Promise<ClientResponse<LambdaResponse>>}
   */
  retrieveLambdas(): Promise<ClientResponse<LambdaResponse>> {
    return this.start<LambdaResponse, void>()
        .withUri('/api/lambda')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the lambdas for the provided type.
   *
   * @param {LambdaType} type The type of the lambda to return.
   * @returns {Promise<ClientResponse<LambdaResponse>>}
   */
  retrieveLambdasByType(type: LambdaType): Promise<ClientResponse<LambdaResponse>> {
    return this.start<LambdaResponse, void>()
        .withUri('/api/lambda')
        .withParameter('type', type)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the login report between the two instants. If you specify an application id, it will only return the
   * login counts for that application.
   *
   * @param {UUID} applicationId (Optional) The application id.
   * @param {number} start The start instant as UTC milliseconds since Epoch.
   * @param {number} end The end instant as UTC milliseconds since Epoch.
   * @returns {Promise<ClientResponse<LoginReportResponse>>}
   */
  retrieveLoginReport(applicationId: UUID, start: number, end: number): Promise<ClientResponse<LoginReportResponse>> {
    return this.start<LoginReportResponse, Errors>()
        .withUri('/api/report/login')
        .withParameter('applicationId', applicationId)
        .withParameter('start', start)
        .withParameter('end', end)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the message template for the given Id. If you don't specify the id, this will return all the message templates.
   *
   * @param {UUID} messageTemplateId (Optional) The Id of the message template.
   * @returns {Promise<ClientResponse<MessageTemplateResponse>>}
   */
  retrieveMessageTemplate(messageTemplateId: UUID): Promise<ClientResponse<MessageTemplateResponse>> {
    return this.start<MessageTemplateResponse, void>()
        .withUri('/api/message/template')
        .withUriSegment(messageTemplateId)
        .withMethod("GET")
        .go();
  }

  /**
   * Creates a preview of the message template provided in the request, normalized to a given locale.
   *
   * @param {PreviewMessageTemplateRequest} request The request that contains the email template and optionally a locale to render it in.
   * @returns {Promise<ClientResponse<PreviewMessageTemplateResponse>>}
   */
  retrieveMessageTemplatePreview(request: PreviewMessageTemplateRequest): Promise<ClientResponse<PreviewMessageTemplateResponse>> {
    return this.start<PreviewMessageTemplateResponse, Errors>()
        .withUri('/api/message/template/preview')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Retrieves all the message templates.
   *
   * @returns {Promise<ClientResponse<MessageTemplateResponse>>}
   */
  retrieveMessageTemplates(): Promise<ClientResponse<MessageTemplateResponse>> {
    return this.start<MessageTemplateResponse, void>()
        .withUri('/api/message/template')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the messenger with the given Id.
   *
   * @param {UUID} messengerId The Id of the messenger.
   * @returns {Promise<ClientResponse<MessengerResponse>>}
   */
  retrieveMessenger(messengerId: UUID): Promise<ClientResponse<MessengerResponse>> {
    return this.start<MessengerResponse, void>()
        .withUri('/api/messenger')
        .withUriSegment(messengerId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the messengers.
   *
   * @returns {Promise<ClientResponse<MessengerResponse>>}
   */
  retrieveMessengers(): Promise<ClientResponse<MessengerResponse>> {
    return this.start<MessengerResponse, void>()
        .withUri('/api/messenger')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the monthly active user report between the two instants. If you specify an application id, it will only
   * return the monthly active counts for that application.
   *
   * @param {UUID} applicationId (Optional) The application id.
   * @param {number} start The start instant as UTC milliseconds since Epoch.
   * @param {number} end The end instant as UTC milliseconds since Epoch.
   * @returns {Promise<ClientResponse<MonthlyActiveUserReportResponse>>}
   */
  retrieveMonthlyActiveReport(applicationId: UUID, start: number, end: number): Promise<ClientResponse<MonthlyActiveUserReportResponse>> {
    return this.start<MonthlyActiveUserReportResponse, Errors>()
        .withUri('/api/report/monthly-active-user')
        .withParameter('applicationId', applicationId)
        .withParameter('start', start)
        .withParameter('end', end)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves a custom OAuth scope.
   *
   * @param {UUID} applicationId The Id of the application that the OAuth scope belongs to.
   * @param {UUID} scopeId The Id of the OAuth scope to retrieve.
   * @returns {Promise<ClientResponse<ApplicationOAuthScopeResponse>>}
   */
  retrieveOAuthScope(applicationId: UUID, scopeId: UUID): Promise<ClientResponse<ApplicationOAuthScopeResponse>> {
    return this.start<ApplicationOAuthScopeResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("scope")
        .withUriSegment(scopeId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the Oauth2 configuration for the application for the given Application Id.
   *
   * @param {UUID} applicationId The Id of the Application to retrieve OAuth configuration.
   * @returns {Promise<ClientResponse<OAuthConfigurationResponse>>}
   */
  retrieveOauthConfiguration(applicationId: UUID): Promise<ClientResponse<OAuthConfigurationResponse>> {
    return this.start<OAuthConfigurationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("oauth-configuration")
        .withMethod("GET")
        .go();
  }

  /**
   * Returns the well known OpenID Configuration JSON document
   *
   * @returns {Promise<ClientResponse<OpenIdConfiguration>>}
   */
  retrieveOpenIdConfiguration(): Promise<ClientResponse<OpenIdConfiguration>> {
    return this.startAnonymous<OpenIdConfiguration, void>()
        .withUri('/.well-known/openid-configuration')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the password validation rules for a specific tenant. This method requires a tenantId to be provided 
   * through the use of a Tenant scoped API key or an HTTP header X-FusionAuth-TenantId to specify the Tenant Id.
   * 
   * This API does not require an API key.
   *
   * @returns {Promise<ClientResponse<PasswordValidationRulesResponse>>}
   */
  retrievePasswordValidationRules(): Promise<ClientResponse<PasswordValidationRulesResponse>> {
    return this.startAnonymous<PasswordValidationRulesResponse, void>()
        .withUri('/api/tenant/password-validation-rules')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the password validation rules for a specific tenant.
   * 
   * This API does not require an API key.
   *
   * @param {UUID} tenantId The Id of the tenant.
   * @returns {Promise<ClientResponse<PasswordValidationRulesResponse>>}
   */
  retrievePasswordValidationRulesWithTenantId(tenantId: UUID): Promise<ClientResponse<PasswordValidationRulesResponse>> {
    return this.startAnonymous<PasswordValidationRulesResponse, void>()
        .withUri('/api/tenant/password-validation-rules')
        .withUriSegment(tenantId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the children for the given parent email address.
   *
   * @param {string} parentEmail The email of the parent.
   * @returns {Promise<ClientResponse<PendingResponse>>}
   */
  retrievePendingChildren(parentEmail: string): Promise<ClientResponse<PendingResponse>> {
    return this.start<PendingResponse, Errors>()
        .withUri('/api/user/family/pending')
        .withParameter('parentEmail', parentEmail)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieve a pending identity provider link. This is useful to validate a pending link and retrieve meta-data about the identity provider link.
   *
   * @param {string} pendingLinkId The pending link Id.
   * @param {UUID} userId The optional userId. When provided additional meta-data will be provided to identify how many links if any the user already has.
   * @returns {Promise<ClientResponse<IdentityProviderPendingLinkResponse>>}
   */
  retrievePendingLink(pendingLinkId: string, userId: UUID): Promise<ClientResponse<IdentityProviderPendingLinkResponse>> {
    return this.start<IdentityProviderPendingLinkResponse, Errors>()
        .withUri('/api/identity-provider/link/pending')
        .withUriSegment(pendingLinkId)
        .withParameter('userId', userId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the FusionAuth Reactor metrics.
   *
   * @returns {Promise<ClientResponse<ReactorMetricsResponse>>}
   */
  retrieveReactorMetrics(): Promise<ClientResponse<ReactorMetricsResponse>> {
    return this.start<ReactorMetricsResponse, void>()
        .withUri('/api/reactor/metrics')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the FusionAuth Reactor status.
   *
   * @returns {Promise<ClientResponse<ReactorResponse>>}
   */
  retrieveReactorStatus(): Promise<ClientResponse<ReactorResponse>> {
    return this.start<ReactorResponse, void>()
        .withUri('/api/reactor')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the last number of login records.
   *
   * @param {number} offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
   * @param {number} limit (Optional, defaults to 10) The number of records to retrieve.
   * @returns {Promise<ClientResponse<RecentLoginResponse>>}
   */
  retrieveRecentLogins(offset: number, limit: number): Promise<ClientResponse<RecentLoginResponse>> {
    return this.start<RecentLoginResponse, Errors>()
        .withUri('/api/user/recent-login')
        .withParameter('offset', offset)
        .withParameter('limit', limit)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves a single refresh token by unique Id. This is not the same thing as the string value of the refresh token. If you have that, you already have what you need.
   *
   * @param {UUID} tokenId The Id of the token.
   * @returns {Promise<ClientResponse<RefreshTokenResponse>>}
   */
  retrieveRefreshTokenById(tokenId: UUID): Promise<ClientResponse<RefreshTokenResponse>> {
    return this.start<RefreshTokenResponse, Errors>()
        .withUri('/api/jwt/refresh')
        .withUriSegment(tokenId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the refresh tokens that belong to the user with the given Id.
   *
   * @param {UUID} userId The Id of the user.
   * @returns {Promise<ClientResponse<RefreshTokenResponse>>}
   */
  retrieveRefreshTokens(userId: UUID): Promise<ClientResponse<RefreshTokenResponse>> {
    return this.start<RefreshTokenResponse, Errors>()
        .withUri('/api/jwt/refresh')
        .withParameter('userId', userId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the user registration for the user with the given Id and the given application id.
   *
   * @param {UUID} userId The Id of the user.
   * @param {UUID} applicationId The Id of the application.
   * @returns {Promise<ClientResponse<RegistrationResponse>>}
   */
  retrieveRegistration(userId: UUID, applicationId: UUID): Promise<ClientResponse<RegistrationResponse>> {
    return this.start<RegistrationResponse, Errors>()
        .withUri('/api/user/registration')
        .withUriSegment(userId)
        .withUriSegment(applicationId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the registration report between the two instants. If you specify an application id, it will only return
   * the registration counts for that application.
   *
   * @param {UUID} applicationId (Optional) The application id.
   * @param {number} start The start instant as UTC milliseconds since Epoch.
   * @param {number} end The end instant as UTC milliseconds since Epoch.
   * @returns {Promise<ClientResponse<RegistrationReportResponse>>}
   */
  retrieveRegistrationReport(applicationId: UUID, start: number, end: number): Promise<ClientResponse<RegistrationReportResponse>> {
    return this.start<RegistrationReportResponse, Errors>()
        .withUri('/api/report/registration')
        .withParameter('applicationId', applicationId)
        .withParameter('start', start)
        .withParameter('end', end)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieve the status of a re-index process. A status code of 200 indicates the re-index is in progress, a status code of  
   * 404 indicates no re-index is in progress.
   *
   * @returns {Promise<ClientResponse<void>>}
   */
  retrieveReindexStatus(): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/system/reindex')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the system configuration.
   *
   * @returns {Promise<ClientResponse<SystemConfigurationResponse>>}
   */
  retrieveSystemConfiguration(): Promise<ClientResponse<SystemConfigurationResponse>> {
    return this.start<SystemConfigurationResponse, void>()
        .withUri('/api/system-configuration')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the FusionAuth system health. This API will return 200 if the system is healthy, and 500 if the system is un-healthy.
   *
   * @returns {Promise<ClientResponse<void>>}
   */
  retrieveSystemHealth(): Promise<ClientResponse<void>> {
    return this.startAnonymous<void, void>()
        .withUri('/api/health')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the FusionAuth system status. This request is anonymous and does not require an API key. When an API key is not provided the response will contain a single value in the JSON response indicating the current health check.
   *
   * @returns {Promise<ClientResponse<StatusResponse>>}
   */
  retrieveSystemStatus(): Promise<ClientResponse<StatusResponse>> {
    return this.startAnonymous<StatusResponse, void>()
        .withUri('/api/status')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the FusionAuth system status using an API key. Using an API key will cause the response to include the product version, health checks and various runtime metrics.
   *
   * @returns {Promise<ClientResponse<StatusResponse>>}
   */
  retrieveSystemStatusUsingAPIKey(): Promise<ClientResponse<StatusResponse>> {
    return this.start<StatusResponse, void>()
        .withUri('/api/status')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the tenant for the given Id.
   *
   * @param {UUID} tenantId The Id of the tenant.
   * @returns {Promise<ClientResponse<TenantResponse>>}
   */
  retrieveTenant(tenantId: UUID): Promise<ClientResponse<TenantResponse>> {
    return this.start<TenantResponse, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the tenants.
   *
   * @returns {Promise<ClientResponse<TenantResponse>>}
   */
  retrieveTenants(): Promise<ClientResponse<TenantResponse>> {
    return this.start<TenantResponse, void>()
        .withUri('/api/tenant')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the theme for the given Id.
   *
   * @param {UUID} themeId The Id of the theme.
   * @returns {Promise<ClientResponse<ThemeResponse>>}
   */
  retrieveTheme(themeId: UUID): Promise<ClientResponse<ThemeResponse>> {
    return this.start<ThemeResponse, Errors>()
        .withUri('/api/theme')
        .withUriSegment(themeId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the themes.
   *
   * @returns {Promise<ClientResponse<ThemeResponse>>}
   */
  retrieveThemes(): Promise<ClientResponse<ThemeResponse>> {
    return this.start<ThemeResponse, void>()
        .withUri('/api/theme')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the totals report. This contains all the total counts for each application and the global registration
   * count.
   *
   * @returns {Promise<ClientResponse<TotalsReportResponse>>}
   */
  retrieveTotalReport(): Promise<ClientResponse<TotalsReportResponse>> {
    return this.start<TotalsReportResponse, void>()
        .withUri('/api/report/totals')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieve two-factor recovery codes for a user.
   *
   * @param {UUID} userId The Id of the user to retrieve Two Factor recovery codes.
   * @returns {Promise<ClientResponse<TwoFactorRecoveryCodeResponse>>}
   */
  retrieveTwoFactorRecoveryCodes(userId: UUID): Promise<ClientResponse<TwoFactorRecoveryCodeResponse>> {
    return this.start<TwoFactorRecoveryCodeResponse, Errors>()
        .withUri('/api/user/two-factor/recovery-code')
        .withUriSegment(userId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieve a user's two-factor status.
   * 
   * This can be used to see if a user will need to complete a two-factor challenge to complete a login,
   * and optionally identify the state of the two-factor trust across various applications.
   *
   * @param {UUID} userId The user Id to retrieve the Two-Factor status.
   * @param {UUID} applicationId The optional applicationId to verify.
   * @param {string} twoFactorTrustId The optional two-factor trust Id to verify.
   * @returns {Promise<ClientResponse<TwoFactorStatusResponse>>}
   */
  retrieveTwoFactorStatus(userId: UUID, applicationId: UUID, twoFactorTrustId: string): Promise<ClientResponse<TwoFactorStatusResponse>> {
    return this.start<TwoFactorStatusResponse, Errors>()
        .withUri('/api/two-factor/status')
        .withParameter('userId', userId)
        .withParameter('applicationId', applicationId)
        .withUriSegment(twoFactorTrustId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the user for the given Id.
   *
   * @param {UUID} userId The Id of the user.
   * @returns {Promise<ClientResponse<UserResponse>>}
   */
  retrieveUser(userId: UUID): Promise<ClientResponse<UserResponse>> {
    return this.start<UserResponse, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the user action for the given Id. If you pass in null for the id, this will return all the user
   * actions.
   *
   * @param {UUID} userActionId (Optional) The Id of the user action.
   * @returns {Promise<ClientResponse<UserActionResponse>>}
   */
  retrieveUserAction(userActionId: UUID): Promise<ClientResponse<UserActionResponse>> {
    return this.start<UserActionResponse, void>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the user action reason for the given Id. If you pass in null for the id, this will return all the user
   * action reasons.
   *
   * @param {UUID} userActionReasonId (Optional) The Id of the user action reason.
   * @returns {Promise<ClientResponse<UserActionReasonResponse>>}
   */
  retrieveUserActionReason(userActionReasonId: UUID): Promise<ClientResponse<UserActionReasonResponse>> {
    return this.start<UserActionReasonResponse, void>()
        .withUri('/api/user-action-reason')
        .withUriSegment(userActionReasonId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the user action reasons.
   *
   * @returns {Promise<ClientResponse<UserActionReasonResponse>>}
   */
  retrieveUserActionReasons(): Promise<ClientResponse<UserActionReasonResponse>> {
    return this.start<UserActionReasonResponse, void>()
        .withUri('/api/user-action-reason')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the user actions.
   *
   * @returns {Promise<ClientResponse<UserActionResponse>>}
   */
  retrieveUserActions(): Promise<ClientResponse<UserActionResponse>> {
    return this.start<UserActionResponse, void>()
        .withUri('/api/user-action')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the user by a change password Id. The intended use of this API is to retrieve a user after the forgot
   * password workflow has been initiated and you may not know the user's email or username.
   *
   * @param {string} changePasswordId The unique change password Id that was sent via email or returned by the Forgot Password API.
   * @returns {Promise<ClientResponse<UserResponse>>}
   */
  retrieveUserByChangePasswordId(changePasswordId: string): Promise<ClientResponse<UserResponse>> {
    return this.start<UserResponse, Errors>()
        .withUri('/api/user')
        .withParameter('changePasswordId', changePasswordId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the user for the given email.
   *
   * @param {string} email The email of the user.
   * @returns {Promise<ClientResponse<UserResponse>>}
   */
  retrieveUserByEmail(email: string): Promise<ClientResponse<UserResponse>> {
    return this.start<UserResponse, Errors>()
        .withUri('/api/user')
        .withParameter('email', email)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the user for the loginId. The loginId can be either the username or the email.
   *
   * @param {string} loginId The email or username of the user.
   * @returns {Promise<ClientResponse<UserResponse>>}
   */
  retrieveUserByLoginId(loginId: string): Promise<ClientResponse<UserResponse>> {
    return this.start<UserResponse, Errors>()
        .withUri('/api/user')
        .withParameter('loginId', loginId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the user for the given username.
   *
   * @param {string} username The username of the user.
   * @returns {Promise<ClientResponse<UserResponse>>}
   */
  retrieveUserByUsername(username: string): Promise<ClientResponse<UserResponse>> {
    return this.start<UserResponse, Errors>()
        .withUri('/api/user')
        .withParameter('username', username)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the user by a verificationId. The intended use of this API is to retrieve a user after the forgot
   * password workflow has been initiated and you may not know the user's email or username.
   *
   * @param {string} verificationId The unique verification Id that has been set on the user object.
   * @returns {Promise<ClientResponse<UserResponse>>}
   */
  retrieveUserByVerificationId(verificationId: string): Promise<ClientResponse<UserResponse>> {
    return this.start<UserResponse, Errors>()
        .withUri('/api/user')
        .withParameter('verificationId', verificationId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieve a user_code that is part of an in-progress Device Authorization Grant.
   * 
   * This API is useful if you want to build your own login workflow to complete a device grant.
   *
   * @param {string} client_id The client id.
   * @param {string} client_secret The client id.
   * @param {string} user_code The end-user verification code.
   * @returns {Promise<ClientResponse<void>>}
   */
  retrieveUserCode(client_id: string, client_secret: string, user_code: string): Promise<ClientResponse<void>> {
    let body = new URLSearchParams();

    body.append('client_id', client_id);
    body.append('client_secret', client_secret);
    body.append('user_code', user_code);
    return this.startAnonymous<void, void>()
        .withUri('/oauth2/device/user-code')
        .withFormData(body)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieve a user_code that is part of an in-progress Device Authorization Grant.
   * 
   * This API is useful if you want to build your own login workflow to complete a device grant.
   * 
   * This request will require an API key.
   *
   * @param {string} user_code The end-user verification code.
   * @returns {Promise<ClientResponse<void>>}
   */
  retrieveUserCodeUsingAPIKey(user_code: string): Promise<ClientResponse<void>> {
    let body = new URLSearchParams();

    body.append('user_code', user_code);
    return this.startAnonymous<void, void>()
        .withUri('/oauth2/device/user-code')
        .withFormData(body)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the comments for the user with the given Id.
   *
   * @param {UUID} userId The Id of the user.
   * @returns {Promise<ClientResponse<UserCommentResponse>>}
   */
  retrieveUserComments(userId: UUID): Promise<ClientResponse<UserCommentResponse>> {
    return this.start<UserCommentResponse, Errors>()
        .withUri('/api/user/comment')
        .withUriSegment(userId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieve a single User consent by Id.
   *
   * @param {UUID} userConsentId The User consent Id
   * @returns {Promise<ClientResponse<UserConsentResponse>>}
   */
  retrieveUserConsent(userConsentId: UUID): Promise<ClientResponse<UserConsentResponse>> {
    return this.start<UserConsentResponse, void>()
        .withUri('/api/user/consent')
        .withUriSegment(userConsentId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the consents for a User.
   *
   * @param {UUID} userId The User's Id
   * @returns {Promise<ClientResponse<UserConsentResponse>>}
   */
  retrieveUserConsents(userId: UUID): Promise<ClientResponse<UserConsentResponse>> {
    return this.start<UserConsentResponse, void>()
        .withUri('/api/user/consent')
        .withParameter('userId', userId)
        .withMethod("GET")
        .go();
  }

  /**
   * Call the UserInfo endpoint to retrieve User Claims from the access token issued by FusionAuth.
   *
   * @param {string} encodedJWT The encoded JWT (access token).
   * @returns {Promise<ClientResponse<UserinfoResponse>>}
   */
  retrieveUserInfoFromAccessToken(encodedJWT: string): Promise<ClientResponse<UserinfoResponse>> {
    return this.startAnonymous<UserinfoResponse, OAuthError>()
        .withUri('/oauth2/userinfo')
        .withAuthorization('Bearer ' + encodedJWT)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieve a single Identity Provider user (link).
   *
   * @param {UUID} identityProviderId The unique Id of the identity provider.
   * @param {string} identityProviderUserId The unique Id of the user in the 3rd party identity provider.
   * @param {UUID} userId The unique Id of the FusionAuth user.
   * @returns {Promise<ClientResponse<IdentityProviderLinkResponse>>}
   */
  retrieveUserLink(identityProviderId: UUID, identityProviderUserId: string, userId: UUID): Promise<ClientResponse<IdentityProviderLinkResponse>> {
    return this.start<IdentityProviderLinkResponse, Errors>()
        .withUri('/api/identity-provider/link')
        .withParameter('identityProviderId', identityProviderId)
        .withParameter('identityProviderUserId', identityProviderUserId)
        .withParameter('userId', userId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieve all Identity Provider users (links) for the user. Specify the optional identityProviderId to retrieve links for a particular IdP.
   *
   * @param {UUID} identityProviderId (Optional) The unique Id of the identity provider. Specify this value to reduce the links returned to those for a particular IdP.
   * @param {UUID} userId The unique Id of the user.
   * @returns {Promise<ClientResponse<IdentityProviderLinkResponse>>}
   */
  retrieveUserLinksByUserId(identityProviderId: UUID, userId: UUID): Promise<ClientResponse<IdentityProviderLinkResponse>> {
    return this.start<IdentityProviderLinkResponse, Errors>()
        .withUri('/api/identity-provider/link')
        .withParameter('identityProviderId', identityProviderId)
        .withParameter('userId', userId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the login report between the two instants for a particular user by Id. If you specify an application id, it will only return the
   * login counts for that application.
   *
   * @param {UUID} applicationId (Optional) The application id.
   * @param {UUID} userId The userId id.
   * @param {number} start The start instant as UTC milliseconds since Epoch.
   * @param {number} end The end instant as UTC milliseconds since Epoch.
   * @returns {Promise<ClientResponse<LoginReportResponse>>}
   */
  retrieveUserLoginReport(applicationId: UUID, userId: UUID, start: number, end: number): Promise<ClientResponse<LoginReportResponse>> {
    return this.start<LoginReportResponse, Errors>()
        .withUri('/api/report/login')
        .withParameter('applicationId', applicationId)
        .withParameter('userId', userId)
        .withParameter('start', start)
        .withParameter('end', end)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the login report between the two instants for a particular user by login Id. If you specify an application id, it will only return the
   * login counts for that application.
   *
   * @param {UUID} applicationId (Optional) The application id.
   * @param {string} loginId The userId id.
   * @param {number} start The start instant as UTC milliseconds since Epoch.
   * @param {number} end The end instant as UTC milliseconds since Epoch.
   * @returns {Promise<ClientResponse<LoginReportResponse>>}
   */
  retrieveUserLoginReportByLoginId(applicationId: UUID, loginId: string, start: number, end: number): Promise<ClientResponse<LoginReportResponse>> {
    return this.start<LoginReportResponse, Errors>()
        .withUri('/api/report/login')
        .withParameter('applicationId', applicationId)
        .withParameter('loginId', loginId)
        .withParameter('start', start)
        .withParameter('end', end)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the last number of login records for a user.
   *
   * @param {UUID} userId The Id of the user.
   * @param {number} offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
   * @param {number} limit (Optional, defaults to 10) The number of records to retrieve.
   * @returns {Promise<ClientResponse<RecentLoginResponse>>}
   */
  retrieveUserRecentLogins(userId: UUID, offset: number, limit: number): Promise<ClientResponse<RecentLoginResponse>> {
    return this.start<RecentLoginResponse, Errors>()
        .withUri('/api/user/recent-login')
        .withParameter('userId', userId)
        .withParameter('offset', offset)
        .withParameter('limit', limit)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the user for the given Id. This method does not use an API key, instead it uses a JSON Web Token (JWT) for authentication.
   *
   * @param {string} encodedJWT The encoded JWT (access token).
   * @returns {Promise<ClientResponse<UserResponse>>}
   */
  retrieveUserUsingJWT(encodedJWT: string): Promise<ClientResponse<UserResponse>> {
    return this.startAnonymous<UserResponse, Errors>()
        .withUri('/api/user')
        .withAuthorization('Bearer ' + encodedJWT)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the FusionAuth version string.
   *
   * @returns {Promise<ClientResponse<VersionResponse>>}
   */
  retrieveVersion(): Promise<ClientResponse<VersionResponse>> {
    return this.start<VersionResponse, Errors>()
        .withUri('/api/system/version')
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the WebAuthn credential for the given Id.
   *
   * @param {UUID} id The Id of the WebAuthn credential.
   * @returns {Promise<ClientResponse<WebAuthnCredentialResponse>>}
   */
  retrieveWebAuthnCredential(id: UUID): Promise<ClientResponse<WebAuthnCredentialResponse>> {
    return this.start<WebAuthnCredentialResponse, Errors>()
        .withUri('/api/webauthn')
        .withUriSegment(id)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all WebAuthn credentials for the given user.
   *
   * @param {UUID} userId The user's ID.
   * @returns {Promise<ClientResponse<WebAuthnCredentialResponse>>}
   */
  retrieveWebAuthnCredentialsForUser(userId: UUID): Promise<ClientResponse<WebAuthnCredentialResponse>> {
    return this.start<WebAuthnCredentialResponse, Errors>()
        .withUri('/api/webauthn')
        .withParameter('userId', userId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the webhook for the given Id. If you pass in null for the id, this will return all the webhooks.
   *
   * @param {UUID} webhookId (Optional) The Id of the webhook.
   * @returns {Promise<ClientResponse<WebhookResponse>>}
   */
  retrieveWebhook(webhookId: UUID): Promise<ClientResponse<WebhookResponse>> {
    return this.start<WebhookResponse, void>()
        .withUri('/api/webhook')
        .withUriSegment(webhookId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves a single webhook attempt log for the given Id.
   *
   * @param {UUID} webhookAttemptLogId The Id of the webhook attempt log to retrieve.
   * @returns {Promise<ClientResponse<WebhookAttemptLogResponse>>}
   */
  retrieveWebhookAttemptLog(webhookAttemptLogId: UUID): Promise<ClientResponse<WebhookAttemptLogResponse>> {
    return this.start<WebhookAttemptLogResponse, Errors>()
        .withUri('/api/system/webhook-attempt-log')
        .withUriSegment(webhookAttemptLogId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves a single webhook event log for the given Id.
   *
   * @param {UUID} webhookEventLogId The Id of the webhook event log to retrieve.
   * @returns {Promise<ClientResponse<WebhookEventLogResponse>>}
   */
  retrieveWebhookEventLog(webhookEventLogId: UUID): Promise<ClientResponse<WebhookEventLogResponse>> {
    return this.start<WebhookEventLogResponse, Errors>()
        .withUri('/api/system/webhook-event-log')
        .withUriSegment(webhookEventLogId)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves all the webhooks.
   *
   * @returns {Promise<ClientResponse<WebhookResponse>>}
   */
  retrieveWebhooks(): Promise<ClientResponse<WebhookResponse>> {
    return this.start<WebhookResponse, void>()
        .withUri('/api/webhook')
        .withMethod("GET")
        .go();
  }

  /**
   * Revokes refresh tokens.
   * 
   * Usage examples:
   *   - Delete a single refresh token, pass in only the token.
   *       revokeRefreshToken(token)
   * 
   *   - Delete all refresh tokens for a user, pass in only the userId.
   *       revokeRefreshToken(null, userId)
   * 
   *   - Delete all refresh tokens for a user for a specific application, pass in both the userId and the applicationId.
   *       revokeRefreshToken(null, userId, applicationId)
   * 
   *   - Delete all refresh tokens for an application
   *       revokeRefreshToken(null, null, applicationId)
   * 
   * Note: <code>null</code> may be handled differently depending upon the programming language.
   * 
   * See also: (method names may vary by language... but you'll figure it out)
   * 
   *  - revokeRefreshTokenById
   *  - revokeRefreshTokenByToken
   *  - revokeRefreshTokensByUserId
   *  - revokeRefreshTokensByApplicationId
   *  - revokeRefreshTokensByUserIdForApplication
   *
   * @param {string} token (Optional) The refresh token to delete.
   * @param {UUID} userId (Optional) The user Id whose tokens to delete.
   * @param {UUID} applicationId (Optional) The application Id of the tokens to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  revokeRefreshToken(token: string, userId: UUID, applicationId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withParameter('token', token)
        .withParameter('userId', userId)
        .withParameter('applicationId', applicationId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Revokes a single refresh token by the unique Id. The unique Id is not sensitive as it cannot be used to obtain another JWT.
   *
   * @param {UUID} tokenId The unique Id of the token to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  revokeRefreshTokenById(tokenId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withUriSegment(tokenId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Revokes a single refresh token by using the actual refresh token value. This refresh token value is sensitive, so  be careful with this API request.
   *
   * @param {string} token The refresh token to delete.
   * @returns {Promise<ClientResponse<void>>}
   */
  revokeRefreshTokenByToken(token: string): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withParameter('token', token)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Revoke all refresh tokens that belong to an application by applicationId.
   *
   * @param {UUID} applicationId The unique Id of the application that you want to delete all refresh tokens for.
   * @returns {Promise<ClientResponse<void>>}
   */
  revokeRefreshTokensByApplicationId(applicationId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withParameter('applicationId', applicationId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Revoke all refresh tokens that belong to a user by user Id.
   *
   * @param {UUID} userId The unique Id of the user that you want to delete all refresh tokens for.
   * @returns {Promise<ClientResponse<void>>}
   */
  revokeRefreshTokensByUserId(userId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withParameter('userId', userId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Revoke all refresh tokens that belong to a user by user Id for a specific application by applicationId.
   *
   * @param {UUID} userId The unique Id of the user that you want to delete all refresh tokens for.
   * @param {UUID} applicationId The unique Id of the application that you want to delete refresh tokens for.
   * @returns {Promise<ClientResponse<void>>}
   */
  revokeRefreshTokensByUserIdForApplication(userId: UUID, applicationId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withParameter('userId', userId)
        .withParameter('applicationId', applicationId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Revokes refresh tokens using the information in the JSON body. The handling for this method is the same as the revokeRefreshToken method
   * and is based on the information you provide in the RefreshDeleteRequest object. See that method for additional information.
   *
   * @param {RefreshTokenRevokeRequest} request The request information used to revoke the refresh tokens.
   * @returns {Promise<ClientResponse<void>>}
   */
  revokeRefreshTokensWithRequest(request: RefreshTokenRevokeRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withJSONBody(request)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Revokes a single User consent by Id.
   *
   * @param {UUID} userConsentId The User Consent Id
   * @returns {Promise<ClientResponse<void>>}
   */
  revokeUserConsent(userConsentId: UUID): Promise<ClientResponse<void>> {
    return this.start<void, void>()
        .withUri('/api/user/consent')
        .withUriSegment(userConsentId)
        .withMethod("DELETE")
        .go();
  }

  /**
   * Searches applications with the specified criteria and pagination.
   *
   * @param {ApplicationSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<ApplicationSearchResponse>>}
   */
  searchApplications(request: ApplicationSearchRequest): Promise<ClientResponse<ApplicationSearchResponse>> {
    return this.start<ApplicationSearchResponse, Errors>()
        .withUri('/api/application/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches the audit logs with the specified criteria and pagination.
   *
   * @param {AuditLogSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<AuditLogSearchResponse>>}
   */
  searchAuditLogs(request: AuditLogSearchRequest): Promise<ClientResponse<AuditLogSearchResponse>> {
    return this.start<AuditLogSearchResponse, Errors>()
        .withUri('/api/system/audit-log/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches consents with the specified criteria and pagination.
   *
   * @param {ConsentSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<ConsentSearchResponse>>}
   */
  searchConsents(request: ConsentSearchRequest): Promise<ClientResponse<ConsentSearchResponse>> {
    return this.start<ConsentSearchResponse, Errors>()
        .withUri('/api/consent/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches email templates with the specified criteria and pagination.
   *
   * @param {EmailTemplateSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<EmailTemplateSearchResponse>>}
   */
  searchEmailTemplates(request: EmailTemplateSearchRequest): Promise<ClientResponse<EmailTemplateSearchResponse>> {
    return this.start<EmailTemplateSearchResponse, Errors>()
        .withUri('/api/email/template/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches entities with the specified criteria and pagination.
   *
   * @param {EntitySearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<EntitySearchResponse>>}
   */
  searchEntities(request: EntitySearchRequest): Promise<ClientResponse<EntitySearchResponse>> {
    return this.start<EntitySearchResponse, Errors>()
        .withUri('/api/entity/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Retrieves the entities for the given ids. If any Id is invalid, it is ignored.
   *
   * @param {Array<string>} ids The entity ids to search for.
   * @returns {Promise<ClientResponse<EntitySearchResponse>>}
   */
  searchEntitiesByIds(ids: Array<string>): Promise<ClientResponse<EntitySearchResponse>> {
    return this.start<EntitySearchResponse, Errors>()
        .withUri('/api/entity/search')
        .withParameter('ids', ids)
        .withMethod("GET")
        .go();
  }

  /**
   * Searches Entity Grants with the specified criteria and pagination.
   *
   * @param {EntityGrantSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<EntityGrantSearchResponse>>}
   */
  searchEntityGrants(request: EntityGrantSearchRequest): Promise<ClientResponse<EntityGrantSearchResponse>> {
    return this.start<EntityGrantSearchResponse, Errors>()
        .withUri('/api/entity/grant/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches the entity types with the specified criteria and pagination.
   *
   * @param {EntityTypeSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<EntityTypeSearchResponse>>}
   */
  searchEntityTypes(request: EntityTypeSearchRequest): Promise<ClientResponse<EntityTypeSearchResponse>> {
    return this.start<EntityTypeSearchResponse, Errors>()
        .withUri('/api/entity/type/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches the event logs with the specified criteria and pagination.
   *
   * @param {EventLogSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<EventLogSearchResponse>>}
   */
  searchEventLogs(request: EventLogSearchRequest): Promise<ClientResponse<EventLogSearchResponse>> {
    return this.start<EventLogSearchResponse, Errors>()
        .withUri('/api/system/event-log/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches group members with the specified criteria and pagination.
   *
   * @param {GroupMemberSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<GroupMemberSearchResponse>>}
   */
  searchGroupMembers(request: GroupMemberSearchRequest): Promise<ClientResponse<GroupMemberSearchResponse>> {
    return this.start<GroupMemberSearchResponse, Errors>()
        .withUri('/api/group/member/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches groups with the specified criteria and pagination.
   *
   * @param {GroupSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<GroupSearchResponse>>}
   */
  searchGroups(request: GroupSearchRequest): Promise<ClientResponse<GroupSearchResponse>> {
    return this.start<GroupSearchResponse, Errors>()
        .withUri('/api/group/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches the IP Access Control Lists with the specified criteria and pagination.
   *
   * @param {IPAccessControlListSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<IPAccessControlListSearchResponse>>}
   */
  searchIPAccessControlLists(request: IPAccessControlListSearchRequest): Promise<ClientResponse<IPAccessControlListSearchResponse>> {
    return this.start<IPAccessControlListSearchResponse, Errors>()
        .withUri('/api/ip-acl/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches identity providers with the specified criteria and pagination.
   *
   * @param {IdentityProviderSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<IdentityProviderSearchResponse>>}
   */
  searchIdentityProviders(request: IdentityProviderSearchRequest): Promise<ClientResponse<IdentityProviderSearchResponse>> {
    return this.start<IdentityProviderSearchResponse, Errors>()
        .withUri('/api/identity-provider/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches keys with the specified criteria and pagination.
   *
   * @param {KeySearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<KeySearchResponse>>}
   */
  searchKeys(request: KeySearchRequest): Promise<ClientResponse<KeySearchResponse>> {
    return this.start<KeySearchResponse, Errors>()
        .withUri('/api/key/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches lambdas with the specified criteria and pagination.
   *
   * @param {LambdaSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<LambdaSearchResponse>>}
   */
  searchLambdas(request: LambdaSearchRequest): Promise<ClientResponse<LambdaSearchResponse>> {
    return this.start<LambdaSearchResponse, Errors>()
        .withUri('/api/lambda/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches the login records with the specified criteria and pagination.
   *
   * @param {LoginRecordSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<LoginRecordSearchResponse>>}
   */
  searchLoginRecords(request: LoginRecordSearchRequest): Promise<ClientResponse<LoginRecordSearchResponse>> {
    return this.start<LoginRecordSearchResponse, Errors>()
        .withUri('/api/system/login-record/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches tenants with the specified criteria and pagination.
   *
   * @param {TenantSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<TenantSearchResponse>>}
   */
  searchTenants(request: TenantSearchRequest): Promise<ClientResponse<TenantSearchResponse>> {
    return this.start<TenantSearchResponse, Errors>()
        .withUri('/api/tenant/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches themes with the specified criteria and pagination.
   *
   * @param {ThemeSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<ThemeSearchResponse>>}
   */
  searchThemes(request: ThemeSearchRequest): Promise<ClientResponse<ThemeSearchResponse>> {
    return this.start<ThemeSearchResponse, Errors>()
        .withUri('/api/theme/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches user comments with the specified criteria and pagination.
   *
   * @param {UserCommentSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<UserCommentSearchResponse>>}
   */
  searchUserComments(request: UserCommentSearchRequest): Promise<ClientResponse<UserCommentSearchResponse>> {
    return this.start<UserCommentSearchResponse, Errors>()
        .withUri('/api/user/comment/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Retrieves the users for the given ids. If any Id is invalid, it is ignored.
   *
   * @param {Array<string>} ids The user ids to search for.
   * @returns {Promise<ClientResponse<SearchResponse>>}
   *
   * @deprecated This method has been renamed to searchUsersByIds, use that method instead.
   */
  searchUsers(ids: Array<string>): Promise<ClientResponse<SearchResponse>> {
    return this.start<SearchResponse, Errors>()
        .withUri('/api/user/search')
        .withParameter('ids', ids)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the users for the given ids. If any Id is invalid, it is ignored.
   *
   * @param {Array<string>} ids The user ids to search for.
   * @returns {Promise<ClientResponse<SearchResponse>>}
   */
  searchUsersByIds(ids: Array<string>): Promise<ClientResponse<SearchResponse>> {
    return this.start<SearchResponse, Errors>()
        .withUri('/api/user/search')
        .withParameter('ids', ids)
        .withMethod("GET")
        .go();
  }

  /**
   * Retrieves the users for the given search criteria and pagination.
   *
   * @param {SearchRequest} request The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
   *    and sortFields.
   * @returns {Promise<ClientResponse<SearchResponse>>}
   */
  searchUsersByQuery(request: SearchRequest): Promise<ClientResponse<SearchResponse>> {
    return this.start<SearchResponse, Errors>()
        .withUri('/api/user/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Retrieves the users for the given search criteria and pagination.
   *
   * @param {SearchRequest} request The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
   *    and sortFields.
   * @returns {Promise<ClientResponse<SearchResponse>>}
   *
   * @deprecated This method has been renamed to searchUsersByQuery, use that method instead.
   */
  searchUsersByQueryString(request: SearchRequest): Promise<ClientResponse<SearchResponse>> {
    return this.start<SearchResponse, Errors>()
        .withUri('/api/user/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches the webhook event logs with the specified criteria and pagination.
   *
   * @param {WebhookEventLogSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<WebhookEventLogSearchResponse>>}
   */
  searchWebhookEventLogs(request: WebhookEventLogSearchRequest): Promise<ClientResponse<WebhookEventLogSearchResponse>> {
    return this.start<WebhookEventLogSearchResponse, Errors>()
        .withUri('/api/system/webhook-event-log/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Searches webhooks with the specified criteria and pagination.
   *
   * @param {WebhookSearchRequest} request The search criteria and pagination information.
   * @returns {Promise<ClientResponse<WebhookSearchResponse>>}
   */
  searchWebhooks(request: WebhookSearchRequest): Promise<ClientResponse<WebhookSearchResponse>> {
    return this.start<WebhookSearchResponse, Errors>()
        .withUri('/api/webhook/search')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Send an email using an email template id. You can optionally provide <code>requestData</code> to access key value
   * pairs in the email template.
   *
   * @param {UUID} emailTemplateId The Id for the template.
   * @param {SendRequest} request The send email request that contains all the information used to send the email.
   * @returns {Promise<ClientResponse<SendResponse>>}
   */
  sendEmail(emailTemplateId: UUID, request: SendRequest): Promise<ClientResponse<SendResponse>> {
    return this.start<SendResponse, Errors>()
        .withUri('/api/email/send')
        .withUriSegment(emailTemplateId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Sends out an email to a parent that they need to register and create a family or need to log in and add a child to their existing family.
   *
   * @param {FamilyEmailRequest} request The request object that contains the parent email.
   * @returns {Promise<ClientResponse<void>>}
   */
  sendFamilyRequestEmail(request: FamilyEmailRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user/family/request')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Send a passwordless authentication code in an email to complete login.
   *
   * @param {PasswordlessSendRequest} request The passwordless send request that contains all the information used to send an email containing a code.
   * @returns {Promise<ClientResponse<void>>}
   */
  sendPasswordlessCode(request: PasswordlessSendRequest): Promise<ClientResponse<void>> {
    return this.startAnonymous<void, Errors>()
        .withUri('/api/passwordless/send')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
   *
   * @param {TwoFactorSendRequest} request The request object that contains all the information used to send the code.
   * @returns {Promise<ClientResponse<void>>}
   *
   * @deprecated This method has been renamed to sendTwoFactorCodeForEnableDisable, use that method instead.
   */
  sendTwoFactorCode(request: TwoFactorSendRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/two-factor/send')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
   *
   * @param {TwoFactorSendRequest} request The request object that contains all the information used to send the code.
   * @returns {Promise<ClientResponse<void>>}
   */
  sendTwoFactorCodeForEnableDisable(request: TwoFactorSendRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/two-factor/send')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Send a Two Factor authentication code to allow the completion of Two Factor authentication.
   *
   * @param {string} twoFactorId The Id returned by the Login API necessary to complete Two Factor authentication.
   * @returns {Promise<ClientResponse<void>>}
   *
   * @deprecated This method has been renamed to sendTwoFactorCodeForLoginUsingMethod, use that method instead.
   */
  sendTwoFactorCodeForLogin(twoFactorId: string): Promise<ClientResponse<void>> {
    return this.startAnonymous<void, Errors>()
        .withHeader('Content-Type', 'text/plain')
        .withUri('/api/two-factor/send')
        .withUriSegment(twoFactorId)
        .withMethod("POST")
        .go();
  }

  /**
   * Send a Two Factor authentication code to allow the completion of Two Factor authentication.
   *
   * @param {string} twoFactorId The Id returned by the Login API necessary to complete Two Factor authentication.
   * @param {TwoFactorSendRequest} request The Two Factor send request that contains all the information used to send the Two Factor code to the user.
   * @returns {Promise<ClientResponse<void>>}
   */
  sendTwoFactorCodeForLoginUsingMethod(twoFactorId: string, request: TwoFactorSendRequest): Promise<ClientResponse<void>> {
    return this.startAnonymous<void, Errors>()
        .withUri('/api/two-factor/send')
        .withUriSegment(twoFactorId)
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Send a verification code using the appropriate transport for the identity type being verified.
   *
   * @param {VerifySendCompleteRequest} request The identity verify send request that contains all the information used send the code.
   * @returns {Promise<ClientResponse<void>>}
   */
  sendVerifyIdentity(request: VerifySendCompleteRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/identity/verify/send')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Begins a login request for a 3rd party login that requires user interaction such as HYPR.
   *
   * @param {IdentityProviderStartLoginRequest} request The third-party login request that contains information from the third-party login
   *    providers that FusionAuth uses to reconcile the user's account.
   * @returns {Promise<ClientResponse<IdentityProviderStartLoginResponse>>}
   */
  startIdentityProviderLogin(request: IdentityProviderStartLoginRequest): Promise<ClientResponse<IdentityProviderStartLoginResponse>> {
    return this.start<IdentityProviderStartLoginResponse, Errors>()
        .withUri('/api/identity-provider/start')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Start a passwordless login request by generating a passwordless code. This code can be sent to the User using the Send
   * Passwordless Code API or using a mechanism outside of FusionAuth. The passwordless login is completed by using the Passwordless Login API with this code.
   *
   * @param {PasswordlessStartRequest} request The passwordless start request that contains all the information used to begin the passwordless login request.
   * @returns {Promise<ClientResponse<PasswordlessStartResponse>>}
   */
  startPasswordlessLogin(request: PasswordlessStartRequest): Promise<ClientResponse<PasswordlessStartResponse>> {
    return this.start<PasswordlessStartResponse, Errors>()
        .withUri('/api/passwordless/start')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Start a Two-Factor login request by generating a two-factor identifier. This code can then be sent to the Two Factor Send 
   * API (/api/two-factor/send)in order to send a one-time use code to a user. You can also use one-time use code returned 
   * to send the code out-of-band. The Two-Factor login is completed by making a request to the Two-Factor Login 
   * API (/api/two-factor/login). with the two-factor identifier and the one-time use code.
   * 
   * This API is intended to allow you to begin a Two-Factor login outside a normal login that originated from the Login API (/api/login).
   *
   * @param {TwoFactorStartRequest} request The Two-Factor start request that contains all the information used to begin the Two-Factor login request.
   * @returns {Promise<ClientResponse<TwoFactorStartResponse>>}
   */
  startTwoFactorLogin(request: TwoFactorStartRequest): Promise<ClientResponse<TwoFactorStartResponse>> {
    return this.start<TwoFactorStartResponse, Errors>()
        .withUri('/api/two-factor/start')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Start a verification of an identity by generating a code. This code can be sent to the User using the Verify Send API
   * Verification Code API or using a mechanism outside of FusionAuth. The verification is completed by using the Verify Complete API with this code.
   *
   * @param {VerifyStartRequest} request The identity verify start request that contains all the information used to begin the request.
   * @returns {Promise<ClientResponse<VerifyStartResponse>>}
   */
  startVerifyIdentity(request: VerifyStartRequest): Promise<ClientResponse<VerifyStartResponse>> {
    return this.start<VerifyStartResponse, Errors>()
        .withUri('/api/identity/verify/start')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Start a WebAuthn authentication ceremony by generating a new challenge for the user
   *
   * @param {WebAuthnStartRequest} request An object containing data necessary for starting the authentication ceremony
   * @returns {Promise<ClientResponse<WebAuthnStartResponse>>}
   */
  startWebAuthnLogin(request: WebAuthnStartRequest): Promise<ClientResponse<WebAuthnStartResponse>> {
    return this.start<WebAuthnStartResponse, Errors>()
        .withUri('/api/webauthn/start')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Start a WebAuthn registration ceremony by generating a new challenge for the user
   *
   * @param {WebAuthnRegisterStartRequest} request An object containing data necessary for starting the registration ceremony
   * @returns {Promise<ClientResponse<WebAuthnRegisterStartResponse>>}
   */
  startWebAuthnRegistration(request: WebAuthnRegisterStartRequest): Promise<ClientResponse<WebAuthnRegisterStartResponse>> {
    return this.start<WebAuthnRegisterStartResponse, Errors>()
        .withUri('/api/webauthn/register/start')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Complete login using a 2FA challenge
   *
   * @param {TwoFactorLoginRequest} request The login request that contains the user credentials used to log them in.
   * @returns {Promise<ClientResponse<LoginResponse>>}
   */
  twoFactorLogin(request: TwoFactorLoginRequest): Promise<ClientResponse<LoginResponse>> {
    return this.startAnonymous<LoginResponse, Errors>()
        .withUri('/api/two-factor/login')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Updates an API key by given id
   *
   * @param {UUID} apiKeyId The Id of the API key to update.
   * @param {APIKeyRequest} request The request object that contains all the information used to create the API Key.
   * @returns {Promise<ClientResponse<APIKeyResponse>>}
   */
  updateAPIKey(apiKeyId: UUID, request: APIKeyRequest): Promise<ClientResponse<APIKeyResponse>> {
    return this.start<APIKeyResponse, Errors>()
        .withUri('/api/api-key')
        .withUriSegment(apiKeyId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the application with the given Id.
   *
   * @param {UUID} applicationId The Id of the application to update.
   * @param {ApplicationRequest} request The request that contains all the new application information.
   * @returns {Promise<ClientResponse<ApplicationResponse>>}
   */
  updateApplication(applicationId: UUID, request: ApplicationRequest): Promise<ClientResponse<ApplicationResponse>> {
    return this.start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the application role with the given Id for the application.
   *
   * @param {UUID} applicationId The Id of the application that the role belongs to.
   * @param {UUID} roleId The Id of the role to update.
   * @param {ApplicationRequest} request The request that contains all the new role information.
   * @returns {Promise<ClientResponse<ApplicationResponse>>}
   */
  updateApplicationRole(applicationId: UUID, roleId: UUID, request: ApplicationRequest): Promise<ClientResponse<ApplicationResponse>> {
    return this.start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("role")
        .withUriSegment(roleId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the connector with the given Id.
   *
   * @param {UUID} connectorId The Id of the connector to update.
   * @param {ConnectorRequest} request The request object that contains all the new connector information.
   * @returns {Promise<ClientResponse<ConnectorResponse>>}
   */
  updateConnector(connectorId: UUID, request: ConnectorRequest): Promise<ClientResponse<ConnectorResponse>> {
    return this.start<ConnectorResponse, Errors>()
        .withUri('/api/connector')
        .withUriSegment(connectorId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the consent with the given Id.
   *
   * @param {UUID} consentId The Id of the consent to update.
   * @param {ConsentRequest} request The request that contains all the new consent information.
   * @returns {Promise<ClientResponse<ConsentResponse>>}
   */
  updateConsent(consentId: UUID, request: ConsentRequest): Promise<ClientResponse<ConsentResponse>> {
    return this.start<ConsentResponse, Errors>()
        .withUri('/api/consent')
        .withUriSegment(consentId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the email template with the given Id.
   *
   * @param {UUID} emailTemplateId The Id of the email template to update.
   * @param {EmailTemplateRequest} request The request that contains all the new email template information.
   * @returns {Promise<ClientResponse<EmailTemplateResponse>>}
   */
  updateEmailTemplate(emailTemplateId: UUID, request: EmailTemplateRequest): Promise<ClientResponse<EmailTemplateResponse>> {
    return this.start<EmailTemplateResponse, Errors>()
        .withUri('/api/email/template')
        .withUriSegment(emailTemplateId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the Entity with the given Id.
   *
   * @param {UUID} entityId The Id of the Entity to update.
   * @param {EntityRequest} request The request that contains all the new Entity information.
   * @returns {Promise<ClientResponse<EntityResponse>>}
   */
  updateEntity(entityId: UUID, request: EntityRequest): Promise<ClientResponse<EntityResponse>> {
    return this.start<EntityResponse, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the Entity Type with the given Id.
   *
   * @param {UUID} entityTypeId The Id of the Entity Type to update.
   * @param {EntityTypeRequest} request The request that contains all the new Entity Type information.
   * @returns {Promise<ClientResponse<EntityTypeResponse>>}
   */
  updateEntityType(entityTypeId: UUID, request: EntityTypeRequest): Promise<ClientResponse<EntityTypeResponse>> {
    return this.start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the permission with the given Id for the entity type.
   *
   * @param {UUID} entityTypeId The Id of the entityType that the permission belongs to.
   * @param {UUID} permissionId The Id of the permission to update.
   * @param {EntityTypeRequest} request The request that contains all the new permission information.
   * @returns {Promise<ClientResponse<EntityTypeResponse>>}
   */
  updateEntityTypePermission(entityTypeId: UUID, permissionId: UUID, request: EntityTypeRequest): Promise<ClientResponse<EntityTypeResponse>> {
    return this.start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withUriSegment("permission")
        .withUriSegment(permissionId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the form with the given Id.
   *
   * @param {UUID} formId The Id of the form to update.
   * @param {FormRequest} request The request object that contains all the new form information.
   * @returns {Promise<ClientResponse<FormResponse>>}
   */
  updateForm(formId: UUID, request: FormRequest): Promise<ClientResponse<FormResponse>> {
    return this.start<FormResponse, Errors>()
        .withUri('/api/form')
        .withUriSegment(formId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the form field with the given Id.
   *
   * @param {UUID} fieldId The Id of the form field to update.
   * @param {FormFieldRequest} request The request object that contains all the new form field information.
   * @returns {Promise<ClientResponse<FormFieldResponse>>}
   */
  updateFormField(fieldId: UUID, request: FormFieldRequest): Promise<ClientResponse<FormFieldResponse>> {
    return this.start<FormFieldResponse, Errors>()
        .withUri('/api/form/field')
        .withUriSegment(fieldId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the group with the given Id.
   *
   * @param {UUID} groupId The Id of the group to update.
   * @param {GroupRequest} request The request that contains all the new group information.
   * @returns {Promise<ClientResponse<GroupResponse>>}
   */
  updateGroup(groupId: UUID, request: GroupRequest): Promise<ClientResponse<GroupResponse>> {
    return this.start<GroupResponse, Errors>()
        .withUri('/api/group')
        .withUriSegment(groupId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Creates a member in a group.
   *
   * @param {MemberRequest} request The request object that contains all the information used to create the group member(s).
   * @returns {Promise<ClientResponse<MemberResponse>>}
   */
  updateGroupMembers(request: MemberRequest): Promise<ClientResponse<MemberResponse>> {
    return this.start<MemberResponse, Errors>()
        .withUri('/api/group/member')
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the IP Access Control List with the given Id.
   *
   * @param {UUID} accessControlListId The Id of the IP Access Control List to update.
   * @param {IPAccessControlListRequest} request The request that contains all the new IP Access Control List information.
   * @returns {Promise<ClientResponse<IPAccessControlListResponse>>}
   */
  updateIPAccessControlList(accessControlListId: UUID, request: IPAccessControlListRequest): Promise<ClientResponse<IPAccessControlListResponse>> {
    return this.start<IPAccessControlListResponse, Errors>()
        .withUri('/api/ip-acl')
        .withUriSegment(accessControlListId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the identity provider with the given Id.
   *
   * @param {UUID} identityProviderId The Id of the identity provider to update.
   * @param {IdentityProviderRequest} request The request object that contains the updated identity provider.
   * @returns {Promise<ClientResponse<IdentityProviderResponse>>}
   */
  updateIdentityProvider(identityProviderId: UUID, request: IdentityProviderRequest): Promise<ClientResponse<IdentityProviderResponse>> {
    return this.start<IdentityProviderResponse, Errors>()
        .withUri('/api/identity-provider')
        .withUriSegment(identityProviderId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the available integrations.
   *
   * @param {IntegrationRequest} request The request that contains all the new integration information.
   * @returns {Promise<ClientResponse<IntegrationResponse>>}
   */
  updateIntegrations(request: IntegrationRequest): Promise<ClientResponse<IntegrationResponse>> {
    return this.start<IntegrationResponse, Errors>()
        .withUri('/api/integration')
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the key with the given Id.
   *
   * @param {UUID} keyId The Id of the key to update.
   * @param {KeyRequest} request The request that contains all the new key information.
   * @returns {Promise<ClientResponse<KeyResponse>>}
   */
  updateKey(keyId: UUID, request: KeyRequest): Promise<ClientResponse<KeyResponse>> {
    return this.start<KeyResponse, Errors>()
        .withUri('/api/key')
        .withUriSegment(keyId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the lambda with the given Id.
   *
   * @param {UUID} lambdaId The Id of the lambda to update.
   * @param {LambdaRequest} request The request that contains all the new lambda information.
   * @returns {Promise<ClientResponse<LambdaResponse>>}
   */
  updateLambda(lambdaId: UUID, request: LambdaRequest): Promise<ClientResponse<LambdaResponse>> {
    return this.start<LambdaResponse, Errors>()
        .withUri('/api/lambda')
        .withUriSegment(lambdaId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the message template with the given Id.
   *
   * @param {UUID} messageTemplateId The Id of the message template to update.
   * @param {MessageTemplateRequest} request The request that contains all the new message template information.
   * @returns {Promise<ClientResponse<MessageTemplateResponse>>}
   */
  updateMessageTemplate(messageTemplateId: UUID, request: MessageTemplateRequest): Promise<ClientResponse<MessageTemplateResponse>> {
    return this.start<MessageTemplateResponse, Errors>()
        .withUri('/api/message/template')
        .withUriSegment(messageTemplateId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the messenger with the given Id.
   *
   * @param {UUID} messengerId The Id of the messenger to update.
   * @param {MessengerRequest} request The request object that contains all the new messenger information.
   * @returns {Promise<ClientResponse<MessengerResponse>>}
   */
  updateMessenger(messengerId: UUID, request: MessengerRequest): Promise<ClientResponse<MessengerResponse>> {
    return this.start<MessengerResponse, Errors>()
        .withUri('/api/messenger')
        .withUriSegment(messengerId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the OAuth scope with the given Id for the application.
   *
   * @param {UUID} applicationId The Id of the application that the OAuth scope belongs to.
   * @param {UUID} scopeId The Id of the OAuth scope to update.
   * @param {ApplicationOAuthScopeRequest} request The request that contains all the new OAuth scope information.
   * @returns {Promise<ClientResponse<ApplicationOAuthScopeResponse>>}
   */
  updateOAuthScope(applicationId: UUID, scopeId: UUID, request: ApplicationOAuthScopeRequest): Promise<ClientResponse<ApplicationOAuthScopeResponse>> {
    return this.start<ApplicationOAuthScopeResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("scope")
        .withUriSegment(scopeId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the registration for the user with the given Id and the application defined in the request.
   *
   * @param {UUID} userId The Id of the user whose registration is going to be updated.
   * @param {RegistrationRequest} request The request that contains all the new registration information.
   * @returns {Promise<ClientResponse<RegistrationResponse>>}
   */
  updateRegistration(userId: UUID, request: RegistrationRequest): Promise<ClientResponse<RegistrationResponse>> {
    return this.start<RegistrationResponse, Errors>()
        .withUri('/api/user/registration')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the system configuration.
   *
   * @param {SystemConfigurationRequest} request The request that contains all the new system configuration information.
   * @returns {Promise<ClientResponse<SystemConfigurationResponse>>}
   */
  updateSystemConfiguration(request: SystemConfigurationRequest): Promise<ClientResponse<SystemConfigurationResponse>> {
    return this.start<SystemConfigurationResponse, Errors>()
        .withUri('/api/system-configuration')
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the tenant with the given Id.
   *
   * @param {UUID} tenantId The Id of the tenant to update.
   * @param {TenantRequest} request The request that contains all the new tenant information.
   * @returns {Promise<ClientResponse<TenantResponse>>}
   */
  updateTenant(tenantId: UUID, request: TenantRequest): Promise<ClientResponse<TenantResponse>> {
    return this.start<TenantResponse, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the theme with the given Id.
   *
   * @param {UUID} themeId The Id of the theme to update.
   * @param {ThemeRequest} request The request that contains all the new theme information.
   * @returns {Promise<ClientResponse<ThemeResponse>>}
   */
  updateTheme(themeId: UUID, request: ThemeRequest): Promise<ClientResponse<ThemeResponse>> {
    return this.start<ThemeResponse, Errors>()
        .withUri('/api/theme')
        .withUriSegment(themeId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the user with the given Id.
   *
   * @param {UUID} userId The Id of the user to update.
   * @param {UserRequest} request The request that contains all the new user information.
   * @returns {Promise<ClientResponse<UserResponse>>}
   */
  updateUser(userId: UUID, request: UserRequest): Promise<ClientResponse<UserResponse>> {
    return this.start<UserResponse, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the user action with the given Id.
   *
   * @param {UUID} userActionId The Id of the user action to update.
   * @param {UserActionRequest} request The request that contains all the new user action information.
   * @returns {Promise<ClientResponse<UserActionResponse>>}
   */
  updateUserAction(userActionId: UUID, request: UserActionRequest): Promise<ClientResponse<UserActionResponse>> {
    return this.start<UserActionResponse, Errors>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the user action reason with the given Id.
   *
   * @param {UUID} userActionReasonId The Id of the user action reason to update.
   * @param {UserActionReasonRequest} request The request that contains all the new user action reason information.
   * @returns {Promise<ClientResponse<UserActionReasonResponse>>}
   */
  updateUserActionReason(userActionReasonId: UUID, request: UserActionReasonRequest): Promise<ClientResponse<UserActionReasonResponse>> {
    return this.start<UserActionReasonResponse, Errors>()
        .withUri('/api/user-action-reason')
        .withUriSegment(userActionReasonId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates a single User consent by Id.
   *
   * @param {UUID} userConsentId The User Consent Id
   * @param {UserConsentRequest} request The request that contains the user consent information.
   * @returns {Promise<ClientResponse<UserConsentResponse>>}
   */
  updateUserConsent(userConsentId: UUID, request: UserConsentRequest): Promise<ClientResponse<UserConsentResponse>> {
    return this.start<UserConsentResponse, Errors>()
        .withUri('/api/user/consent')
        .withUriSegment(userConsentId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Updates the webhook with the given Id.
   *
   * @param {UUID} webhookId The Id of the webhook to update.
   * @param {WebhookRequest} request The request that contains all the new webhook information.
   * @returns {Promise<ClientResponse<WebhookResponse>>}
   */
  updateWebhook(webhookId: UUID, request: WebhookRequest): Promise<ClientResponse<WebhookResponse>> {
    return this.start<WebhookResponse, Errors>()
        .withUri('/api/webhook')
        .withUriSegment(webhookId)
        .withJSONBody(request)
        .withMethod("PUT")
        .go();
  }

  /**
   * Creates or updates an Entity Grant. This is when a User/Entity is granted permissions to an Entity.
   *
   * @param {UUID} entityId The Id of the Entity that the User/Entity is being granted access to.
   * @param {EntityGrantRequest} request The request object that contains all the information used to create the Entity Grant.
   * @returns {Promise<ClientResponse<void>>}
   */
  upsertEntityGrant(entityId: UUID, request: EntityGrantRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withUriSegment("grant")
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Validates the end-user provided user_code from the user-interaction of the Device Authorization Grant.
   * If you build your own activation form you should validate the user provided code prior to beginning the Authorization grant.
   *
   * @param {string} user_code The end-user verification code.
   * @param {string} client_id The client id.
   * @returns {Promise<ClientResponse<void>>}
   */
  validateDevice(user_code: string, client_id: string): Promise<ClientResponse<void>> {
    return this.startAnonymous<void, void>()
        .withUri('/oauth2/device/validate')
        .withParameter('user_code', user_code)
        .withParameter('client_id', client_id)
        .withMethod("GET")
        .go();
  }

  /**
   * Validates the provided JWT (encoded JWT string) to ensure the token is valid. A valid access token is properly
   * signed and not expired.
   * <p>
   * This API may be used to verify the JWT as well as decode the encoded JWT into human readable identity claims.
   *
   * @param {string} encodedJWT The encoded JWT (access token).
   * @returns {Promise<ClientResponse<ValidateResponse>>}
   */
  validateJWT(encodedJWT: string): Promise<ClientResponse<ValidateResponse>> {
    return this.startAnonymous<ValidateResponse, void>()
        .withUri('/api/jwt/validate')
        .withAuthorization('Bearer ' + encodedJWT)
        .withMethod("GET")
        .go();
  }

  /**
   * It's a JWT vending machine!
   * 
   * Issue a new access token (JWT) with the provided claims in the request. This JWT is not scoped to a tenant or user, it is a free form 
   * token that will contain what claims you provide.
   * <p>
   * The iat, exp and jti claims will be added by FusionAuth, all other claims must be provided by the caller.
   * 
   * If a TTL is not provided in the request, the TTL will be retrieved from the default Tenant or the Tenant specified on the request either 
   * by way of the X-FusionAuth-TenantId request header, or a tenant scoped API key.
   *
   * @param {JWTVendRequest} request The request that contains all the claims for this JWT.
   * @returns {Promise<ClientResponse<JWTVendResponse>>}
   */
  vendJWT(request: JWTVendRequest): Promise<ClientResponse<JWTVendResponse>> {
    return this.start<JWTVendResponse, Errors>()
        .withUri('/api/jwt/vend')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Confirms a email verification. The Id given is usually from an email sent to the user.
   *
   * @param {string} verificationId The email verification Id sent to the user.
   * @returns {Promise<ClientResponse<void>>}
   *
   * @deprecated This method has been renamed to verifyEmailAddress and changed to take a JSON request body, use that method instead.
   */
  verifyEmail(verificationId: string): Promise<ClientResponse<void>> {
    return this.startAnonymous<void, Errors>()
        .withHeader('Content-Type', 'text/plain')
        .withUri('/api/user/verify-email')
        .withUriSegment(verificationId)
        .withMethod("POST")
        .go();
  }

  /**
   * Confirms a user's email address. 
   * 
   * The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When 
   * the tenant is configured to gate a user until their email address is verified, this procedures requires two values instead of one. 
   * The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The 
   * two values together are able to confirm a user's email address and mark the user's email address as verified.
   *
   * @param {VerifyEmailRequest} request The request that contains the verificationId and optional one-time use code paired with the verificationId.
   * @returns {Promise<ClientResponse<void>>}
   */
  verifyEmailAddress(request: VerifyEmailRequest): Promise<ClientResponse<void>> {
    return this.startAnonymous<void, Errors>()
        .withUri('/api/user/verify-email')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Administratively verify a user's email address. Use this method to bypass email verification for the user.
   * 
   * The request body will contain the userId to be verified. An API key is required when sending the userId in the request body.
   *
   * @param {VerifyEmailRequest} request The request that contains the userId to verify.
   * @returns {Promise<ClientResponse<void>>}
   */
  verifyEmailAddressByUserId(request: VerifyEmailRequest): Promise<ClientResponse<void>> {
    return this.start<void, Errors>()
        .withUri('/api/user/verify-email')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }

  /**
   * Confirms an application registration. The Id given is usually from an email sent to the user.
   *
   * @param {string} verificationId The registration verification Id sent to the user.
   * @returns {Promise<ClientResponse<void>>}
   *
   * @deprecated This method has been renamed to verifyUserRegistration and changed to take a JSON request body, use that method instead.
   */
  verifyRegistration(verificationId: string): Promise<ClientResponse<void>> {
    return this.startAnonymous<void, Errors>()
        .withHeader('Content-Type', 'text/plain')
        .withUri('/api/user/verify-registration')
        .withUriSegment(verificationId)
        .withMethod("POST")
        .go();
  }

  /**
   * Confirms a user's registration. 
   * 
   * The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When 
   * the application is configured to gate a user until their registration is verified, this procedures requires two values instead of one. 
   * The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The 
   * two values together are able to confirm a user's registration and mark the user's registration as verified.
   *
   * @param {VerifyRegistrationRequest} request The request that contains the verificationId and optional one-time use code paired with the verificationId.
   * @returns {Promise<ClientResponse<void>>}
   */
  verifyUserRegistration(request: VerifyRegistrationRequest): Promise<ClientResponse<void>> {
    return this.startAnonymous<void, Errors>()
        .withUri('/api/user/verify-registration')
        .withJSONBody(request)
        .withMethod("POST")
        .go();
  }


  /* ===================================================================================================================
   * Private methods
   * ===================================================================================================================*/

  /**
   * creates a rest client
   *
   * @returns The RESTClient that will be used to call.
   * @private
   */
  private start<RT, ERT>(): IRESTClient<RT, ERT> {
    return this.startAnonymous<RT, ERT>()
               .withAuthorization(this.apiKey);
  }

  private startAnonymous<RT, ERT>(): IRESTClient<RT, ERT> {
    let client = this.clientBuilder.build<RT, ERT>(this.host);

    if (this.tenantId != null) {
      client.withHeader('X-FusionAuth-TenantId', this.tenantId);
    }

    if (this.credentials != null) {
      client.withCredentials(this.credentials);
    }

    return client;
  }
}

export default FusionAuthClient;

/**
 * A 128 bit UUID in string format "8-4-4-4-12", for example "58D5E212-165B-4CA0-909B-C86B9CEE0111".
 */
export type UUID = string;


/**
 * Webhook attempt log response.
 *
 * @author Spencer Witt
 */
export interface WebhookAttemptLogResponse {
  webhookAttemptLog?: WebhookAttemptLog;
}

/**
 * @author Rob Davis
 */
export interface TenantLambdaConfiguration {
  loginValidationId?: UUID;
  scimEnterpriseUserRequestConverterId?: UUID;
  scimEnterpriseUserResponseConverterId?: UUID;
  scimGroupRequestConverterId?: UUID;
  scimGroupResponseConverterId?: UUID;
  scimUserRequestConverterId?: UUID;
  scimUserResponseConverterId?: UUID;
}

export interface SAMLv2AssertionEncryptionConfiguration extends Enableable {
  digestAlgorithm?: string;
  encryptionAlgorithm?: string;
  keyLocation?: string;
  keyTransportAlgorithm?: string;
  keyTransportEncryptionKeyId?: UUID;
  maskGenerationFunction?: string;
}

/**
 * Models action reasons.
 *
 * @author Brian Pontarelli
 */
export interface UserActionReason {
  code?: string;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  localizedTexts?: LocalizedStrings;
  text?: string;
}

export interface AuthenticationTokenConfiguration extends Enableable {
}

/**
 * Event to indicate an audit log was created.
 *
 * @author Daniel DeGroff
 */
export interface AuditLogCreateEvent extends BaseEvent {
  auditLog?: AuditLog;
}

/**
 * Models the FusionAuth connector.
 *
 * @author Trevor Smith
 */
export interface FusionAuthConnectorConfiguration extends BaseConnectorConfiguration {
}

/**
 * @author Brian Pontarelli
 */
export interface AuditLogRequest extends BaseEventRequest {
  auditLog?: AuditLog;
}

/**
 * @author Brett Guy
 */
export interface IPAccessControlList {
  data?: Record<string, any>;
  entries?: Array<IPAccessControlEntry>;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  name?: string;
}

/**
 * @author Lyle Schemmerling
 */
export interface SAMLv2DestinationAssertionConfiguration {
  alternates?: Array<string>;
  policy?: SAMLv2DestinationAssertionPolicy;
}

/**
 * Form response.
 *
 * @author Daniel DeGroff
 */
export interface FormRequest {
  form?: Form;
}

/**
 * @author Seth Musselman
 */
export interface UserCommentRequest {
  userComment?: UserComment;
}

/**
 * IdP Initiated login configuration
 *
 * @author Daniel DeGroff
 */
export interface SAMLv2IdPInitiatedLoginConfiguration extends Enableable {
  nameIdFormat?: string;
}

export interface DeleteConfiguration extends Enableable {
  numberOfDaysToRetain?: number;
}

/**
 * @author Daniel DeGroff
 */
export enum FormDataType {
  bool = "bool",
  consent = "consent",
  date = "date",
  email = "email",
  number = "number",
  phoneNumber = "phoneNumber",
  string = "string"
}

/**
 * Key search response
 *
 * @author Spencer Witt
 */
export interface KeySearchResponse {
  keys?: Array<Key>;
  total?: number;
}

/**
 * @author Brady Wied
 */
export interface VerifyStartRequest {
  applicationId?: UUID;
  loginId?: string;
  loginIdType?: string;
  verificationStrategy?: string;
}

/**
 * A Application-level policy for deleting Users.
 *
 * @author Trevor Smith
 */
export interface ApplicationRegistrationDeletePolicy {
  unverified?: TimeBasedDeletePolicy;
}

/**
 * Models the User Delete Registration Event.
 *
 * @author Daniel DeGroff
 */
export interface UserRegistrationDeleteEvent extends BaseUserEvent {
  applicationId?: UUID;
  registration?: UserRegistration;
}

/**
 * @author Daniel DeGroff
 */
export interface AccessToken {
  access_token?: string;
  expires_in?: number;
  id_token?: string;
  refresh_token?: string;
  refresh_token_id?: UUID;
  scope?: string;
  token_type?: TokenType;
  userId?: UUID;
}

/**
 * Search request for Group Members.
 *
 * @author Daniel DeGroff
 */
export interface GroupMemberSearchRequest {
  search?: GroupMemberSearchCriteria;
}

export interface MultiFactorSMSTemplate {
  templateId?: UUID;
}

/**
 * A log for an event that happened to a User.
 *
 * @author Brian Pontarelli
 */
export interface UserComment {
  comment?: string;
  commenterId?: UUID;
  id?: UUID;
  insertInstant?: number;
  userId?: UUID;
}

/**
 * Models the Group Create Complete Event.
 *
 * @author Daniel DeGroff
 */
export interface GroupDeleteCompleteEvent extends BaseGroupEvent {
}

/**
 * Email template search response
 *
 * @author Mark Manes
 */
export interface EmailTemplateSearchResponse {
  emailTemplates?: Array<EmailTemplate>;
  total?: number;
}

/**
 * A marker interface indicating this event is not scoped to a tenant and will be sent to all webhooks.
 *
 * @author Daniel DeGroff
 */
export interface InstanceEvent extends NonTransactionalEvent {
}

/**
 * Models the user action Event.
 *
 * @author Brian Pontarelli
 */
export interface UserActionEvent extends BaseEvent {
  action?: string;
  actioneeUserId?: UUID;
  actionerUserId?: UUID;
  actionId?: UUID;
  applicationIds?: Array<UUID>;
  comment?: string;
  email?: Email;
  emailedUser?: boolean;
  expiry?: number;
  localizedAction?: string;
  localizedDuration?: string;
  localizedOption?: string;
  localizedReason?: string;
  notifyUser?: boolean;
  option?: string;
  phase?: UserActionPhase;
  reason?: string;
  reasonCode?: string;
}

/**
 * @author Daniel DeGroff
 */
export enum BreachedPasswordStatus {
  None = "None",
  ExactMatch = "ExactMatch",
  SubAddressMatch = "SubAddressMatch",
  PasswordOnly = "PasswordOnly",
  CommonPassword = "CommonPassword"
}

/**
 * @author Michael Sleevi
 */
export interface SMSMessage {
  phoneNumber?: string;
  textMessage?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface TwitterApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  buttonText?: string;
  consumerKey?: string;
  consumerSecret?: string;
}

/**
 * A User's WebAuthnCredential. Contains all data required to complete WebAuthn authentication ceremonies.
 *
 * @author Spencer Witt
 */
export interface WebAuthnCredential {
  algorithm?: CoseAlgorithmIdentifier;
  attestationType?: AttestationType;
  authenticatorSupportsUserVerification?: boolean;
  credentialId?: string;
  data?: Record<string, any>;
  discoverable?: boolean;
  displayName?: string;
  id?: UUID;
  insertInstant?: number;
  lastUseInstant?: number;
  name?: string;
  publicKey?: string;
  relyingPartyId?: string;
  signCount?: number;
  tenantId?: UUID;
  transports?: Array<string>;
  userAgent?: string;
  userId?: UUID;
}

export interface LambdaConfiguration {
  accessTokenPopulateId?: UUID;
  idTokenPopulateId?: UUID;
  samlv2PopulateId?: UUID;
  selfServiceRegistrationValidationId?: UUID;
  userinfoPopulateId?: UUID;
}

/**
 * @author Daniel DeGroff
 */
export interface RegistrationUnverifiedOptions {
  behavior?: UnverifiedBehavior;
}

/**
 * Models a consent.
 *
 * @author Daniel DeGroff
 */
export enum ConsentStatus {
  Active = "Active",
  Revoked = "Revoked"
}

/**
 * Contains the output for the {@code credProps} extension
 *
 * @author Spencer Witt
 */
export interface CredentialPropertiesOutput {
  rk?: boolean;
}

/**
 * @author Daniel DeGroff
 */
export interface VerifyRegistrationRequest extends BaseEventRequest {
  oneTimeCode?: string;
  verificationId?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface UserinfoResponse extends Record<string, any> {
}

/**
 * Stores an email template used to send emails to users.
 *
 * @author Brian Pontarelli
 */
export interface EmailTemplate {
  defaultFromName?: string;
  defaultHtmlTemplate?: string;
  defaultSubject?: string;
  defaultTextTemplate?: string;
  fromEmail?: string;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  localizedFromNames?: LocalizedStrings;
  localizedHtmlTemplates?: LocalizedStrings;
  localizedSubjects?: LocalizedStrings;
  localizedTextTemplates?: LocalizedStrings;
  name?: string;
}

/**
 * Models the User Email Verify Event.
 *
 * @author Trevor Smith
 */
export interface UserEmailVerifiedEvent extends BaseUserEvent {
}

/**
 * @author Daniel DeGroff
 */
export interface ApplicationAccessControlConfiguration {
  uiIPAccessControlListId?: UUID;
}

/**
 * Form response.
 *
 * @author Daniel DeGroff
 */
export interface FormResponse {
  form?: Form;
  forms?: Array<Form>;
}

/**
 * @author Daniel DeGroff
 */
export enum ApplicationMultiFactorTrustPolicy {
  Any = "Any",
  This = "This",
  None = "None"
}

/**
 * A JSON Web Key as defined by <a href="https://tools.ietf.org/html/rfc7517#section-4">RFC 7517 JSON Web Key (JWK)
 * Section 4</a> and <a href="https://tools.ietf.org/html/rfc7518">RFC 7518 JSON Web Algorithms (JWA)</a>.
 *
 * @author Daniel DeGroff
 */
export interface JSONWebKey {
  alg?: Algorithm;
  crv?: string;
  d?: string;
  dp?: string;
  dq?: string;
  e?: string;
  kid?: string;
  kty?: KeyType;
  n?: string;
  [other: string]: any; // Any other fields
  p?: string;
  q?: string;
  qi?: string;
  use?: string;
  x?: string;
  x5c?: Array<string>;
  x5t?: string;
  x5t_S256?: string;
  y?: string;
}

/**
 * Search request for Consents
 *
 * @author Spencer Witt
 */
export interface ConsentSearchRequest {
  search?: ConsentSearchCriteria;
}

/**
 * Models the User Reactivate Event.
 *
 * @author Brian Pontarelli
 */
export interface UserReactivateEvent extends BaseUserEvent {
}

/**
 * OpenID Connect Configuration as described by the <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID
 * Provider Metadata</a>.
 *
 * @author Daniel DeGroff
 */
export interface OpenIdConfiguration {
  authorization_endpoint?: string;
  backchannel_logout_supported?: boolean;
  claims_supported?: Array<string>;
  device_authorization_endpoint?: string;
  end_session_endpoint?: string;
  frontchannel_logout_supported?: boolean;
  grant_types_supported?: Array<string>;
  id_token_signing_alg_values_supported?: Array<string>;
  issuer?: string;
  jwks_uri?: string;
  response_modes_supported?: Array<string>;
  response_types_supported?: Array<string>;
  scopes_supported?: Array<string>;
  subject_types_supported?: Array<string>;
  token_endpoint?: string;
  token_endpoint_auth_methods_supported?: Array<string>;
  userinfo_endpoint?: string;
  userinfo_signing_alg_values_supported?: Array<string>;
}

/**
 * This class is the user query. It provides a build pattern as well as public fields for use on forms and in actions.
 *
 * @author Brian Pontarelli
 */
export interface UserSearchCriteria extends BaseElasticSearchCriteria {
}

/**
 * @author Daniel DeGroff
 */
export interface UserIdentity {
  displayValue?: string;
  insertInstant?: number;
  lastLoginInstant?: number;
  lastUpdateInstant?: number;
  moderationStatus?: ContentStatus;
  primary?: boolean;
  type?: IdentityType;
  value?: string;
  verified?: boolean;
  verifiedInstant?: number;
  verifiedReason?: IdentityVerifiedReason;
}

/**
 * @author Daniel DeGroff
 */
export enum UserState {
  Authenticated = "Authenticated",
  AuthenticatedNotRegistered = "AuthenticatedNotRegistered",
  AuthenticatedNotVerified = "AuthenticatedNotVerified",
  AuthenticatedRegistrationNotVerified = "AuthenticatedRegistrationNotVerified"
}

/**
 * Models a JWT Refresh Token.
 *
 * @author Daniel DeGroff
 */
export interface RefreshToken {
  applicationId?: UUID;
  data?: Record<string, any>;
  id?: UUID;
  insertInstant?: number;
  metaData?: MetaData;
  startInstant?: number;
  tenantId?: UUID;
  token?: string;
  userId?: UUID;
}

/**
 * Search criteria for entity grants.
 *
 * @author Brian Pontarelli
 */
export interface EntityGrantSearchCriteria extends BaseSearchCriteria {
  entityId?: UUID;
  name?: string;
  userId?: UUID;
}

/**
 * This class is an abstraction of a simple email message.
 *
 * @author Brian Pontarelli
 */
export interface Email {
  attachments?: Array<Attachment>;
  bcc?: Array<EmailAddress>;
  cc?: Array<EmailAddress>;
  from?: EmailAddress;
  html?: string;
  replyTo?: EmailAddress;
  subject?: string;
  text?: string;
  to?: Array<EmailAddress>;
}

/**
 * An audit log.
 *
 * @author Brian Pontarelli
 */
export interface AuditLog {
  data?: Record<string, any>;
  id?: number;
  insertInstant?: number;
  insertUser?: string;
  message?: string;
  newValue?: any;
  oldValue?: any;
  reason?: string;
}

/**
 * Models the User Identity Provider Link Event.
 *
 * @author Rob Davis
 */
export interface UserIdentityProviderLinkEvent extends BaseUserEvent {
  identityProviderLink?: IdentityProviderLink;
}

/**
 * Application search response
 *
 * @author Spencer Witt
 */
export interface ApplicationSearchResponse extends ExpandableResponse {
  applications?: Array<Application>;
  total?: number;
}

/**
 * Configuration for unverified phone number identities.
 *
 * @author Spencer Witt
 */
export interface PhoneUnverifiedOptions {
  behavior?: UnverifiedBehavior;
}

/**
 * @author Daniel DeGroff
 */
export interface OAuthConfigurationResponse {
  httpSessionMaxInactiveInterval?: number;
  logoutURL?: string;
  oauthConfiguration?: OAuth2Configuration;
}

/**
 * Contains attributes for the Relying Party to refer to an existing public key credential as an input parameter.
 *
 * @author Spencer Witt
 */
export interface PublicKeyCredentialDescriptor {
  id?: string;
  transports?: Array<string>;
  type?: PublicKeyCredentialType;
}

/**
 * @author Brian Pontarelli
 */
export interface PendingResponse {
  users?: Array<User>;
}

/**
 * Steam gaming login provider.
 *
 * @author Brett Pontarelli
 */
export interface SteamIdentityProvider extends BaseIdentityProvider<SteamApplicationConfiguration> {
  apiMode?: SteamAPIMode;
  buttonText?: string;
  client_id?: string;
  scope?: string;
  webAPIKey?: string;
}

/**
 * Allows the Relying Party to specify desired attributes of a new credential.
 *
 * @author Spencer Witt
 */
export interface PublicKeyCredentialCreationOptions {
  attestation?: AttestationConveyancePreference;
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  challenge?: string;
  excludeCredentials?: Array<PublicKeyCredentialDescriptor>;
  extensions?: WebAuthnRegistrationExtensionOptions;
  pubKeyCredParams?: Array<PublicKeyCredentialParameters>;
  rp?: PublicKeyCredentialRelyingPartyEntity;
  timeout?: number;
  user?: PublicKeyCredentialUserEntity;
}

/**
 * Authorization Grant types as defined by the <a href="https://tools.ietf.org/html/rfc6749">The OAuth 2.0 Authorization
 * Framework - RFC 6749</a>.
 * <p>
 * Specific names as defined by <a href="https://tools.ietf.org/html/rfc7591#section-4.1">
 * OAuth 2.0 Dynamic Client Registration Protocol - RFC 7591 Section 4.1</a>
 *
 * @author Daniel DeGroff
 */
export enum GrantType {
  authorization_code = "authorization_code",
  implicit = "implicit",
  password = "password",
  client_credentials = "client_credentials",
  refresh_token = "refresh_token",
  unknown = "unknown",
  device_code = "urn:ietf:params:oauth:grant-type:device_code"
}

/**
 * A User's membership into a Group
 *
 * @author Daniel DeGroff
 */
export interface GroupMember {
  data?: Record<string, any>;
  groupId?: UUID;
  id?: UUID;
  insertInstant?: number;
  user?: User;
  userId?: UUID;
}

/**
 * Models the User Update Event.
 *
 * @author Brian Pontarelli
 */
export interface UserUpdateEvent extends BaseUserEvent {
  original?: User;
}

/**
 * The application's relationship to the authorization server. First-party applications will be granted implicit permission for requested scopes.
 * Third-party applications will use the {@link OAuthScopeConsentMode} policy.
 *
 * @author Spencer Witt
 */
export enum OAuthApplicationRelationship {
  FirstParty = "FirstParty",
  ThirdParty = "ThirdParty"
}

/**
 * The summary of the action that is preventing login to be returned on the login response.
 *
 * @author Daniel DeGroff
 */
export interface LoginPreventedResponse {
  actionerUserId?: UUID;
  actionId?: UUID;
  expiry?: number;
  localizedName?: string;
  localizedOption?: string;
  localizedReason?: string;
  name?: string;
  option?: string;
  reason?: string;
  reasonCode?: string;
}

/**
 * This class is the entity query. It provides a build pattern as well as public fields for use on forms and in actions.
 *
 * @author Brian Pontarelli
 */
export interface EntitySearchCriteria extends BaseElasticSearchCriteria {
}

/**
 * Theme API request object.
 *
 * @author Trevor Smith
 */
export interface ThemeRequest {
  sourceThemeId?: UUID;
  theme?: Theme;
}

/**
 * @author Daniel DeGroff
 */
export interface PasswordlessSendRequest {
  applicationId?: UUID;
  code?: string;
  loginId?: string;
  state?: Record<string, any>;
}

/**
 * Models the User Login event for a new device (un-recognized)
 *
 * @author Daniel DeGroff
 */
export interface UserLoginNewDeviceEvent extends UserLoginSuccessEvent {
}

/**
 * Key API response object.
 *
 * @author Daniel DeGroff
 */
export interface KeyResponse {
  key?: Key;
  keys?: Array<Key>;
}

/**
 * @author Brett Guy
 */
export interface TwoFactorStartRequest {
  applicationId?: UUID;
  code?: string;
  loginId?: string;
  state?: Record<string, any>;
  trustChallenge?: string;
  userId?: UUID;
}

/**
 * Models the Group Create Event.
 *
 * @author Daniel DeGroff
 */
export interface GroupCreateEvent extends BaseGroupEvent {
}

/**
 * @author Trevor Smith
 */
export interface ConnectorPolicy {
  connectorId?: UUID;
  data?: Record<string, any>;
  domains?: Array<string>;
  migrate?: boolean;
}

/**
 * @author Daniel DeGroff
 */
export interface FormField {
  confirm?: boolean;
  consentId?: UUID;
  control?: FormControl;
  data?: Record<string, any>;
  description?: string;
  id?: UUID;
  insertInstant?: number;
  key?: string;
  lastUpdateInstant?: number;
  name?: string;
  options?: Array<string>;
  required?: boolean;
  type?: FormDataType;
  validator?: FormFieldValidator;
}

/**
 * @author Brian Pontarelli
 */
export interface FamilyConfiguration extends Enableable {
  allowChildRegistrations?: boolean;
  confirmChildEmailTemplateId?: UUID;
  deleteOrphanedAccounts?: boolean;
  deleteOrphanedAccountsDays?: number;
  familyRequestEmailTemplateId?: UUID;
  maximumChildAge?: number;
  minimumOwnerAge?: number;
  parentEmailRequired?: boolean;
  parentRegistrationEmailTemplateId?: UUID;
}

/**
 * @author Brett Pontarelli
 */
export interface TwitchApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
}

/**
 * A displayable raw login that includes application name and user loginId.
 *
 * @author Brian Pontarelli
 */
export interface DisplayableRawLogin extends RawLogin {
  applicationName?: string;
  location?: Location;
  loginId?: string;
  loginIdType?: IdentityType;
}

export interface SAMLv2SingleLogout extends Enableable {
  keyId?: UUID;
  url?: string;
  xmlSignatureC14nMethod?: CanonicalizationMethod;
}

/**
 * @author Daniel DeGroff
 */
export interface OpenIdConnectApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  buttonImageURL?: string;
  buttonText?: string;
  oauth2?: IdentityProviderOauth2Configuration;
}

/**
 * @author Daniel DeGroff
 */
export interface ApplicationFormConfiguration {
  adminRegistrationFormId?: UUID;
  selfServiceFormConfiguration?: SelfServiceFormConfiguration;
  selfServiceFormId?: UUID;
}

/**
 * A policy for deleting Users based upon some external criteria.
 *
 * @author Trevor Smith
 */
export interface TimeBasedDeletePolicy extends Enableable {
  enabledInstant?: number;
  numberOfDaysToRetain?: number;
}

/**
 * Search criteria for Keys
 *
 * @author Spencer Witt
 */
export interface KeySearchCriteria extends BaseSearchCriteria {
  algorithm?: KeyAlgorithm;
  name?: string;
  type?: KeyType;
}

/**
 * @author Brian Pontarelli
 */
export enum ReactorFeatureStatus {
  ACTIVE = "ACTIVE",
  DISCONNECTED = "DISCONNECTED",
  PENDING = "PENDING",
  DISABLED = "DISABLED",
  UNKNOWN = "UNKNOWN"
}

/**
 * @author Daniel DeGroff
 */
export interface RefreshRequest extends BaseEventRequest {
  refreshToken?: string;
  timeToLiveInSeconds?: number;
  token?: string;
}

/**
 * Models an event where a user is being created with an "in-use" login Id (email, username, or other identities).
 *
 * @author Daniel DeGroff
 */
export interface UserLoginIdDuplicateOnCreateEvent extends BaseUserEvent {
  duplicateEmail?: string;
  duplicateIdentities?: Array<IdentityInfo>;
  duplicatePhoneNumber?: string;
  duplicateUsername?: string;
  existing?: User;
}

export enum ThemeType {
  advanced = "advanced",
  simple = "simple"
}

/**
 * Login API request object.
 *
 * @author Seth Musselman
 */
export interface LoginRequest extends BaseLoginRequest {
  loginId?: string;
  loginIdTypes?: Array<string>;
  oneTimePassword?: string;
  password?: string;
  twoFactorTrustId?: string;
}

/**
 * The reason for the login failure.
 *
 * @author Daniel DeGroff
 */
export interface UserLoginFailedReason {
  code?: string;
  lambdaId?: UUID;
  lambdaResult?: Errors;
}

/**
 * Response for the user login report.
 *
 * @author Seth Musselman
 */
export interface RecentLoginResponse {
  logins?: Array<DisplayableRawLogin>;
}

/**
 * Theme object for values used in the css variables for simple themes.
 *
 * @author Lyle Schemmerling
 */
export interface SimpleThemeVariables {
  alertBackgroundColor?: string;
  alertFontColor?: string;
  backgroundImageURL?: string;
  backgroundSize?: string;
  borderRadius?: string;
  deleteButtonColor?: string;
  deleteButtonFocusColor?: string;
  deleteButtonTextColor?: string;
  deleteButtonTextFocusColor?: string;
  errorFontColor?: string;
  errorIconColor?: string;
  fontColor?: string;
  fontFamily?: string;
  footerDisplay?: boolean;
  iconBackgroundColor?: string;
  iconColor?: string;
  infoIconColor?: string;
  inputBackgroundColor?: string;
  inputIconColor?: string;
  inputTextColor?: string;
  linkTextColor?: string;
  linkTextFocusColor?: string;
  logoImageSize?: string;
  logoImageURL?: string;
  monoFontColor?: string;
  monoFontFamily?: string;
  pageBackgroundColor?: string;
  panelBackgroundColor?: string;
  primaryButtonColor?: string;
  primaryButtonFocusColor?: string;
  primaryButtonTextColor?: string;
  primaryButtonTextFocusColor?: string;
}

/**
 * API response for User consent.
 *
 * @author Daniel DeGroff
 */
export interface UserConsentRequest {
  userConsent?: UserConsent;
}

/**
 * API request for sending out family requests to parent's.
 *
 * @author Brian Pontarelli
 */
export interface FamilyEmailRequest {
  parentEmail?: string;
}

/**
 * Search request for entities
 *
 * @author Brett Guy
 */
export interface EntitySearchRequest {
  search?: EntitySearchCriteria;
}

/**
 * Interface describing the need for CORS configuration.
 *
 * @author Daniel DeGroff
 */
export interface RequiresCORSConfiguration {
}

/**
 * Audit log response.
 *
 * @author Brian Pontarelli
 */
export interface AuditLogResponse {
  auditLog?: AuditLog;
}

/**
 * @author Brett Pontarelli
 */
export interface SteamApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  apiMode?: SteamAPIMode;
  buttonText?: string;
  client_id?: string;
  scope?: string;
  webAPIKey?: string;
}

/**
 * @author Mikey Sleevi
 */
export interface TenantMultiFactorConfiguration {
  authenticator?: MultiFactorAuthenticatorMethod;
  email?: MultiFactorEmailMethod;
  loginPolicy?: MultiFactorLoginPolicy;
  sms?: MultiFactorSMSMethod;
}

/**
 * Xbox gaming login provider.
 *
 * @author Brett Pontarelli
 */
export interface XboxIdentityProvider extends BaseIdentityProvider<XboxApplicationConfiguration> {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
}

/**
 * @author Brett Guy
 */
export enum ProofKeyForCodeExchangePolicy {
  Required = "Required",
  NotRequired = "NotRequired",
  NotRequiredWhenUsingClientAuthentication = "NotRequiredWhenUsingClientAuthentication"
}

/**
 * Audit log response.
 *
 * @author Brian Pontarelli
 */
export interface AuditLogSearchResponse {
  auditLogs?: Array<AuditLog>;
  total?: number;
}

/**
 * <ul>
 * <li>Bearer Token type as defined by <a href="https://tools.ietf.org/html/rfc6750">RFC 6750</a>.</li>
 * <li>MAC Token type as referenced by <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a> and
 * <a href="https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-05">
 * Draft RFC on OAuth 2.0 Message Authentication Code (MAC) Tokens</a>
 * </li>
 * </ul>
 *
 * @author Daniel DeGroff
 */
export enum TokenType {
  Bearer = "Bearer",
  MAC = "MAC"
}

/**
 * Search response for Groups
 *
 * @author Daniel DeGroff
 */
export interface GroupSearchResponse {
  groups?: Array<Group>;
  total?: number;
}

/**
 * Configuration for signing webhooks.
 *
 * @author Brent Halsey
 */
export interface WebhookSignatureConfiguration extends Enableable {
  signingKeyId?: UUID;
}

export enum XMLSignatureLocation {
  Assertion = "Assertion",
  Response = "Response"
}

/**
 * Search criteria for user comments.
 *
 * @author Spencer Witt
 */
export interface UserCommentSearchCriteria extends BaseSearchCriteria {
  comment?: string;
  commenterId?: UUID;
  tenantId?: UUID;
  userId?: UUID;
}

/**
 * @author Daniel DeGroff
 */
export interface LinkedInIdentityProvider extends BaseIdentityProvider<LinkedInApplicationConfiguration> {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
}

/**
 * A server where events are sent. This includes user action events and any other events sent by FusionAuth.
 *
 * @author Brian Pontarelli
 */
export interface Webhook {
  connectTimeout?: number;
  data?: Record<string, any>;
  description?: string;
  eventsEnabled?: Record<EventType, boolean>;
  global?: boolean;
  headers?: HTTPHeaders;
  httpAuthenticationPassword?: string;
  httpAuthenticationUsername?: string;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  readTimeout?: number;
  signatureConfiguration?: WebhookSignatureConfiguration;
  sslCertificate?: string;
  sslCertificateKeyId?: UUID;
  tenantIds?: Array<UUID>;
  url?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface TwoFactorLoginRequest extends BaseLoginRequest {
  code?: string;
  trustComputer?: boolean;
  twoFactorId?: string;
  userId?: UUID;
}

/**
 * Entity grant API request object.
 *
 * @author Brian Pontarelli
 */
export interface EntityGrantRequest {
  grant?: EntityGrant;
}

/**
 * @author Daniel DeGroff
 */
export interface IdentityProviderLinkResponse {
  identityProviderLink?: IdentityProviderLink;
  identityProviderLinks?: Array<IdentityProviderLink>;
}

/**
 * The handling policy for scopes provided by FusionAuth
 *
 * @author Spencer Witt
 */
export interface ProvidedScopePolicy {
  address?: Requirable;
  email?: Requirable;
  phone?: Requirable;
  profile?: Requirable;
}

export interface HistoryItem {
  actionerUserId?: UUID;
  comment?: string;
  createInstant?: number;
  expiry?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface BaseExportRequest {
  dateTimeSecondsFormat?: string;
  zoneId?: string;
}

/**
 * Google social login provider parameters.
 *
 * @author Daniel DeGroff
 */
export interface GoogleIdentityProviderProperties {
  api?: string;
  button?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface OAuthError {
  change_password_id?: string;
  error?: OAuthErrorType;
  error_description?: string;
  error_reason?: OAuthErrorReason;
  error_uri?: string;
  two_factor_id?: string;
  two_factor_methods?: Array<TwoFactorMethod>;
}

/**
 * @author Daniel DeGroff
 */
export interface TwoFactorRecoveryCodeResponse {
  recoveryCodes?: Array<string>;
}

/**
 * Describes the authenticator attachment modality preference for a WebAuthn workflow. See {@link AuthenticatorAttachment}
 *
 * @author Spencer Witt
 */
export enum AuthenticatorAttachmentPreference {
  any = "any",
  platform = "platform",
  crossPlatform = "crossPlatform"
}

/**
 * Models the Group Update Complete Event.
 *
 * @author Daniel DeGroff
 */
export interface GroupUpdateCompleteEvent extends BaseGroupEvent {
  original?: Group;
}

export interface LambdaConfiguration {
  reconcileId?: UUID;
}

/**
 * Search criteria for Lambdas
 *
 * @author Mark Manes
 */
export interface LambdaSearchCriteria extends BaseSearchCriteria {
  body?: string;
  name?: string;
  type?: LambdaType;
}

/**
 * @author Brian Pontarelli
 */
export interface SystemConfiguration {
  auditLogConfiguration?: AuditLogConfiguration;
  corsConfiguration?: CORSConfiguration;
  data?: Record<string, any>;
  eventLogConfiguration?: EventLogConfiguration;
  insertInstant?: number;
  lastUpdateInstant?: number;
  loginRecordConfiguration?: LoginRecordConfiguration;
  reportTimezone?: string;
  trustedProxyConfiguration?: SystemTrustedProxyConfiguration;
  uiConfiguration?: UIConfiguration;
  usageDataConfiguration?: UsageDataConfiguration;
  webhookEventLogConfiguration?: WebhookEventLogConfiguration;
}

/**
 * @author Brett Guy
 */
export enum IPAccessControlEntryAction {
  Allow = "Allow",
  Block = "Block"
}

/**
 * Webhook API request object.
 *
 * @author Brian Pontarelli
 */
export interface WebhookRequest {
  webhook?: Webhook;
}

/**
 * Form field response.
 *
 * @author Brett Guy
 */
export interface FormFieldResponse {
  field?: FormField;
  fields?: Array<FormField>;
}

/**
 * @author Mikey Sleevi
 */
export enum MessageType {
  SMS = "SMS"
}

// Do not require a setter for 'type', it is defined by the concrete class and is not mutable
export interface BaseConnectorConfiguration {
  data?: Record<string, any>;
  debug?: boolean;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  name?: string;
  type?: ConnectorType;
}

/**
 * Configuration for the behavior of failed login attempts. This helps us protect against brute force password attacks.
 *
 * @author Daniel DeGroff
 */
export interface FailedAuthenticationConfiguration {
  actionCancelPolicy?: FailedAuthenticationActionCancelPolicy;
  actionDuration?: number;
  actionDurationUnit?: ExpiryUnit;
  emailUser?: boolean;
  resetCountInSeconds?: number;
  tooManyAttempts?: number;
  userActionId?: UUID;
}

/**
 * Search criteria for Tenants
 *
 * @author Mark Manes
 */
export interface TenantSearchCriteria extends BaseSearchCriteria {
  name?: string;
}

/**
 * @author Rob Davis
 */
export interface TenantSCIMServerConfiguration extends Enableable {
  clientEntityTypeId?: UUID;
  schemas?: Record<string, any>;
  serverEntityTypeId?: UUID;
}

/**
 * An email address.
 *
 * @author Brian Pontarelli
 */
export interface EmailAddress {
  address?: string;
  display?: string;
}

/**
 * Status for content like usernames, profile attributes, etc.
 *
 * @author Brian Pontarelli
 */
export enum ContentStatus {
  ACTIVE = "ACTIVE",
  PENDING = "PENDING",
  REJECTED = "REJECTED"
}

/**
 * @author Brett Guy
 */
export interface GenericMessengerConfiguration extends BaseMessengerConfiguration {
  connectTimeout?: number;
  headers?: HTTPHeaders;
  httpAuthenticationPassword?: string;
  httpAuthenticationUsername?: string;
  readTimeout?: number;
  sslCertificate?: string;
  url?: string;
}

/**
 * @author Daniel DeGroff
 */
export enum FormControl {
  checkbox = "checkbox",
  number = "number",
  password = "password",
  radio = "radio",
  select = "select",
  textarea = "textarea",
  text = "text"
}

export enum BreachMatchMode {
  Low = "Low",
  Medium = "Medium",
  High = "High"
}

/**
 * Search criteria for Group Members
 *
 * @author Daniel DeGroff
 */
export interface GroupMemberSearchCriteria extends BaseSearchCriteria {
  groupId?: UUID;
  tenantId?: UUID;
  userId?: UUID;
}

/**
 * COSE key type
 *
 * @author Spencer Witt
 */
export enum CoseKeyType {
  Reserved = "0",
  OKP = "1",
  EC2 = "2",
  RSA = "3",
  Symmetric = "4"
}

/**
 * User API request object.
 *
 * @author Brian Pontarelli
 */
export interface UserRequest extends BaseEventRequest {
  applicationId?: UUID;
  currentPassword?: string;
  disableDomainBlock?: boolean;
  sendSetPasswordEmail?: boolean;
  skipVerification?: boolean;
  user?: User;
  verificationIds?: Array<string>;
}

/**
 * User API bulk response object.
 *
 * @author Trevor Smith
 */
export interface UserDeleteResponse {
  dryRun?: boolean;
  hardDelete?: boolean;
  total?: number;
  userIds?: Array<UUID>;
}

/**
 * Change password request object.
 *
 * @author Brian Pontarelli
 */
export interface ChangePasswordRequest extends BaseEventRequest {
  applicationId?: UUID;
  changePasswordId?: string;
  currentPassword?: string;
  loginId?: string;
  password?: string;
  refreshToken?: string;
  trustChallenge?: string;
  trustToken?: string;
}

export interface SAMLv2Configuration extends Enableable {
  assertionEncryptionConfiguration?: SAMLv2AssertionEncryptionConfiguration;
  audience?: string;
  authorizedRedirectURLs?: Array<string>;
  callbackURL?: string;
  debug?: boolean;
  defaultVerificationKeyId?: UUID;
  initiatedLogin?: SAMLv2IdPInitiatedLoginConfiguration;
  issuer?: string;
  keyId?: UUID;
  loginHintConfiguration?: LoginHintConfiguration;
  logout?: SAMLv2Logout;
  logoutURL?: string;
  requireSignedRequests?: boolean;
  xmlSignatureC14nMethod?: CanonicalizationMethod;
  xmlSignatureLocation?: XMLSignatureLocation;
}

/**
 * CleanSpeak configuration at the system and application level.
 *
 * @author Brian Pontarelli
 */
export interface CleanSpeakConfiguration extends Enableable {
  apiKey?: string;
  applicationIds?: Array<UUID>;
  url?: string;
  usernameModeration?: UsernameModeration;
}

/**
 * User Action API response object.
 *
 * @author Brian Pontarelli
 */
export interface UserActionResponse {
  userAction?: UserAction;
  userActions?: Array<UserAction>;
}

/**
 * @author Lyle Schemmerling
 */
export enum SAMLv2DestinationAssertionPolicy {
  Enabled = "Enabled",
  Disabled = "Disabled",
  AllowAlternates = "AllowAlternates"
}

/**
 * API response for starting a WebAuthn authentication ceremony
 *
 * @author Spencer Witt
 */
export interface WebAuthnStartResponse {
  options?: PublicKeyCredentialRequestOptions;
}

/**
 * Theme API response object.
 *
 * @author Trevor Smith
 */
export interface ThemeResponse {
  theme?: Theme;
  themes?: Array<Theme>;
}

/**
 * Defines valid credential types. This is an extension point in the WebAuthn spec. The only defined value at this time is "public-key"
 *
 * @author Spencer Witt
 */
export enum PublicKeyCredentialType {
  publicKey = "public-key"
}

/**
 * @author Daniel DeGroff
 */
export interface OAuthResponse {
}

/**
 * @author Daniel DeGroff
 */
export enum FormFieldAdminPolicy {
  Edit = "Edit",
  View = "View"
}

export interface EmailPlus extends Enableable {
  emailTemplateId?: UUID;
  maximumTimeToSendEmailInHours?: number;
  minimumTimeToSendEmailInHours?: number;
}

/**
 * API response for managing families and members.
 *
 * @author Brian Pontarelli
 */
export interface FamilyResponse {
  families?: Array<Family>;
  family?: Family;
}

/**
 * Models a specific entity type permission. This permission can be granted to users or other entities.
 *
 * @author Brian Pontarelli
 */
export interface EntityTypePermission {
  data?: Record<string, any>;
  description?: string;
  id?: UUID;
  insertInstant?: number;
  isDefault?: boolean;
  lastUpdateInstant?: number;
  name?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface RateLimitedRequestConfiguration extends Enableable {
  limit?: number;
  timePeriodInSeconds?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface ReactorStatus {
  advancedIdentityProviders?: ReactorFeatureStatus;
  advancedLambdas?: ReactorFeatureStatus;
  advancedMultiFactorAuthentication?: ReactorFeatureStatus;
  advancedOAuthScopes?: ReactorFeatureStatus;
  advancedOAuthScopesCustomScopes?: ReactorFeatureStatus;
  advancedOAuthScopesThirdPartyApplications?: ReactorFeatureStatus;
  advancedRegistration?: ReactorFeatureStatus;
  applicationMultiFactorAuthentication?: ReactorFeatureStatus;
  applicationThemes?: ReactorFeatureStatus;
  breachedPasswordDetection?: ReactorFeatureStatus;
  connectors?: ReactorFeatureStatus;
  entityManagement?: ReactorFeatureStatus;
  expiration?: string;
  licenseAttributes?: Record<string, string>;
  licensed?: boolean;
  scimServer?: ReactorFeatureStatus;
  threatDetection?: ReactorFeatureStatus;
  webAuthn?: ReactorFeatureStatus;
  webAuthnPlatformAuthenticators?: ReactorFeatureStatus;
  webAuthnRoamingAuthenticators?: ReactorFeatureStatus;
}

/**
 * Models a single family member.
 *
 * @author Brian Pontarelli
 */
export interface FamilyMember {
  data?: Record<string, any>;
  insertInstant?: number;
  lastUpdateInstant?: number;
  owner?: boolean;
  role?: FamilyRole;
  userId?: UUID;
}

export interface CertificateInformation {
  issuer?: string;
  md5Fingerprint?: string;
  serialNumber?: string;
  sha1Fingerprint?: string;
  sha1Thumbprint?: string;
  sha256Fingerprint?: string;
  sha256Thumbprint?: string;
  subject?: string;
  validFrom?: number;
  validTo?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface PasswordlessStartResponse {
  code?: string;
  oneTimeCode?: string;
}

/**
 * Response for the daily active user report.
 *
 * @author Brian Pontarelli
 */
export interface DailyActiveUserReportResponse {
  dailyActiveUsers?: Array<Count>;
  total?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface VersionResponse {
  version?: string;
}

/**
 * @author Michael Sleevi
 */
export interface PreviewMessageTemplateRequest {
  locale?: string;
  messageTemplate?: MessageTemplate;
}

/**
 * @author Daniel DeGroff
 */
export interface IssueResponse {
  refreshToken?: string;
  token?: string;
}

/**
 * Response for the login report.
 *
 * @author Brian Pontarelli
 */
export interface LoginReportResponse {
  hourlyCounts?: Array<Count>;
  total?: number;
}

/**
 * @author Daniel DeGroff
 */
export enum HTTPMethod {
  GET = "GET",
  POST = "POST",
  PUT = "PUT",
  DELETE = "DELETE",
  HEAD = "HEAD",
  OPTIONS = "OPTIONS",
  PATCH = "PATCH"
}

/**
 * @author Mikey Sleevi
 */
export interface Message {
}

// Do not require a setter for 'type', it is defined by the concrete class and is not mutable
export interface BaseIdentityProvider<D extends BaseIdentityProviderApplicationConfiguration> extends Enableable {
  applicationConfiguration?: Record<UUID, D>;
  data?: Record<string, any>;
  debug?: boolean;
  id?: UUID;
  insertInstant?: number;
  lambdaConfiguration?: LambdaConfiguration;
  lastUpdateInstant?: number;
  linkingStrategy?: IdentityProviderLinkingStrategy;
  name?: string;
  tenantConfiguration?: Record<UUID, IdentityProviderTenantConfiguration>;
  type?: IdentityProviderType;
}

export interface MultiFactorEmailMethod extends Enableable {
  templateId?: UUID;
}

/**
 * @author Trevor Smith
 */
export interface ConnectorRequest {
  connector?: BaseConnectorConfiguration;
}

/**
 * Models the User Created Event.
 * <p>
 * This is different than the user.create event in that it will be sent after the user has been created. This event cannot be made transactional.
 *
 * @author Daniel DeGroff
 */
export interface UserCreateCompleteEvent extends BaseUserEvent {
}

/**
 * A number identifying a cryptographic algorithm. Values should be registered with the <a
 * href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms registry</a>
 *
 * @author Spencer Witt
 */
export enum CoseAlgorithmIdentifier {
  ES256 = "SHA256withECDSA",
  ES384 = "SHA384withECDSA",
  ES512 = "SHA512withECDSA",
  RS256 = "SHA256withRSA",
  RS384 = "SHA384withRSA",
  RS512 = "SHA512withRSA",
  PS256 = "SHA-256",
  PS384 = "SHA-384",
  PS512 = "SHA-512"
}

/**
 * @author andrewpai
 */
export interface SelfServiceFormConfiguration {
  requireCurrentPasswordOnPasswordChange?: boolean;
}

/**
 * @author Daniel DeGroff
 */
export interface RememberPreviousPasswords extends Enableable {
  count?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface HYPRApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  relyingPartyApplicationId?: string;
  relyingPartyURL?: string;
}

/**
 * @author Brett Guy
 */
export interface KafkaMessengerConfiguration extends BaseMessengerConfiguration {
  defaultTopic?: string;
  producer?: Record<string, string>;
}

/**
 * Models the User Created Registration Event.
 * <p>
 * This is different than the user.registration.create event in that it will be sent after the user has been created. This event cannot be made
 * transactional.
 *
 * @author Daniel DeGroff
 */
export interface UserRegistrationCreateCompleteEvent extends BaseUserEvent {
  applicationId?: UUID;
  registration?: UserRegistration;
}

/**
 * @author Daniel DeGroff
 */
export interface LoginRecordSearchRequest {
  retrieveTotal?: boolean;
  search?: LoginRecordSearchCriteria;
}

/**
 * @author Daniel DeGroff
 */
export interface KafkaConfiguration extends Enableable {
  defaultTopic?: string;
  producer?: Record<string, string>;
}

/**
 * This class contains the managed fields that are also put into the database during FusionAuth setup.
 * <p>
 * Internal Note: These fields are also declared in SQL in order to bootstrap the system. These need to stay in sync.
 * Any changes to these fields needs to also be reflected in mysql.sql and postgresql.sql
 *
 * @author Brian Pontarelli
 */
export interface ManagedFields {
}

/**
 * Response for the daily active user report.
 *
 * @author Brian Pontarelli
 */
export interface MonthlyActiveUserReportResponse {
  monthlyActiveUsers?: Array<Count>;
  total?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface IdentityProviderLinkRequest extends BaseEventRequest {
  identityProviderLink?: IdentityProviderLink;
  pendingIdPLinkId?: string;
}

/**
 * The types of lambdas that indicate how they are invoked by FusionAuth.
 *
 * @author Brian Pontarelli
 */
export enum LambdaType {
  JWTPopulate = "JWTPopulate",
  OpenIDReconcile = "OpenIDReconcile",
  SAMLv2Reconcile = "SAMLv2Reconcile",
  SAMLv2Populate = "SAMLv2Populate",
  AppleReconcile = "AppleReconcile",
  ExternalJWTReconcile = "ExternalJWTReconcile",
  FacebookReconcile = "FacebookReconcile",
  GoogleReconcile = "GoogleReconcile",
  HYPRReconcile = "HYPRReconcile",
  TwitterReconcile = "TwitterReconcile",
  LDAPConnectorReconcile = "LDAPConnectorReconcile",
  LinkedInReconcile = "LinkedInReconcile",
  EpicGamesReconcile = "EpicGamesReconcile",
  NintendoReconcile = "NintendoReconcile",
  SonyPSNReconcile = "SonyPSNReconcile",
  SteamReconcile = "SteamReconcile",
  TwitchReconcile = "TwitchReconcile",
  XboxReconcile = "XboxReconcile",
  ClientCredentialsJWTPopulate = "ClientCredentialsJWTPopulate",
  SCIMServerGroupRequestConverter = "SCIMServerGroupRequestConverter",
  SCIMServerGroupResponseConverter = "SCIMServerGroupResponseConverter",
  SCIMServerUserRequestConverter = "SCIMServerUserRequestConverter",
  SCIMServerUserResponseConverter = "SCIMServerUserResponseConverter",
  SelfServiceRegistrationValidation = "SelfServiceRegistrationValidation",
  UserInfoPopulate = "UserInfoPopulate",
  LoginValidation = "LoginValidation"
}

/**
 * @author Daniel DeGroff
 */
export interface SecureGeneratorConfiguration {
  length?: number;
  type?: SecureGeneratorType;
}

/**
 * Models an LDAP connector.
 *
 * @author Trevor Smith
 */
export interface LDAPConnectorConfiguration extends BaseConnectorConfiguration {
  authenticationURL?: string;
  baseStructure?: string;
  connectTimeout?: number;
  identifyingAttribute?: string;
  lambdaConfiguration?: LambdaConfiguration;
  loginIdAttribute?: string;
  readTimeout?: number;
  requestedAttributes?: Array<string>;
  securityMethod?: LDAPSecurityMethod;
  systemAccountDN?: string;
  systemAccountPassword?: string;
}

/**
 * External JWT-only identity provider.
 *
 * @author Daniel DeGroff and Brian Pontarelli
 */
export interface ExternalJWTIdentityProvider extends BaseIdentityProvider<ExternalJWTApplicationConfiguration> {
  claimMap?: Record<string, string>;
  defaultKeyId?: UUID;
  domains?: Array<string>;
  headerKeyParameter?: string;
  oauth2?: IdentityProviderOauth2Configuration;
  uniqueIdentityClaim?: string;
}

/**
 * Lambda API request object.
 *
 * @author Brian Pontarelli
 */
export interface LambdaRequest {
  lambda?: Lambda;
}

/**
 * Models an event where a user's email is updated outside of a forgot / change password workflow.
 *
 * @author Daniel DeGroff
 */
export interface UserEmailUpdateEvent extends BaseUserEvent {
  previousEmail?: string;
}

/**
 * Raw login information for each time a user logs into an application.
 *
 * @author Brian Pontarelli
 */
export interface RawLogin {
  applicationId?: UUID;
  instant?: number;
  ipAddress?: string;
  userId?: UUID;
}

/**
 * Search response for Group Members
 *
 * @author Daniel DeGroff
 */
export interface GroupMemberSearchResponse {
  members?: Array<GroupMember>;
  total?: number;
}

/**
 * API response for retrieving Refresh Tokens
 *
 * @author Daniel DeGroff
 */
export interface RefreshTokenResponse {
  refreshToken?: RefreshToken;
  refreshTokens?: Array<RefreshToken>;
}

/**
 * @author Daniel DeGroff
 */
export interface DeviceApprovalResponse {
  deviceGrantStatus?: string;
  deviceInfo?: DeviceInfo;
  identityProviderLink?: IdentityProviderLink;
  tenantId?: UUID;
  userId?: UUID;
}

/**
 * JSON Web Token (JWT) as defined by RFC 7519.
 * <pre>
 * From RFC 7519 Section 1. Introduction:
 *    The suggested pronunciation of JWT is the same as the English word "jot".
 * </pre>
 * The JWT is not Thread-Safe and should not be re-used.
 *
 * @author Daniel DeGroff
 */
export interface JWT {
  aud?: any;
  exp?: number;
  iat?: number;
  iss?: string;
  jti?: string;
  nbf?: number;
  [otherClaims: string]: any; // Any other fields
  sub?: string;
}

/**
 * @author Brian Pontarelli
 */
export interface Tenantable {
}

/**
 * Used by the Relying Party to specify their requirements for authenticator attributes. Fields use the deprecated "resident key" terminology to refer
 * to client-side discoverable credentials to maintain backwards compatibility with WebAuthn Level 1.
 *
 * @author Spencer Witt
 */
export interface AuthenticatorSelectionCriteria {
  authenticatorAttachment?: AuthenticatorAttachment;
  requireResidentKey?: boolean;
  residentKey?: ResidentKeyRequirement;
  userVerification?: UserVerificationRequirement;
}

/**
 * @author Daniel DeGroff
 */
export interface ApplicationWebAuthnWorkflowConfiguration extends Enableable {
}

/**
 * Used to communicate whether and how authenticator attestation should be delivered to the Relying Party
 *
 * @author Spencer Witt
 */
export enum AttestationConveyancePreference {
  none = "none",
  indirect = "indirect",
  direct = "direct",
  enterprise = "enterprise"
}

/**
 * SAML v2 identity provider configuration.
 *
 * @author Brian Pontarelli
 */
export interface SAMLv2IdentityProvider extends BaseSAMLv2IdentityProvider<SAMLv2ApplicationConfiguration> {
  assertionConfiguration?: SAMLv2AssertionConfiguration;
  buttonImageURL?: string;
  buttonText?: string;
  domains?: Array<string>;
  idpEndpoint?: string;
  idpInitiatedConfiguration?: SAMLv2IdpInitiatedConfiguration;
  issuer?: string;
  loginHintConfiguration?: LoginHintConfiguration;
  nameIdFormat?: string;
  postRequest?: boolean;
  requestSigningKeyId?: UUID;
  signRequest?: boolean;
  xmlSignatureC14nMethod?: CanonicalizationMethod;
}

/**
 * Facebook social login provider.
 *
 * @author Brian Pontarelli
 */
export interface FacebookIdentityProvider extends BaseIdentityProvider<FacebookApplicationConfiguration> {
  appId?: string;
  buttonText?: string;
  client_secret?: string;
  fields?: string;
  loginMethod?: IdentityProviderLoginMethod;
  permissions?: string;
}

/**
 * An expandable API request.
 *
 * @author Daniel DeGroff
 */
export interface ExpandableRequest {
  expand?: Array<string>;
}

/**
 * Models a set of localized Integers that can be stored as JSON.
 *
 * @author Daniel DeGroff
 */
export interface LocalizedIntegers extends Record<string, number> {
}

/**
 * Interface for all identity providers that can be domain based.
 */
export interface DomainBasedIdentityProvider {
}

/**
 * @author Daniel DeGroff
 */
export enum ObjectState {
  Active = "Active",
  Inactive = "Inactive",
  PendingDelete = "PendingDelete"
}

/**
 * Email template request.
 *
 * @author Brian Pontarelli
 */
export interface EmailTemplateRequest {
  emailTemplate?: EmailTemplate;
}

/**
 * API response for completing WebAuthn credential registration or assertion
 *
 * @author Spencer Witt
 */
export interface WebAuthnRegisterCompleteResponse {
  credential?: WebAuthnCredential;
}

export interface IdentityProviderDetails {
  applicationIds?: Array<UUID>;
  id?: UUID;
  idpEndpoint?: string;
  name?: string;
  oauth2?: IdentityProviderOauth2Configuration;
  type?: IdentityProviderType;
}

/**
 * Events that are bound to applications.
 *
 * @author Brian Pontarelli
 */
export interface ApplicationEvent {
}

/**
 * @author Brett Pontarelli
 */
export enum AuthenticationThreats {
  ImpossibleTravel = "ImpossibleTravel"
}

/**
 * @author Daniel DeGroff
 */
export interface TenantRequest extends BaseEventRequest {
  sourceTenantId?: UUID;
  tenant?: Tenant;
  webhookIds?: Array<UUID>;
}

/**
 * @author Brett Guy
 */
export interface IPAccessControlListSearchCriteria extends BaseSearchCriteria {
  name?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface AppleApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  bundleId?: string;
  buttonText?: string;
  keyId?: UUID;
  scope?: string;
  servicesId?: string;
  teamId?: string;
}

/**
 * @author Spencer Witt
 */
export interface TenantWebAuthnWorkflowConfiguration extends Enableable {
  authenticatorAttachmentPreference?: AuthenticatorAttachmentPreference;
  userVerificationRequirement?: UserVerificationRequirement;
}

/**
 * Model a user event when a two-factor method has been added.
 *
 * @author Daniel DeGroff
 */
export interface UserTwoFactorMethodRemoveEvent extends BaseUserEvent {
  method?: TwoFactorMethod;
}

export interface UsernameModeration extends Enableable {
  applicationId?: UUID;
}

/**
 * Authentication key request object.
 *
 * @author Sanjay
 */
export interface APIKeyRequest {
  apiKey?: APIKey;
  sourceKeyId?: UUID;
}

export interface EventConfigurationData extends Enableable {
  transactionType?: TransactionType;
}

/**
 * The <i>authenticator's</i> response for the registration ceremony in its encoded format
 *
 * @author Spencer Witt
 */
export interface WebAuthnAuthenticatorRegistrationResponse {
  attestationObject?: string;
  clientDataJSON?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface PasswordlessLoginRequest extends BaseLoginRequest {
  code?: string;
  oneTimeCode?: string;
  twoFactorTrustId?: string;
}

/**
 * Search criteria for Consents
 *
 * @author Spencer Witt
 */
export interface ConsentSearchCriteria extends BaseSearchCriteria {
  name?: string;
}

/**
 * JWT Configuration. A JWT Configuration for an Application may not be active if it is using the global configuration, the configuration
 * may be <code>enabled = false</code>.
 *
 * @author Daniel DeGroff
 */
export interface JWTConfiguration extends Enableable {
  accessTokenKeyId?: UUID;
  idTokenKeyId?: UUID;
  refreshTokenExpirationPolicy?: RefreshTokenExpirationPolicy;
  refreshTokenOneTimeUseConfiguration?: RefreshTokenOneTimeUseConfiguration;
  refreshTokenRevocationPolicy?: RefreshTokenRevocationPolicy;
  refreshTokenSlidingWindowConfiguration?: RefreshTokenSlidingWindowConfiguration;
  refreshTokenTimeToLiveInMinutes?: number;
  refreshTokenUsagePolicy?: RefreshTokenUsagePolicy;
  timeToLiveInSeconds?: number;
}

export interface EmailTemplateErrors {
  parseErrors?: Record<string, string>;
  renderErrors?: Record<string, string>;
}

/**
 * Models the User Login event that is suspicious.
 *
 * @author Daniel DeGroff
 */
export interface UserLoginSuspiciousEvent extends UserLoginSuccessEvent {
  threatsDetected?: Array<AuthenticationThreats>;
}

/**
 * Describes the Relying Party's requirements for <a href="https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential">client-side
 * discoverable credentials</a> (formerly known as "resident keys")
 *
 * @author Spencer Witt
 */
export enum ResidentKeyRequirement {
  discouraged = "discouraged",
  preferred = "preferred",
  required = "required"
}

/**
 * @author Daniel DeGroff
 */
export interface TestEvent extends BaseEvent {
  message?: string;
}

/**
 * Webhook API response object.
 *
 * @author Brian Pontarelli
 */
export interface WebhookResponse {
  webhook?: Webhook;
  webhooks?: Array<Webhook>;
}

/**
 * Information about a user event (login, register, etc) that helps identify the source of the event (location, device type, OS, etc).
 *
 * @author Brian Pontarelli
 */
export interface EventInfo {
  data?: Record<string, any>;
  deviceDescription?: string;
  deviceName?: string;
  deviceType?: string;
  ipAddress?: string;
  location?: Location;
  os?: string;
  userAgent?: string;
}

/**
 * Lambda API response object.
 *
 * @author Brian Pontarelli
 */
export interface LambdaResponse {
  lambda?: Lambda;
  lambdas?: Array<Lambda>;
}

/**
 * @author Brett Guy
 */
export enum ClientAuthenticationPolicy {
  Required = "Required",
  NotRequired = "NotRequired",
  NotRequiredWhenUsingPKCE = "NotRequiredWhenUsingPKCE"
}

/**
 * @author Daniel DeGroff
 */
export enum RefreshTokenUsagePolicy {
  Reusable = "Reusable",
  OneTimeUse = "OneTimeUse"
}

/**
 * Container for the event information. This is the JSON that is sent from FusionAuth to webhooks.
 *
 * @author Brian Pontarelli
 */
export interface EventRequest {
  event?: BaseEvent;
}

/**
 * Available Integrations
 *
 * @author Daniel DeGroff
 */
export interface Integrations {
  cleanspeak?: CleanSpeakConfiguration;
  kafka?: KafkaConfiguration;
}

/**
 * Models the User Password Update Event.
 *
 * @author Daniel DeGroff
 */
export interface UserPasswordUpdateEvent extends BaseUserEvent {
}

/**
 * Standard error domain object that can also be used as the response from an API call.
 *
 * @author Brian Pontarelli
 */
export interface Errors {
  fieldErrors?: Record<string, Array<Error>>;
  generalErrors?: Array<Error>;
}

/**
 * @author Michael Sleevi
 */
export interface PreviewMessageTemplateResponse {
  errors?: Errors;
  message?: SMSMessage;
}

/**
 * The possible states of an individual webhook attempt to a single endpoint.
 *
 * @author Spencer Witt
 */
export enum WebhookAttemptResult {
  Success = "Success",
  Failure = "Failure",
  Unknown = "Unknown"
}

/**
 * @author Daniel DeGroff
 */
export interface TenantFormConfiguration {
  adminUserFormId?: UUID;
}

export enum DeviceType {
  BROWSER = "BROWSER",
  DESKTOP = "DESKTOP",
  LAPTOP = "LAPTOP",
  MOBILE = "MOBILE",
  OTHER = "OTHER",
  SERVER = "SERVER",
  TABLET = "TABLET",
  TV = "TV",
  UNKNOWN = "UNKNOWN"
}

/**
 * Event log used internally by FusionAuth to help developers debug hooks, Webhooks, email templates, etc.
 *
 * @author Brian Pontarelli
 */
export interface EventLog {
  id?: number;
  insertInstant?: number;
  message?: string;
  type?: EventLogType;
}

/**
 * This class is a simple attachment with a byte array, name and MIME type.
 *
 * @author Brian Pontarelli
 */
export interface Attachment {
  attachment?: Array<number>;
  mime?: string;
  name?: string;
}

/**
 * Config for Usage Data / Stats
 *
 * @author Lyle Schemmerling
 */
export interface UsageDataConfiguration extends Enableable {
  numberOfDaysToRetain?: number;
}

/**
 * A grant for an entity to a user or another entity.
 *
 * @author Brian Pontarelli
 */
export interface EntityGrant {
  data?: Record<string, any>;
  entity?: Entity;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  permissions?: Array<string>;
  recipientEntityId?: UUID;
  userId?: UUID;
}

/**
 * User comment search response
 *
 * @author Spencer Witt
 */
export interface UserCommentSearchResponse {
  total?: number;
  userComments?: Array<UserComment>;
}

/**
 * @author Brett Pontarelli
 */
export enum CaptchaMethod {
  GoogleRecaptchaV2 = "GoogleRecaptchaV2",
  GoogleRecaptchaV3 = "GoogleRecaptchaV3",
  HCaptcha = "HCaptcha",
  HCaptchaEnterprise = "HCaptchaEnterprise"
}

/**
 * @author Seth Musselman
 */
export interface Application {
  accessControlConfiguration?: ApplicationAccessControlConfiguration;
  active?: boolean;
  authenticationTokenConfiguration?: AuthenticationTokenConfiguration;
  cleanSpeakConfiguration?: CleanSpeakConfiguration;
  data?: Record<string, any>;
  emailConfiguration?: ApplicationEmailConfiguration;
  externalIdentifierConfiguration?: ApplicationExternalIdentifierConfiguration;
  formConfiguration?: ApplicationFormConfiguration;
  id?: UUID;
  insertInstant?: number;
  jwtConfiguration?: JWTConfiguration;
  lambdaConfiguration?: LambdaConfiguration;
  lastUpdateInstant?: number;
  loginConfiguration?: LoginConfiguration;
  multiFactorConfiguration?: ApplicationMultiFactorConfiguration;
  name?: string;
  oauthConfiguration?: OAuth2Configuration;
  passwordlessConfiguration?: PasswordlessConfiguration;
  registrationConfiguration?: RegistrationConfiguration;
  registrationDeletePolicy?: ApplicationRegistrationDeletePolicy;
  roles?: Array<ApplicationRole>;
  samlv2Configuration?: SAMLv2Configuration;
  scopes?: Array<ApplicationOAuthScope>;
  state?: ObjectState;
  tenantId?: UUID;
  themeId?: UUID;
  unverified?: RegistrationUnverifiedOptions;
  verificationEmailTemplateId?: UUID;
  verificationStrategy?: VerificationStrategy;
  verifyRegistration?: boolean;
  webAuthnConfiguration?: ApplicationWebAuthnConfiguration;
}

/**
 * @author Daniel DeGroff
 */
export interface SortField {
  missing?: string;
  name?: string;
  order?: Sort;
}

/**
 * SAML v2 IdP Initiated identity provider configuration.
 *
 * @author Daniel DeGroff
 */
export interface SAMLv2IdPInitiatedIdentityProvider extends BaseSAMLv2IdentityProvider<SAMLv2IdPInitiatedApplicationConfiguration> {
  issuer?: string;
}

/**
 * Search criteria for the event log.
 *
 * @author Brian Pontarelli
 */
export interface EventLogSearchCriteria extends BaseSearchCriteria {
  end?: number;
  message?: string;
  start?: number;
  type?: EventLogType;
}

export enum KeyAlgorithm {
  ES256 = "ES256",
  ES384 = "ES384",
  ES512 = "ES512",
  HS256 = "HS256",
  HS384 = "HS384",
  HS512 = "HS512",
  RS256 = "RS256",
  RS384 = "RS384",
  RS512 = "RS512"
}

/**
 * @author Daniel DeGroff
 */
export interface JWTVendResponse {
  token?: string;
}

/**
 * Reindex API request
 *
 * @author Daniel DeGroff
 */
export interface ReindexRequest {
  index?: string;
}

/**
 * Entity grant API response object.
 *
 * @author Brian Pontarelli
 */
export interface EntityGrantResponse {
  grant?: EntityGrant;
  grants?: Array<EntityGrant>;
}

export interface RegistrationConfiguration extends Enableable {
  birthDate?: Requirable;
  confirmPassword?: boolean;
  firstName?: Requirable;
  formId?: UUID;
  fullName?: Requirable;
  lastName?: Requirable;
  loginIdType?: LoginIdType;
  middleName?: Requirable;
  mobilePhone?: Requirable;
  preferredLanguages?: Requirable;
  type?: RegistrationType;
}

export interface VerificationId {
  id?: string;
  oneTimeCode?: string;
  type?: IdentityType;
  value?: string;
}

/**
 * Helper interface that indicates an identity provider can be federated to using the HTTP POST method.
 *
 * @author Brian Pontarelli
 */
export interface SupportsPostBindings {
}

/**
 * @author Daniel DeGroff
 */
export interface OAuth2Configuration {
  authorizedOriginURLs?: Array<string>;
  authorizedRedirectURLs?: Array<string>;
  authorizedURLValidationPolicy?: Oauth2AuthorizedURLValidationPolicy;
  clientAuthenticationPolicy?: ClientAuthenticationPolicy;
  clientId?: string;
  clientSecret?: string;
  consentMode?: OAuthScopeConsentMode;
  debug?: boolean;
  deviceVerificationURL?: string;
  enabledGrants?: Array<GrantType>;
  generateRefreshTokens?: boolean;
  logoutBehavior?: LogoutBehavior;
  logoutURL?: string;
  proofKeyForCodeExchangePolicy?: ProofKeyForCodeExchangePolicy;
  providedScopePolicy?: ProvidedScopePolicy;
  relationship?: OAuthApplicationRelationship;
  requireClientAuthentication?: boolean;
  requireRegistration?: boolean;
  scopeHandlingPolicy?: OAuthScopeHandlingPolicy;
  unknownScopePolicy?: UnknownScopePolicy;
}

/**
 * @author Daniel DeGroff
 */
export interface TwoFactorSendRequest {
  applicationId?: UUID;
  email?: string;
  method?: string;
  methodId?: string;
  mobilePhone?: string;
  userId?: UUID;
}

/**
 * Search criteria for Applications
 *
 * @author Spencer Witt
 */
export interface ApplicationSearchCriteria extends BaseSearchCriteria {
  name?: string;
  state?: ObjectState;
  tenantId?: UUID;
}

/**
 * Models the User Registration Verified Event.
 *
 * @author Trevor Smith
 */
export interface UserRegistrationVerifiedEvent extends BaseUserEvent {
  applicationId?: UUID;
  registration?: UserRegistration;
}

/**
 * A Message Template Request to the API
 *
 * @author Michael Sleevi
 */
export interface MessageTemplateRequest {
  messageTemplate?: MessageTemplate;
}

/**
 * Entity Type API request object.
 *
 * @author Brian Pontarelli
 */
export interface EntityTypeRequest {
  entityType?: EntityType;
  permission?: EntityTypePermission;
}

/**
 * A marker interface indicating this event cannot be made transactional.
 *
 * @author Daniel DeGroff
 */
export interface NonTransactionalEvent {
}

/**
 * Models the User Create Event.
 *
 * @author Brian Pontarelli
 */
export interface UserCreateEvent extends BaseUserEvent {
}

/**
 * @author Daniel DeGroff
 */
export interface ApplicationMultiFactorConfiguration {
  email?: MultiFactorEmailTemplate;
  loginPolicy?: MultiFactorLoginPolicy;
  sms?: MultiFactorSMSTemplate;
  trustPolicy?: ApplicationMultiFactorTrustPolicy;
}

/**
 * @author Daniel DeGroff
 */
export enum FormType {
  registration = "registration",
  adminRegistration = "adminRegistration",
  adminUser = "adminUser",
  selfServiceUser = "selfServiceUser"
}

/**
 * @author Brian Pontarelli
 */
export interface TwoFactorRequest extends BaseEventRequest {
  applicationId?: UUID;
  authenticatorId?: string;
  code?: string;
  email?: string;
  method?: string;
  mobilePhone?: string;
  secret?: string;
  secretBase32Encoded?: string;
  twoFactorId?: string;
}

/**
 * User Action Reason API request object.
 *
 * @author Brian Pontarelli
 */
export interface UserActionReasonRequest {
  userActionReason?: UserActionReason;
}

/**
 * Domain for a public key, key pair or an HMAC secret. This is used by KeyMaster to manage keys for JWTs, SAML, etc.
 *
 * @author Brian Pontarelli
 */
export interface Key {
  algorithm?: KeyAlgorithm;
  certificate?: string;
  certificateInformation?: CertificateInformation;
  expirationInstant?: number;
  hasPrivateKey?: boolean;
  id?: UUID;
  insertInstant?: number;
  issuer?: string;
  kid?: string;
  lastUpdateInstant?: number;
  length?: number;
  name?: string;
  privateKey?: string;
  publicKey?: string;
  secret?: string;
  type?: KeyType;
}

/**
 * Models the User Bulk Create Event.
 *
 * @author Brian Pontarelli
 */
export interface UserBulkCreateEvent extends BaseEvent {
  users?: Array<User>;
}

/**
 * @author Daniel DeGroff
 */
export interface IdentityProviderOauth2Configuration {
  authorization_endpoint?: string;
  client_id?: string;
  client_secret?: string;
  clientAuthenticationMethod?: ClientAuthenticationMethod;
  emailClaim?: string;
  emailVerifiedClaim?: string;
  issuer?: string;
  scope?: string;
  token_endpoint?: string;
  uniqueIdClaim?: string;
  userinfo_endpoint?: string;
  usernameClaim?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface IntrospectResponse extends Record<string, any> {
}

/**
 * @author Daniel DeGroff
 */
export interface RefreshTokenRevocationPolicy {
  onLoginPrevented?: boolean;
  onMultiFactorEnable?: boolean;
  onOneTimeTokenReuse?: boolean;
  onPasswordChanged?: boolean;
}

/**
 * Base class for all {@link User}-related events.
 *
 * @author Spencer Witt
 */
export interface BaseUserEvent extends BaseEvent {
  user?: User;
}

/**
 * @author Daniel DeGroff
 */
export interface MinimumPasswordAge extends Enableable {
  seconds?: number;
}

/**
 * Authentication key response object.
 *
 * @author Sanjay
 */
export interface APIKeyResponse {
  apiKey?: APIKey;
}

/**
 * Models the identity verified event
 *
 * @author Brady Wied
 */
export interface IdentityVerifiedEvent extends BaseUserEvent {
  loginId?: string;
  loginIdType?: string;
}

/**
 * Used to indicate what type of attestation was included in the authenticator response for a given WebAuthn credential at the time it was created
 *
 * @author Spencer Witt
 */
export enum AttestationType {
  basic = "basic",
  self = "self",
  attestationCa = "attestationCa",
  anonymizationCa = "anonymizationCa",
  none = "none"
}

/**
 * Models the Group Update Event.
 *
 * @author Daniel DeGroff
 */
export interface GroupUpdateEvent extends BaseGroupEvent {
  original?: Group;
}

/**
 * Models an entity that a user can be granted permissions to. Or an entity that can be granted permissions to another entity.
 *
 * @author Brian Pontarelli
 */
export interface Entity {
  clientId?: string;
  clientSecret?: string;
  data?: Record<string, any>;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  name?: string;
  parentId?: UUID;
  tenantId?: UUID;
  type?: EntityType;
}

export enum KeyType {
  EC = "EC",
  RSA = "RSA",
  HMAC = "HMAC"
}

/**
 * @author Brian Pontarelli
 */
export interface EventLogSearchRequest {
  search?: EventLogSearchCriteria;
}

/**
 * Models the reason that {@link UserIdentity#verified} was set to true or false.
 *
 * @author Brady Wied
 */
export enum IdentityVerifiedReason {
  Skipped = "Skipped",
  Trusted = "Trusted",
  Unverifiable = "Unverifiable",
  Implicit = "Implicit",
  Pending = "Pending",
  Completed = "Completed",
  Disabled = "Disabled"
}

/**
 * The types of connectors. This enum is stored as an ordinal on the <code>identities</code> table, order must be maintained.
 *
 * @author Trevor Smith
 */
export enum ConnectorType {
  FusionAuth = "FusionAuth",
  Generic = "Generic",
  LDAP = "LDAP"
}

/**
 * Import request.
 *
 * @author Brian Pontarelli
 */
export interface ImportRequest extends BaseEventRequest {
  encryptionScheme?: string;
  factor?: number;
  users?: Array<User>;
  validateDbConstraints?: boolean;
}

/**
 * @author Daniel DeGroff
 */
export interface FormFieldValidator extends Enableable {
  expression?: string;
}

/**
 * Search request for entity grants.
 *
 * @author Brian Pontarelli
 */
export interface EntityGrantSearchRequest {
  search?: EntityGrantSearchCriteria;
}

/**
 * Webhook search response
 *
 * @author Spencer Witt
 */
export interface WebhookSearchResponse {
  total?: number;
  webhooks?: Array<Webhook>;
}

/**
 * @author Daniel DeGroff
 */
export interface AppleIdentityProvider extends BaseIdentityProvider<AppleApplicationConfiguration> {
  bundleId?: string;
  buttonText?: string;
  keyId?: UUID;
  scope?: string;
  servicesId?: string;
  teamId?: string;
}

/**
 * User registration information for a single application.
 *
 * @author Brian Pontarelli
 */
export interface UserRegistration {
  applicationId?: UUID;
  authenticationToken?: string;
  cleanSpeakId?: UUID;
  data?: Record<string, any>;
  id?: UUID;
  insertInstant?: number;
  lastLoginInstant?: number;
  lastUpdateInstant?: number;
  preferredLanguages?: Array<string>;
  roles?: Array<string>;
  timezone?: string;
  tokens?: Record<string, string>;
  username?: string;
  usernameStatus?: ContentStatus;
  verified?: boolean;
  verifiedInstant?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface SecureIdentity {
  breachedPasswordLastCheckedInstant?: number;
  breachedPasswordStatus?: BreachedPasswordStatus;
  connectorId?: UUID;
  encryptionScheme?: string;
  factor?: number;
  id?: UUID;
  identities?: Array<UserIdentity>;
  lastLoginInstant?: number;
  password?: string;
  passwordChangeReason?: ChangePasswordReason;
  passwordChangeRequired?: boolean;
  passwordLastUpdateInstant?: number;
  salt?: string;
  uniqueUsername?: string;
  username?: string;
  usernameStatus?: ContentStatus;
  verified?: boolean;
  verifiedInstant?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface ApplicationExternalIdentifierConfiguration {
  twoFactorTrustIdTimeToLiveInSeconds?: number;
}

/**
 * Entity Type API response object.
 *
 * @author Brian Pontarelli
 */
export interface EntityTypeResponse {
  entityType?: EntityType;
  entityTypes?: Array<EntityType>;
  permission?: EntityTypePermission;
}

export interface LoginRecordConfiguration {
  delete?: DeleteConfiguration;
}

/**
 * @author Daniel DeGroff
 */
export interface VerifyEmailResponse {
  oneTimeCode?: string;
  verificationId?: string;
}

/**
 * @author Brian Pontarelli
 */
export interface EventConfiguration {
  events?: Record<EventType, EventConfigurationData>;
}

/**
 * Models an event where a user is being updated and tries to use an "in-use" login Id (email or username).
 *
 * @author Daniel DeGroff
 */
export interface UserLoginIdDuplicateOnUpdateEvent extends UserLoginIdDuplicateOnCreateEvent {
}

/**
 * Models the Group Member Remove Complete Event.
 *
 * @author Daniel DeGroff
 */
export interface GroupMemberRemoveCompleteEvent extends BaseGroupEvent {
  members?: Array<GroupMember>;
}

/**
 * @author Brady Wied
 */
export interface VerifySendCompleteRequest extends BaseEventRequest {
  oneTimeCode?: string;
  verificationId?: string;
}

export interface EventLogConfiguration {
  numberToRetain?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface IdentityProviderResponse {
  identityProvider?: BaseIdentityProvider<any>;
  identityProviders?: Array<BaseIdentityProvider<any>>;
}

/**
 * Search request for webhooks
 *
 * @author Spencer Witt
 */
export interface WebhookSearchRequest {
  search?: WebhookSearchCriteria;
}

/**
 * @author Brady Wied
 */
export interface IdentityType {
  name?: string;
}

/**
 * Models the Group Member Add Complete Event.
 *
 * @author Daniel DeGroff
 */
export interface GroupMemberAddCompleteEvent extends BaseGroupEvent {
  members?: Array<GroupMember>;
}

/**
 * @author Daniel DeGroff
 */
export enum MultiFactorLoginPolicy {
  Disabled = "Disabled",
  Enabled = "Enabled",
  Required = "Required"
}

/**
 * @author Daniel DeGroff
 */
export interface PasswordlessStartRequest {
  applicationId?: UUID;
  loginId?: string;
  loginIdType?: string;
  loginStrategy?: string;
  state?: Record<string, any>;
}

/**
 * @author Daniel DeGroff
 */
export interface ExternalIdentifierConfiguration {
  authorizationGrantIdTimeToLiveInSeconds?: number;
  changePasswordIdGenerator?: SecureGeneratorConfiguration;
  changePasswordIdTimeToLiveInSeconds?: number;
  deviceCodeTimeToLiveInSeconds?: number;
  deviceUserCodeIdGenerator?: SecureGeneratorConfiguration;
  emailVerificationIdGenerator?: SecureGeneratorConfiguration;
  emailVerificationIdTimeToLiveInSeconds?: number;
  emailVerificationOneTimeCodeGenerator?: SecureGeneratorConfiguration;
  externalAuthenticationIdTimeToLiveInSeconds?: number;
  loginIntentTimeToLiveInSeconds?: number;
  oneTimePasswordTimeToLiveInSeconds?: number;
  passwordlessLoginGenerator?: SecureGeneratorConfiguration;
  passwordlessLoginTimeToLiveInSeconds?: number;
  passwordlessShortCodeLoginGenerator?: SecureGeneratorConfiguration;
  passwordlessShortCodeLoginTimeToLiveInSeconds?: number;
  pendingAccountLinkTimeToLiveInSeconds?: number;
  phoneNumberVerificationIdGenerator?: SecureGeneratorConfiguration;
  phoneNumberVerificationIdTimeToLiveInSeconds?: number;
  phoneNumberVerificationOneTimeCodeGenerator?: SecureGeneratorConfiguration;
  registrationVerificationIdGenerator?: SecureGeneratorConfiguration;
  registrationVerificationIdTimeToLiveInSeconds?: number;
  registrationVerificationOneTimeCodeGenerator?: SecureGeneratorConfiguration;
  rememberOAuthScopeConsentChoiceTimeToLiveInSeconds?: number;
  samlv2AuthNRequestIdTimeToLiveInSeconds?: number;
  setupPasswordIdGenerator?: SecureGeneratorConfiguration;
  setupPasswordIdTimeToLiveInSeconds?: number;
  trustTokenTimeToLiveInSeconds?: number;
  twoFactorIdTimeToLiveInSeconds?: number;
  twoFactorOneTimeCodeIdGenerator?: SecureGeneratorConfiguration;
  twoFactorOneTimeCodeIdTimeToLiveInSeconds?: number;
  twoFactorTrustIdTimeToLiveInSeconds?: number;
  webAuthnAuthenticationChallengeTimeToLiveInSeconds?: number;
  webAuthnRegistrationChallengeTimeToLiveInSeconds?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface LoginRecordExportRequest extends BaseExportRequest {
  criteria?: LoginRecordSearchCriteria;
}

/**
 * Describes the <a href="https://www.w3.org/TR/webauthn-2/#authenticator-attachment-modality">authenticator attachment modality</a>.
 *
 * @author Spencer Witt
 */
export enum AuthenticatorAttachment {
  platform = "platform",
  crossPlatform = "crossPlatform"
}

/**
 * Email template response.
 *
 * @author Brian Pontarelli
 */
export interface EmailTemplateResponse {
  emailTemplate?: EmailTemplate;
  emailTemplates?: Array<EmailTemplate>;
}

export interface TenantOAuth2Configuration {
  clientCredentialsAccessTokenPopulateLambdaId?: UUID;
}

/**
 * Request to register a new public key with WebAuthn
 *
 * @author Spencer Witt
 */
export interface WebAuthnPublicKeyRegistrationRequest {
  clientExtensionResults?: WebAuthnExtensionsClientOutputs;
  id?: string;
  response?: WebAuthnAuthenticatorRegistrationResponse;
  rpId?: string;
  transports?: Array<string>;
  type?: string;
}

/**
 * User API response object.
 *
 * @author Brian Pontarelli
 */
export interface UserResponse {
  emailVerificationId?: string;
  emailVerificationOneTimeCode?: string;
  registrationVerificationIds?: Record<UUID, string>;
  registrationVerificationOneTimeCodes?: Record<UUID, string>;
  token?: string;
  tokenExpirationInstant?: number;
  user?: User;
  verificationIds?: Array<VerificationId>;
}

/**
 * @author Daniel DeGroff
 */
export interface DeviceInfo {
  description?: string;
  lastAccessedAddress?: string;
  lastAccessedInstant?: number;
  name?: string;
  type?: string;
}

/**
 * @author Michael Sleevi
 */
export interface SMSMessageTemplate extends MessageTemplate {
  defaultTemplate?: string;
  localizedTemplates?: LocalizedStrings;
}

/**
 * User Action Reason API response object.
 *
 * @author Brian Pontarelli
 */
export interface UserActionReasonResponse {
  userActionReason?: UserActionReason;
  userActionReasons?: Array<UserActionReason>;
}

/**
 * @author Daniel DeGroff
 */
export interface UserTwoFactorConfiguration {
  methods?: Array<TwoFactorMethod>;
  recoveryCodes?: Array<string>;
}

/**
 * @author Daniel DeGroff
 */
export interface PendingIdPLink {
  displayName?: string;
  email?: string;
  identityProviderId?: UUID;
  identityProviderLinks?: Array<IdentityProviderLink>;
  identityProviderName?: string;
  identityProviderTenantConfiguration?: IdentityProviderTenantConfiguration;
  identityProviderType?: IdentityProviderType;
  identityProviderUserId?: string;
  user?: User;
  username?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface JWKSResponse {
  keys?: Array<JSONWebKey>;
}

/**
 * The Integration Response
 *
 * @author Daniel DeGroff
 */
export interface IntegrationResponse {
  integrations?: Integrations;
}

/**
 * API response for starting a WebAuthn registration ceremony
 *
 * @author Spencer Witt
 */
export interface WebAuthnRegisterStartResponse {
  options?: PublicKeyCredentialCreationOptions;
}

/**
 * @author Brett Pontarelli
 */
export interface TenantCaptchaConfiguration extends Enableable {
  captchaMethod?: CaptchaMethod;
  secretKey?: string;
  siteKey?: string;
  threshold?: number;
}

/**
 * The Application API response.
 *
 * @author Brian Pontarelli
 */
export interface ApplicationResponse {
  application?: Application;
  applications?: Array<Application>;
  role?: ApplicationRole;
}

/**
 * COSE Elliptic Curve identifier to determine which elliptic curve to use with a given key
 *
 * @author Spencer Witt
 */
export enum CoseEllipticCurve {
  Reserved = "Reserved",
  P256 = "P256",
  P384 = "P384",
  P521 = "P521",
  X25519 = "X25519",
  X448 = "X448",
  Ed25519 = "Ed25519",
  Ed448 = "Ed448",
  Secp256k1 = "Secp256k1"
}

//      This is separate from IdentityType.
export enum LoginIdType {
  email = "email",
  phoneNumber = "phoneNumber",
  username = "username"
}

/**
 * @author Daniel DeGroff
 */
export interface OpenIdConnectIdentityProvider extends BaseIdentityProvider<OpenIdConnectApplicationConfiguration> {
  buttonImageURL?: string;
  buttonText?: string;
  domains?: Array<string>;
  oauth2?: IdentityProviderOauth2Configuration;
  postRequest?: boolean;
}

export interface UIConfiguration {
  headerColor?: string;
  logoURL?: string;
  menuFontColor?: string;
}

/**
 * Webhook event log response.
 *
 * @author Spencer Witt
 */
export interface WebhookEventLogResponse {
  webhookEventLog?: WebhookEventLog;
}

/**
 * The public Status API response
 *
 * @author Daniel DeGroff
 */
export interface StatusResponse extends Record<string, any> {
}

export enum RegistrationType {
  basic = "basic",
  advanced = "advanced"
}

/**
 * @author Brett Pontarelli
 */
export interface XboxApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
}

/**
 * Search criteria for Groups
 *
 * @author Daniel DeGroff
 */
export interface GroupSearchCriteria extends BaseSearchCriteria {
  name?: string;
  tenantId?: UUID;
}

export interface MultiFactorSMSMethod extends Enableable {
  messengerId?: UUID;
  templateId?: UUID;
}

/**
 * @author Brett Guy
 */
export interface MessengerResponse {
  messenger?: BaseMessengerConfiguration;
  messengers?: Array<BaseMessengerConfiguration>;
}

/**
 * Models the User Login Failed Event.
 *
 * @author Daniel DeGroff
 */
export interface UserLoginFailedEvent extends BaseUserEvent {
  applicationId?: UUID;
  authenticationType?: string;
  ipAddress?: string;
  reason?: UserLoginFailedReason;
}

/**
 * @author Daniel DeGroff
 */
export interface Tenant {
  accessControlConfiguration?: TenantAccessControlConfiguration;
  captchaConfiguration?: TenantCaptchaConfiguration;
  configured?: boolean;
  connectorPolicies?: Array<ConnectorPolicy>;
  data?: Record<string, any>;
  emailConfiguration?: EmailConfiguration;
  eventConfiguration?: EventConfiguration;
  externalIdentifierConfiguration?: ExternalIdentifierConfiguration;
  failedAuthenticationConfiguration?: FailedAuthenticationConfiguration;
  familyConfiguration?: FamilyConfiguration;
  formConfiguration?: TenantFormConfiguration;
  httpSessionMaxInactiveInterval?: number;
  id?: UUID;
  insertInstant?: number;
  issuer?: string;
  jwtConfiguration?: JWTConfiguration;
  lambdaConfiguration?: TenantLambdaConfiguration;
  lastUpdateInstant?: number;
  loginConfiguration?: TenantLoginConfiguration;
  logoutURL?: string;
  maximumPasswordAge?: MaximumPasswordAge;
  minimumPasswordAge?: MinimumPasswordAge;
  multiFactorConfiguration?: TenantMultiFactorConfiguration;
  name?: string;
  oauthConfiguration?: TenantOAuth2Configuration;
  passwordEncryptionConfiguration?: PasswordEncryptionConfiguration;
  passwordValidationRules?: PasswordValidationRules;
  phoneConfiguration?: TenantPhoneConfiguration;
  rateLimitConfiguration?: TenantRateLimitConfiguration;
  registrationConfiguration?: TenantRegistrationConfiguration;
  scimServerConfiguration?: TenantSCIMServerConfiguration;
  ssoConfiguration?: TenantSSOConfiguration;
  state?: ObjectState;
  themeId?: UUID;
  userDeletePolicy?: TenantUserDeletePolicy;
  usernameConfiguration?: TenantUsernameConfiguration;
  webAuthnConfiguration?: TenantWebAuthnConfiguration;
}

/**
 * @author Daniel DeGroff
 */
export enum PasswordlessStrategy {
  ClickableLink = "ClickableLink",
  FormField = "FormField"
}

/**
 * Models the Group Member Update Complete Event.
 *
 * @author Daniel DeGroff
 */
export interface GroupMemberUpdateCompleteEvent extends BaseGroupEvent {
  members?: Array<GroupMember>;
}

// Do not require a setter for 'type', it is defined by the concrete class and is not mutable
export interface BaseMessengerConfiguration {
  data?: Record<string, any>;
  debug?: boolean;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  name?: string;
  transport?: string;
  type?: MessengerType;
}

/**
 * @author Daniel DeGroff
 */
export interface TwoFactorStartResponse {
  code?: string;
  methods?: Array<TwoFactorMethod>;
  twoFactorId?: string;
}

export interface PasswordlessConfiguration extends Enableable {
}

/**
 * Search request for entity grants.
 *
 * @author Brian Pontarelli
 */
export interface EntityGrantSearchResponse {
  grants?: Array<EntityGrant>;
  total?: number;
}

/**
 * @author Trevor Smith
 */
export interface Theme {
  data?: Record<string, any>;
  defaultMessages?: string;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  localizedMessages?: LocalizedStrings;
  name?: string;
  stylesheet?: string;
  templates?: Templates;
  type?: ThemeType;
  variables?: SimpleThemeVariables;
}

/**
 * @author Daniel DeGroff
 */
export enum RefreshTokenExpirationPolicy {
  Fixed = "Fixed",
  SlidingWindow = "SlidingWindow",
  SlidingWindowWithMaximumLifetime = "SlidingWindowWithMaximumLifetime"
}

/**
 * Login API request object used for login to third-party systems (i.e. Login with Facebook).
 *
 * @author Brian Pontarelli
 */
export interface IdentityProviderLoginRequest extends BaseLoginRequest {
  data?: Record<string, string>;
  encodedJWT?: string;
  identityProviderId?: UUID;
  noLink?: boolean;
}

/**
 * Group API response object.
 *
 * @author Daniel DeGroff
 */
export interface GroupResponse {
  group?: Group;
  groups?: Array<Group>;
}

/**
 * A policy to configure if and when the user-action is canceled prior to the expiration of the action.
 *
 * @author Daniel DeGroff
 */
export interface FailedAuthenticationActionCancelPolicy {
  onPasswordReset?: boolean;
}

/**
 * @author Daniel DeGroff
 */
export enum UnverifiedBehavior {
  Allow = "Allow",
  Gated = "Gated"
}

/**
 * Models a consent.
 *
 * @author Daniel DeGroff
 */
export interface Consent {
  consentEmailTemplateId?: UUID;
  countryMinimumAgeForSelfConsent?: LocalizedIntegers;
  data?: Record<string, any>;
  defaultMinimumAgeForSelfConsent?: number;
  emailPlus?: EmailPlus;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  multipleValuesAllowed?: boolean;
  name?: string;
  values?: Array<string>;
}

/**
 * @author Brett Guy
 */
export interface IPAccessControlListRequest {
  ipAccessControlList?: IPAccessControlList;
}

/**
 * @author Brian Pontarelli
 */
export interface SAMLv2ApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  buttonImageURL?: string;
  buttonText?: string;
}

/**
 * @author Brian Pontarelli
 */
export interface AuditLogSearchRequest {
  search?: AuditLogSearchCriteria;
}

/**
 * Models the User Password Breach Event.
 *
 * @author Matthew Altman
 */
export interface UserPasswordBreachEvent extends BaseUserEvent {
}

/**
 * @author Daniel DeGroff
 */
export interface ReactorMetrics {
  breachedPasswordMetrics?: Record<UUID, BreachedPasswordTenantMetric>;
}

/**
 * @author Daniel DeGroff
 */
export interface SendRequest {
  applicationId?: UUID;
  bccAddresses?: Array<string>;
  ccAddresses?: Array<string>;
  preferredLanguages?: Array<string>;
  requestData?: Record<string, any>;
  toAddresses?: Array<EmailAddress>;
  userIds?: Array<UUID>;
}

export interface AuditLogConfiguration {
  delete?: DeleteConfiguration;
}

/**
 * User login failed reason codes.
 */
export interface UserLoginFailedReasonCode {
}

/**
 * Models the User Event (and can be converted to JSON) that is used for all user modifications (create, update,
 * delete).
 *
 * @author Brian Pontarelli
 */
export interface UserDeleteEvent extends BaseUserEvent {
}

/**
 * A custom OAuth scope for a specific application.
 *
 * @author Spencer Witt
 */
export interface ApplicationOAuthScope {
  applicationId?: UUID;
  data?: Record<string, any>;
  defaultConsentDetail?: string;
  defaultConsentMessage?: string;
  description?: string;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  name?: string;
  required?: boolean;
}

/**
 * Registration delete API request object.
 *
 * @author Brian Pontarelli
 */
export interface RegistrationDeleteRequest extends BaseEventRequest {
}

/**
 * The phases of a time-based user action.
 *
 * @author Brian Pontarelli
 */
export enum UserActionPhase {
  start = "start",
  modify = "modify",
  cancel = "cancel",
  end = "end"
}

/**
 * @author Daniel DeGroff
 */
export interface VerifyEmailRequest extends BaseEventRequest {
  oneTimeCode?: string;
  userId?: UUID;
  verificationId?: string;
}

/**
 * @author Brian Pontarelli
 */
export interface TwoFactorDisableRequest extends BaseEventRequest {
  applicationId?: UUID;
  code?: string;
  methodId?: string;
}

/**
 * Google social login provider.
 *
 * @author Daniel DeGroff
 */
export interface GoogleIdentityProvider extends BaseIdentityProvider<GoogleApplicationConfiguration> {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  loginMethod?: IdentityProviderLoginMethod;
  properties?: GoogleIdentityProviderProperties;
  scope?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface FormStep {
  fields?: Array<UUID>;
}

/**
 * A Tenant-level policy for deleting Users.
 *
 * @author Trevor Smith
 */
export interface TenantUserDeletePolicy {
  unverified?: TimeBasedDeletePolicy;
}

/**
 * @author Brett Pontarelli
 */
export interface SonyPSNApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
}

/**
 * Search request for Keys
 *
 * @author Spencer Witt
 */
export interface KeySearchRequest {
  search?: KeySearchCriteria;
}

/**
 * @author Daniel DeGroff
 */
export enum LambdaEngineType {
  GraalJS = "GraalJS",
  Nashorn = "Nashorn"
}

/**
 * @author Daniel DeGroff
 */
export interface SystemTrustedProxyConfiguration {
  trusted?: Array<string>;
  trustPolicy?: SystemTrustedProxyConfigurationPolicy;
}

/**
 * A log for an action that was taken on a User.
 *
 * @author Brian Pontarelli
 */
export interface UserActionLog {
  actioneeUserId?: UUID;
  actionerUserId?: UUID;
  applicationIds?: Array<UUID>;
  comment?: string;
  emailUserOnEnd?: boolean;
  endEventSent?: boolean;
  expiry?: number;
  history?: LogHistory;
  id?: UUID;
  insertInstant?: number;
  localizedName?: string;
  localizedOption?: string;
  localizedReason?: string;
  name?: string;
  notifyUserOnEnd?: boolean;
  option?: string;
  reason?: string;
  reasonCode?: string;
  userActionId?: UUID;
}

/**
 * Login Ping API request object.
 *
 * @author Daniel DeGroff
 */
export interface LoginPingRequest extends BaseLoginRequest {
  userId?: UUID;
}

/**
 * @author Daniel DeGroff
 */
export interface IdentityProviderLimitUserLinkingPolicy extends Enableable {
  maximumLinks?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface EmailUnverifiedOptions {
  allowEmailChangeWhenGated?: boolean;
  behavior?: UnverifiedBehavior;
}

/**
 * Base class for requests that can contain event information. This event information is used when sending Webhooks or emails
 * during the transaction. The caller is responsible for ensuring that the event information is correct.
 *
 * @author Brian Pontarelli
 */
export interface BaseEventRequest {
  eventInfo?: EventInfo;
}

export enum OAuthErrorType {
  invalid_request = "invalid_request",
  invalid_client = "invalid_client",
  invalid_grant = "invalid_grant",
  invalid_token = "invalid_token",
  unauthorized_client = "unauthorized_client",
  invalid_scope = "invalid_scope",
  server_error = "server_error",
  unsupported_grant_type = "unsupported_grant_type",
  unsupported_response_type = "unsupported_response_type",
  access_denied = "access_denied",
  change_password_required = "change_password_required",
  not_licensed = "not_licensed",
  two_factor_required = "two_factor_required",
  authorization_pending = "authorization_pending",
  expired_token = "expired_token",
  unsupported_token_type = "unsupported_token_type"
}

/**
 * Search request for Tenants
 *
 * @author Mark Manes
 */
export interface TenantSearchRequest {
  search?: TenantSearchCriteria;
}

/**
 * JWT Public Key Response Object
 *
 * @author Daniel DeGroff
 */
export interface PublicKeyResponse {
  publicKey?: string;
  publicKeys?: Record<string, string>;
}

/**
 * @author Daniel DeGroff
 */
export enum Sort {
  asc = "asc",
  desc = "desc"
}

/**
 * Forgot password request object.
 *
 * @author Brian Pontarelli
 */
export interface ForgotPasswordRequest extends BaseEventRequest {
  applicationId?: UUID;
  changePasswordId?: string;
  email?: string;
  loginId?: string;
  sendForgotPasswordEmail?: boolean;
  state?: Record<string, any>;
  username?: string;
}

/**
 * Identity Provider response.
 *
 * @author Spencer Witt
 */
export interface IdentityProviderSearchResponse {
  identityProviders?: Array<BaseIdentityProvider<any>>;
  total?: number;
}

export interface MetaData {
  data?: Record<string, any>;
  device?: DeviceInfo;
  scopes?: Array<string>;
}

export interface WebhookEventLog {
  attempts?: Array<WebhookAttemptLog>;
  data?: Record<string, any>;
  event?: Record<string, any>;
  eventResult?: WebhookEventResult;
  eventType?: EventType;
  failedAttempts?: number;
  id?: UUID;
  insertInstant?: number;
  lastAttemptInstant?: number;
  lastUpdateInstant?: number;
  linkedObjectId?: UUID;
  sequence?: number;
  successfulAttempts?: number;
}

export enum SAMLLogoutBehavior {
  AllParticipants = "AllParticipants",
  OnlyOriginator = "OnlyOriginator"
}

/**
 * @author Brian Pontarelli
 */
export interface EmailConfiguration {
  additionalHeaders?: Array<EmailHeader>;
  debug?: boolean;
  defaultFromEmail?: string;
  defaultFromName?: string;
  emailUpdateEmailTemplateId?: UUID;
  emailVerifiedEmailTemplateId?: UUID;
  forgotPasswordEmailTemplateId?: UUID;
  host?: string;
  implicitEmailVerificationAllowed?: boolean;
  loginIdInUseOnCreateEmailTemplateId?: UUID;
  loginIdInUseOnUpdateEmailTemplateId?: UUID;
  loginNewDeviceEmailTemplateId?: UUID;
  loginSuspiciousEmailTemplateId?: UUID;
  password?: string;
  passwordlessEmailTemplateId?: UUID;
  passwordResetSuccessEmailTemplateId?: UUID;
  passwordUpdateEmailTemplateId?: UUID;
  port?: number;
  properties?: string;
  security?: EmailSecurityType;
  setPasswordEmailTemplateId?: UUID;
  twoFactorMethodAddEmailTemplateId?: UUID;
  twoFactorMethodRemoveEmailTemplateId?: UUID;
  unverified?: EmailUnverifiedOptions;
  username?: string;
  verificationEmailTemplateId?: UUID;
  verificationStrategy?: VerificationStrategy;
  verifyEmail?: boolean;
  verifyEmailWhenChanged?: boolean;
}

/**
 * @author Daniel DeGroff
 */
export interface TenantLoginConfiguration {
  requireAuthentication?: boolean;
}

/**
 * The user action request object.
 *
 * @author Brian Pontarelli
 */
export interface ActionRequest extends BaseEventRequest {
  action?: ActionData;
  broadcast?: boolean;
}

/**
 * The IdP behavior when no user link has been made yet.
 *
 * @author Daniel DeGroff
 */
export enum IdentityProviderLinkingStrategy {
  CreatePendingLink = "CreatePendingLink",
  Disabled = "Disabled",
  LinkAnonymously = "LinkAnonymously",
  LinkByEmail = "LinkByEmail",
  LinkByEmailForExistingUser = "LinkByEmailForExistingUser",
  LinkByUsername = "LinkByUsername",
  LinkByUsernameForExistingUser = "LinkByUsernameForExistingUser",
  Unsupported = "Unsupported"
}

/**
 * @author Daniel DeGroff
 */
export interface IdentityProviderRequest {
  identityProvider?: BaseIdentityProvider<any>;
}

/**
 * @author Tyler Scott
 */
export interface Group {
  data?: Record<string, any>;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  name?: string;
  roles?: Record<UUID, Array<ApplicationRole>>;
  tenantId?: UUID;
}

/**
 * @author Lyle Schemmerling
 */
export interface SAMLv2AssertionConfiguration {
  destination?: SAMLv2DestinationAssertionConfiguration;
}

/**
 * Request to complete the WebAuthn registration ceremony for a new credential,.
 *
 * @author Spencer Witt
 */
export interface WebAuthnRegisterCompleteRequest {
  credential?: WebAuthnPublicKeyRegistrationRequest;
  origin?: string;
  rpId?: string;
  userId?: UUID;
}

/**
 * @author Daniel DeGroff
 */
export interface ReactorResponse {
  status?: ReactorStatus;
}

/**
 * A role given to a user for a specific application.
 *
 * @author Seth Musselman
 */
export interface ApplicationRole {
  description?: string;
  id?: UUID;
  insertInstant?: number;
  isDefault?: boolean;
  isSuperRole?: boolean;
  lastUpdateInstant?: number;
  name?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface VerifyRegistrationResponse {
  oneTimeCode?: string;
  verificationId?: string;
}

/**
 * @author Trevor Smith
 */
export interface CORSConfiguration extends Enableable {
  allowCredentials?: boolean;
  allowedHeaders?: Array<string>;
  allowedMethods?: Array<HTTPMethod>;
  allowedOrigins?: Array<string>;
  debug?: boolean;
  exposedHeaders?: Array<string>;
  preflightMaxAgeInSeconds?: number;
}

/**
 * Group Member Request
 *
 * @author Daniel DeGroff
 */
export interface MemberRequest {
  members?: Record<UUID, Array<GroupMember>>;
}

/**
 * @author Brian Pontarelli
 */
export interface BaseSearchCriteria {
  numberOfResults?: number;
  orderBy?: string;
  startRow?: number;
}

/**
 * Interface for any object that can provide JSON Web key Information.
 */
export interface JSONWebKeyInfoProvider {
}

export enum BreachAction {
  Off = "Off",
  RecordOnly = "RecordOnly",
  NotifyUser = "NotifyUser",
  RequireChange = "RequireChange"
}

/**
 * Event Log Type
 *
 * @author Daniel DeGroff
 */
export enum EventLogType {
  Information = "Information",
  Debug = "Debug",
  Error = "Error"
}

/**
 * Models the User Update Registration Event.
 *
 * @author Daniel DeGroff
 */
export interface UserRegistrationUpdateEvent extends BaseUserEvent {
  applicationId?: UUID;
  original?: UserRegistration;
  registration?: UserRegistration;
}

/**
 * Entity API response object.
 *
 * @author Brian Pontarelli
 */
export interface EntityResponse {
  entity?: Entity;
}

/**
 * Describes a user account or WebAuthn Relying Party associated with a public key credential
 */
export interface PublicKeyCredentialEntity {
  name?: string;
}

export interface ApplicationEmailConfiguration {
  emailUpdateEmailTemplateId?: UUID;
  emailVerificationEmailTemplateId?: UUID;
  emailVerifiedEmailTemplateId?: UUID;
  forgotPasswordEmailTemplateId?: UUID;
  loginIdInUseOnCreateEmailTemplateId?: UUID;
  loginIdInUseOnUpdateEmailTemplateId?: UUID;
  loginNewDeviceEmailTemplateId?: UUID;
  loginSuspiciousEmailTemplateId?: UUID;
  passwordlessEmailTemplateId?: UUID;
  passwordResetSuccessEmailTemplateId?: UUID;
  passwordUpdateEmailTemplateId?: UUID;
  setPasswordEmailTemplateId?: UUID;
  twoFactorMethodAddEmailTemplateId?: UUID;
  twoFactorMethodRemoveEmailTemplateId?: UUID;
}

/**
 * @author Daniel DeGroff
 */
export interface IdentityProviderStartLoginResponse {
  code?: string;
}

/**
 * @author Brett Pontarelli
 */
export interface EpicGamesApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
}

/**
 * Models the User Deleted Registration Event.
 * <p>
 * This is different than user.registration.delete in that it is sent after the TX has been committed. This event cannot be transactional.
 *
 * @author Daniel DeGroff
 */
export interface UserRegistrationDeleteCompleteEvent extends BaseUserEvent {
  applicationId?: UUID;
  registration?: UserRegistration;
}

/**
 * Group API request object.
 *
 * @author Daniel DeGroff
 */
export interface GroupRequest {
  group?: Group;
  roleIds?: Array<UUID>;
}

/**
 * User Comment Response
 *
 * @author Seth Musselman
 */
export interface UserCommentResponse {
  userComment?: UserComment;
  userComments?: Array<UserComment>;
}

/**
 * @author Daniel DeGroff
 */
export interface ValidateResponse {
  jwt?: JWT;
}

/**
 * Hold tenant phone configuration for passwordless and verification cases.
 *
 * @author Brady Wied
 */
export interface TenantPhoneConfiguration {
  messengerId?: UUID;
  passwordlessTemplateId?: UUID;
  unverified?: PhoneUnverifiedOptions;
  verificationCompleteTemplateId?: UUID;
  verificationStrategy?: VerificationStrategy;
  verificationTemplateId?: UUID;
  verifyPhoneNumber?: boolean;
}

/**
 * @author Daniel DeGroff
 */
export interface GoogleApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  loginMethod?: IdentityProviderLoginMethod;
  properties?: GoogleIdentityProviderProperties;
  scope?: string;
}

/**
 * Models the User Event (and can be converted to JSON) that is used for all user modifications (create, update,
 * delete).
 * <p>
 * This is different than user.delete because it is sent after the tx is committed, this cannot be transactional.
 *
 * @author Daniel DeGroff
 */
export interface UserDeleteCompleteEvent extends BaseUserEvent {
}

/**
 * Supply additional information about the user account when creating a new credential
 *
 * @author Spencer Witt
 */
export interface PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
  displayName?: string;
  id?: string;
}

/**
 * A JavaScript lambda function that is executed during certain events inside FusionAuth.
 *
 * @author Brian Pontarelli
 */
export interface Lambda {
  body?: string;
  debug?: boolean;
  engineType?: LambdaEngineType;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  name?: string;
  type?: LambdaType;
}

/**
 * Refresh token one-time use configuration. This configuration is utilized when the usage policy is
 * configured for one-time use.
 *
 * @author Daniel DeGroff
 */
export interface RefreshTokenOneTimeUseConfiguration {
  gracePeriodInSeconds?: number;
}

/**
 * SonyPSN gaming login provider.
 *
 * @author Brett Pontarelli
 */
export interface SonyPSNIdentityProvider extends BaseIdentityProvider<SonyPSNApplicationConfiguration> {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface BreachedPasswordTenantMetric {
  actionRequired?: number;
  matchedCommonPasswordCount?: number;
  matchedExactCount?: number;
  matchedPasswordCount?: number;
  matchedSubAddressCount?: number;
  passwordsCheckedCount?: number;
}

/**
 * @author Brett Pontarelli
 */
export interface NintendoApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  emailClaim?: string;
  scope?: string;
  uniqueIdClaim?: string;
  usernameClaim?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface TenantUnverifiedConfiguration {
  email?: UnverifiedBehavior;
  whenGated?: RegistrationUnverifiedOptions;
}

/**
 * @author Daniel DeGroff
 */
export interface LoginRecordSearchCriteria extends BaseSearchCriteria {
  applicationId?: UUID;
  end?: number;
  start?: number;
  userId?: UUID;
}

/**
 * Search request for entity types.
 *
 * @author Brian Pontarelli
 */
export interface EntityTypeSearchRequest {
  search?: EntityTypeSearchCriteria;
}

/**
 * Models the Refresh Token Revoke Event. This event might be for a single token, a user
 * or an entire application.
 *
 * @author Brian Pontarelli
 */
export interface JWTRefreshTokenRevokeEvent extends BaseEvent {
  applicationId?: UUID;
  applicationTimeToLiveInSeconds?: Record<UUID, number>;
  refreshToken?: RefreshToken;
  user?: User;
  userId?: UUID;
}

/**
 * @author Daniel DeGroff
 */
export interface IdentityProviderLink {
  data?: Record<string, any>;
  displayName?: string;
  identityProviderId?: UUID;
  identityProviderName?: string;
  identityProviderType?: IdentityProviderType;
  identityProviderUserId?: string;
  insertInstant?: number;
  lastLoginInstant?: number;
  tenantId?: UUID;
  token?: string;
  userId?: UUID;
}

/**
 * Twitch gaming login provider.
 *
 * @author Brett Pontarelli
 */
export interface TwitchIdentityProvider extends BaseIdentityProvider<TwitchApplicationConfiguration> {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
}

/**
 * The public, global view of a User. This object contains all global information about the user including birthdate, registration information
 * preferred languages, global attributes, etc.
 *
 * @author Seth Musselman
 */
export interface User extends SecureIdentity {
  active?: boolean;
  birthDate?: string;
  cleanSpeakId?: UUID;
  data?: Record<string, any>;
  email?: string;
  expiry?: number;
  firstName?: string;
  fullName?: string;
  imageUrl?: string;
  insertInstant?: number;
  lastName?: string;
  lastUpdateInstant?: number;
  memberships?: Array<GroupMember>;
  middleName?: string;
  mobilePhone?: string;
  parentEmail?: string;
  phoneNumber?: string;
  preferredLanguages?: Array<string>;
  registrations?: Array<UserRegistration>;
  tenantId?: UUID;
  timezone?: string;
  twoFactor?: UserTwoFactorConfiguration;
}

/**
 * A webhook call attempt log.
 *
 * @author Spencer Witt
 */
export interface WebhookAttemptLog {
  attemptResult?: WebhookAttemptResult;
  data?: Record<string, any>;
  endInstant?: number;
  id?: UUID;
  startInstant?: number;
  webhookCallResponse?: WebhookCallResponse;
  webhookEventLogId?: UUID;
  webhookId?: UUID;
}

/**
 * Search criteria for entity types.
 *
 * @author Brian Pontarelli
 */
export interface EntityTypeSearchCriteria extends BaseSearchCriteria {
  name?: string;
}

/**
 * Models the User Identity Provider Unlink Event.
 *
 * @author Rob Davis
 */
export interface UserIdentityProviderUnlinkEvent extends BaseUserEvent {
  identityProviderLink?: IdentityProviderLink;
}

/**
 * Contains extension output for requested extensions during a WebAuthn ceremony
 *
 * @author Spencer Witt
 */
export interface WebAuthnExtensionsClientOutputs {
  credProps?: CredentialPropertiesOutput;
}

/**
 * @author Daniel DeGroff
 */
export interface AuthenticatorConfiguration {
  algorithm?: TOTPAlgorithm;
  codeLength?: number;
  timeStep?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface TwoFactorEnableDisableSendRequest {
  email?: string;
  method?: string;
  methodId?: string;
  mobilePhone?: string;
}

/**
 * Tenant-level configuration for WebAuthn
 *
 * @author Spencer Witt
 */
export interface TenantWebAuthnConfiguration extends Enableable {
  bootstrapWorkflow?: TenantWebAuthnWorkflowConfiguration;
  debug?: boolean;
  reauthenticationWorkflow?: TenantWebAuthnWorkflowConfiguration;
  relyingPartyId?: string;
  relyingPartyName?: string;
}

/**
 * Models the Group Created Event.
 *
 * @author Daniel DeGroff
 */
export interface GroupCreateCompleteEvent extends BaseGroupEvent {
}

/**
 * Options to request extensions during credential registration
 *
 * @author Spencer Witt
 */
export interface WebAuthnRegistrationExtensionOptions {
  credProps?: boolean;
}

/**
 * The system configuration for Webhook Event Log data.
 *
 * @author Spencer Witt
 */
export interface WebhookEventLogConfiguration {
  delete?: DeleteConfiguration;
}

/**
 * Password Encryption Scheme Configuration
 *
 * @author Daniel DeGroff
 */
export interface PasswordEncryptionConfiguration {
  encryptionScheme?: string;
  encryptionSchemeFactor?: number;
  modifyEncryptionSchemeOnLogin?: boolean;
}

/**
 * Registration API request object.
 *
 * @author Brian Pontarelli
 */
export interface RegistrationRequest extends BaseEventRequest {
  disableDomainBlock?: boolean;
  generateAuthenticationToken?: boolean;
  registration?: UserRegistration;
  sendSetPasswordEmail?: boolean;
  skipRegistrationVerification?: boolean;
  skipVerification?: boolean;
  user?: User;
}

/**
 * The Application API request object.
 *
 * @author Brian Pontarelli
 */
export interface ApplicationRequest extends BaseEventRequest {
  application?: Application;
  role?: ApplicationRole;
  sourceApplicationId?: UUID;
}

/**
 * @author Daniel DeGroff
 */
export interface TwoFactorResponse {
  code?: string;
  recoveryCodes?: Array<string>;
}

export interface MultiFactorAuthenticatorMethod extends Enableable {
  algorithm?: TOTPAlgorithm;
  codeLength?: number;
  timeStep?: number;
}

export interface SAMLv2Logout {
  behavior?: SAMLLogoutBehavior;
  defaultVerificationKeyId?: UUID;
  keyId?: UUID;
  requireSignedRequests?: boolean;
  singleLogout?: SAMLv2SingleLogout;
  xmlSignatureC14nMethod?: CanonicalizationMethod;
}

/**
 * @author Daniel DeGroff
 */
export interface RefreshTokenSlidingWindowConfiguration {
  maximumTimeToLiveInMinutes?: number;
}

/**
 * Search criteria for Identity Providers.
 *
 * @author Spencer Witt
 */
export interface IdentityProviderSearchCriteria extends BaseSearchCriteria {
  applicationId?: UUID;
  name?: string;
  type?: IdentityProviderType;
}

/**
 * @author Daniel DeGroff
 */
export interface JWTVendRequest {
  claims?: Record<string, any>;
  keyId?: UUID;
  timeToLiveInSeconds?: number;
}

/**
 * User API delete request object for a single user.
 *
 * @author Brian Pontarelli
 */
export interface UserDeleteSingleRequest extends BaseEventRequest {
  hardDelete?: boolean;
}

/**
 * Search request for Groups.
 *
 * @author Daniel DeGroff
 */
export interface GroupSearchRequest {
  search?: GroupSearchCriteria;
}

/**
 * The <i>authenticator's</i> response for the authentication ceremony in its encoded format
 *
 * @author Spencer Witt
 */
export interface WebAuthnAuthenticatorAuthenticationResponse {
  authenticatorData?: string;
  clientDataJSON?: string;
  signature?: string;
  userHandle?: string;
}

/**
 * Type for webhook headers.
 *
 * @author Brian Pontarelli
 */
export interface HTTPHeaders extends Record<string, string> {
}

/**
 * Epic gaming login provider.
 *
 * @author Brett Pontarelli
 */
export interface EpicGamesIdentityProvider extends BaseIdentityProvider<EpicGamesApplicationConfiguration> {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface Form {
  data?: Record<string, any>;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  name?: string;
  steps?: Array<FormStep>;
  type?: FormType;
}

/**
 * Request to authenticate with WebAuthn
 *
 * @author Spencer Witt
 */
export interface WebAuthnPublicKeyAuthenticationRequest {
  clientExtensionResults?: WebAuthnExtensionsClientOutputs;
  id?: string;
  response?: WebAuthnAuthenticatorAuthenticationResponse;
  rpId?: string;
  type?: string;
}

/**
 * Available JSON Web Algorithms (JWA) as described in RFC 7518 available for this JWT implementation.
 *
 * @author Daniel DeGroff
 */
export enum Algorithm {
  ES256 = "ES256",
  ES384 = "ES384",
  ES512 = "ES512",
  HS256 = "HS256",
  HS384 = "HS384",
  HS512 = "HS512",
  PS256 = "PS256",
  PS384 = "PS384",
  PS512 = "PS512",
  RS256 = "RS256",
  RS384 = "RS384",
  RS512 = "RS512",
  none = "none"
}

/**
 * Search request for Identity Providers
 *
 * @author Spencer Witt
 */
export interface IdentityProviderSearchRequest {
  search?: IdentityProviderSearchCriteria;
}

/**
 * The use type of a key.
 *
 * @author Daniel DeGroff
 */
export enum KeyUse {
  SignOnly = "SignOnly",
  SignAndVerify = "SignAndVerify",
  VerifyOnly = "VerifyOnly"
}

export enum FamilyRole {
  Child = "Child",
  Teen = "Teen",
  Adult = "Adult"
}

/**
 * Entity API request object.
 *
 * @author Brian Pontarelli
 */
export interface EntityRequest {
  entity?: Entity;
}

/**
 * Response for the system configuration API.
 *
 * @author Brian Pontarelli
 */
export interface SystemConfigurationResponse {
  systemConfiguration?: SystemConfiguration;
}

export interface ActionData {
  actioneeUserId?: UUID;
  actionerUserId?: UUID;
  applicationIds?: Array<UUID>;
  comment?: string;
  emailUser?: boolean;
  expiry?: number;
  notifyUser?: boolean;
  option?: string;
  reasonId?: UUID;
  userActionId?: UUID;
}

export interface APIKeyMetaData {
  attributes?: Record<string, string>;
}

/**
 * @author Daniel DeGroff
 */
export interface TenantRateLimitConfiguration {
  failedLogin?: RateLimitedRequestConfiguration;
  forgotPassword?: RateLimitedRequestConfiguration;
  sendEmailVerification?: RateLimitedRequestConfiguration;
  sendPasswordless?: RateLimitedRequestConfiguration;
  sendRegistrationVerification?: RateLimitedRequestConfiguration;
  sendTwoFactor?: RateLimitedRequestConfiguration;
}

/**
 * @author Daniel DeGroff
 */
export interface BaseLoginRequest extends BaseEventRequest {
  applicationId?: UUID;
  ipAddress?: string;
  metaData?: MetaData;
  newDevice?: boolean;
  noJWT?: boolean;
}

/**
 * Nintendo gaming login provider.
 *
 * @author Brett Pontarelli
 */
export interface NintendoIdentityProvider extends BaseIdentityProvider<NintendoApplicationConfiguration> {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  emailClaim?: string;
  scope?: string;
  uniqueIdClaim?: string;
  usernameClaim?: string;
}

/**
 * Models the User Update Event once it is completed. This cannot be transactional.
 *
 * @author Daniel DeGroff
 */
export interface UserUpdateCompleteEvent extends BaseUserEvent {
  original?: User;
}

/**
 * A marker interface indicating this event is an event that can supply a linked object Id.
 *
 * @author Spencer Witt
 */
export interface ObjectIdentifiable {
}

/**
 * The transaction types for Webhooks and other event systems within FusionAuth.
 *
 * @author Brian Pontarelli
 */
export enum TransactionType {
  None = "None",
  Any = "Any",
  SimpleMajority = "SimpleMajority",
  SuperMajority = "SuperMajority",
  AbsoluteMajority = "AbsoluteMajority"
}

/**
 * Models the User Login Success Event.
 *
 * @author Daniel DeGroff
 */
export interface UserLoginSuccessEvent extends BaseUserEvent {
  applicationId?: UUID;
  authenticationType?: string;
  connectorId?: UUID;
  identityProviderId?: UUID;
  identityProviderName?: string;
  ipAddress?: string;
}

/**
 * Group Member Delete Request
 *
 * @author Daniel DeGroff
 */
export interface MemberDeleteRequest {
  memberIds?: Array<UUID>;
  members?: Record<UUID, Array<UUID>>;
}

/**
 * Registration API request object.
 *
 * @author Brian Pontarelli
 */
export interface RegistrationResponse {
  refreshToken?: string;
  refreshTokenId?: UUID;
  registration?: UserRegistration;
  registrationVerificationId?: string;
  registrationVerificationOneTimeCode?: string;
  token?: string;
  tokenExpirationInstant?: number;
  user?: User;
}

/**
 * Models the User Update Registration Event.
 * <p>
 * This is different than user.registration.update in that it is sent after this event completes, this cannot be transactional.
 *
 * @author Daniel DeGroff
 */
export interface UserRegistrationUpdateCompleteEvent extends BaseUserEvent {
  applicationId?: UUID;
  original?: UserRegistration;
  registration?: UserRegistration;
}

/**
 * Search response for Themes
 *
 * @author Mark Manes
 */
export interface ThemeSearchResponse {
  themes?: Array<Theme>;
  total?: number;
}

/**
 * Used to express whether the Relying Party requires <a href="https://www.w3.org/TR/webauthn-2/#user-verification">user verification</a> for the
 * current operation.
 *
 * @author Spencer Witt
 */
export enum UserVerificationRequirement {
  required = "required",
  preferred = "preferred",
  discouraged = "discouraged"
}

/**
 * @author Trevor Smith
 */
export interface DeviceResponse {
  device_code?: string;
  expires_in?: number;
  interval?: number;
  user_code?: string;
  verification_uri?: string;
  verification_uri_complete?: string;
}

/**
 * Search criteria for Email templates
 *
 * @author Mark Manes
 */
export interface EmailTemplateSearchCriteria extends BaseSearchCriteria {
  name?: string;
}

export interface APIKeyPermissions {
  endpoints?: Record<string, Array<string>>;
}

/**
 * @author Brian Pontarelli
 */
export interface BaseElasticSearchCriteria extends BaseSearchCriteria {
  accurateTotal?: boolean;
  ids?: Array<UUID>;
  nextResults?: string;
  query?: string;
  queryString?: string;
  sortFields?: Array<SortField>;
}

/**
 * Search request for IP ACLs .
 *
 * @author Brett Guy
 */
export interface IPAccessControlListSearchRequest {
  search?: IPAccessControlListSearchCriteria;
}

/**
 * The Application Scope API request object.
 *
 * @author Spencer Witt
 */
export interface ApplicationOAuthScopeRequest {
  scope?: ApplicationOAuthScope;
}

export interface LoginConfiguration {
  allowTokenRefresh?: boolean;
  generateRefreshTokens?: boolean;
  requireAuthentication?: boolean;
}

/**
 * Models the Group Member Add Event.
 *
 * @author Daniel DeGroff
 */
export interface GroupMemberAddEvent extends BaseGroupEvent {
  members?: Array<GroupMember>;
}

/**
 * Key API request object.
 *
 * @author Daniel DeGroff
 */
export interface KeyRequest {
  key?: Key;
}

/**
 * Event log response.
 *
 * @author Brian Pontarelli
 */
export interface EventLogSearchResponse {
  eventLogs?: Array<EventLog>;
  total?: number;
}

export interface TwoFactorTrust {
  applicationId?: UUID;
  expiration?: number;
  startInstant?: number;
}

/**
 * Application-level configuration for WebAuthn
 *
 * @author Daniel DeGroff
 */
export interface ApplicationWebAuthnConfiguration extends Enableable {
  bootstrapWorkflow?: ApplicationWebAuthnWorkflowConfiguration;
  reauthenticationWorkflow?: ApplicationWebAuthnWorkflowConfiguration;
}

/**
 * Models a generic connector.
 *
 * @author Trevor Smith
 */
export interface GenericConnectorConfiguration extends BaseConnectorConfiguration {
  authenticationURL?: string;
  connectTimeout?: number;
  headers?: HTTPHeaders;
  httpAuthenticationPassword?: string;
  httpAuthenticationUsername?: string;
  readTimeout?: number;
  sslCertificateKeyId?: UUID;
}

/**
 * Base class for all {@link Group} and {@link GroupMember} events.
 *
 * @author Spencer Witt
 */
export interface BaseGroupEvent extends BaseEvent {
  group?: Group;
}

/**
 * @author Daniel DeGroff
 */
export interface MessengerTransport {
}

/**
 * @author Daniel DeGroff
 */
export interface IdentityProviderTenantConfiguration {
  data?: Record<string, any>;
  limitUserLinkCount?: IdentityProviderLimitUserLinkingPolicy;
}

/**
 * @author Brian Pontarelli
 */
export interface AuditLogSearchCriteria extends BaseSearchCriteria {
  end?: number;
  message?: string;
  newValue?: string;
  oldValue?: string;
  reason?: string;
  start?: number;
  user?: string;
}

/**
 * Refresh Token Import request.
 *
 * @author Brett Guy
 */
export interface RefreshTokenImportRequest {
  refreshTokens?: Array<RefreshToken>;
  validateDbConstraints?: boolean;
}

/**
 * WebAuthn Credential API response
 *
 * @author Spencer Witt
 */
export interface WebAuthnCredentialResponse {
  credential?: WebAuthnCredential;
  credentials?: Array<WebAuthnCredential>;
}

/**
 * Webhook event log search response.
 *
 * @author Spencer Witt
 */
export interface WebhookEventLogSearchResponse {
  total?: number;
  webhookEventLogs?: Array<WebhookEventLog>;
}

/**
 * @author Trevor Smith
 */
export interface ConnectorResponse {
  connector?: BaseConnectorConfiguration;
  connectors?: Array<BaseConnectorConfiguration>;
}

/**
 * Models a User consent.
 *
 * @author Daniel DeGroff
 */
export interface UserConsent {
  consent?: Consent;
  consentId?: UUID;
  data?: Record<string, any>;
  giverUserId?: UUID;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  status?: ConsentStatus;
  userId?: UUID;
  values?: Array<string>;
}

/**
 * Steam API modes.
 *
 * @author Daniel DeGroff
 */
export enum SteamAPIMode {
  Public = "Public",
  Partner = "Partner"
}

/**
 * Request for the Logout API that can be used as an alternative to URL parameters.
 *
 * @author Brian Pontarelli
 */
export interface LogoutRequest extends BaseEventRequest {
  global?: boolean;
  refreshToken?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface LookupResponse {
  identityProvider?: IdentityProviderDetails;
}

/**
 * Models a family grouping of users.
 *
 * @author Brian Pontarelli
 */
export interface Family {
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  members?: Array<FamilyMember>;
}

export interface LambdaConfiguration {
  reconcileId?: UUID;
}

/**
 * Search response for entity types.
 *
 * @author Brian Pontarelli
 */
export interface EntityTypeSearchResponse {
  entityTypes?: Array<EntityType>;
  total?: number;
}

/**
 * @author Lyle Schemmerling
 */
export interface BaseSAMLv2IdentityProvider<D extends BaseIdentityProviderApplicationConfiguration> extends BaseIdentityProvider<D> {
  assertionDecryptionConfiguration?: SAMLv2AssertionDecryptionConfiguration;
  emailClaim?: string;
  keyId?: UUID;
  uniqueIdClaim?: string;
  useNameIdForEmail?: boolean;
  usernameClaim?: string;
}

export interface IdentityInfo {
  type?: string;
  value?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface LinkedInApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  buttonText?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
}

/**
 * @author Brian Pontarelli
 */
export interface PreviewRequest {
  emailTemplate?: EmailTemplate;
  locale?: string;
}

/**
 * Request for the Refresh Token API to revoke a refresh token rather than using the URL parameters.
 *
 * @author Brian Pontarelli
 */
export interface RefreshTokenRevokeRequest extends BaseEventRequest {
  applicationId?: UUID;
  token?: string;
  userId?: UUID;
}

/**
 * @author Trevor Smith
 */
export enum ChangePasswordReason {
  Administrative = "Administrative",
  Breached = "Breached",
  Expired = "Expired",
  Validation = "Validation"
}

/**
 * Something that can be enabled and thus also disabled.
 *
 * @author Daniel DeGroff
 */
export interface Enableable {
  enabled?: boolean;
}

/**
 * Search request for email templates
 *
 * @author Mark Manes
 */
export interface EmailTemplateSearchRequest {
  search?: EmailTemplateSearchCriteria;
}

export enum EmailSecurityType {
  NONE = "NONE",
  SSL = "SSL",
  TLS = "TLS"
}

/**
 * Provides the <i>authenticator</i> with the data it needs to generate an assertion.
 *
 * @author Spencer Witt
 */
export interface PublicKeyCredentialRequestOptions {
  allowCredentials?: Array<PublicKeyCredentialDescriptor>;
  challenge?: string;
  rpId?: string;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
}

/**
 * Supply additional information about the Relying Party when creating a new credential
 *
 * @author Spencer Witt
 */
export interface PublicKeyCredentialRelyingPartyEntity extends PublicKeyCredentialEntity {
  id?: string;
}

/**
 * API response for User consent.
 *
 * @author Daniel DeGroff
 */
export interface UserConsentResponse {
  userConsent?: UserConsent;
  userConsents?: Array<UserConsent>;
}

/**
 * @author Daniel DeGroff
 */
export interface BaseIdentityProviderApplicationConfiguration extends Enableable {
  createRegistration?: boolean;
  data?: Record<string, any>;
}

/**
 * API response for refreshing a JWT with a Refresh Token.
 * <p>
 * Using a different response object from RefreshTokenResponse because the retrieve response will return an object for refreshToken, and this is a
 * string.
 *
 * @author Daniel DeGroff
 */
export interface JWTRefreshResponse {
  refreshToken?: string;
  refreshTokenId?: UUID;
  token?: string;
}

/**
 * @author Brian Pontarelli
 */
export interface Count {
  count?: number;
  interval?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface AuditLogExportRequest extends BaseExportRequest {
  criteria?: AuditLogSearchCriteria;
}

/**
 * Defines an error.
 *
 * @author Brian Pontarelli
 */
export interface Error {
  code?: string;
  data?: Record<string, any>;
  message?: string;
}

/**
 * API request to import an existing WebAuthn credential(s)
 *
 * @author Spencer Witt
 */
export interface WebAuthnCredentialImportRequest {
  credentials?: Array<WebAuthnCredential>;
  validateDbConstraints?: boolean;
}

/**
 * @author Brian Pontarelli
 */
export enum ExpiryUnit {
  MINUTES = "MINUTES",
  HOURS = "HOURS",
  DAYS = "DAYS",
  WEEKS = "WEEKS",
  MONTHS = "MONTHS",
  YEARS = "YEARS"
}

/**
 * @author Brett Guy
 */
export enum MessengerType {
  Generic = "Generic",
  Kafka = "Kafka",
  Twilio = "Twilio"
}

/**
 * An expandable API response.
 *
 * @author Daniel DeGroff
 */
export interface ExpandableResponse {
  expandable?: Array<string>;
}

/**
 * Search request for Themes.
 *
 * @author Mark Manes
 */
export interface ThemeSearchRequest {
  search?: ThemeSearchCriteria;
}

/**
 * @author Daniel DeGroff
 */
export interface PasswordValidationRulesResponse {
  passwordValidationRules?: PasswordValidationRules;
}

/**
 * API request to start a WebAuthn authentication ceremony
 *
 * @author Spencer Witt
 */
export interface WebAuthnStartRequest {
  applicationId?: UUID;
  credentialId?: UUID;
  loginId?: string;
  loginIdTypes?: Array<string>;
  state?: Record<string, any>;
  userId?: UUID;
  workflow?: WebAuthnWorkflow;
}

/**
 * @author Brady Wied
 */
export interface VerifyStartResponse {
  oneTimeCode?: string;
  verificationId?: string;
}

/**
 * A raw login record response
 *
 * @author Daniel DeGroff
 */
export interface LoginRecordSearchResponse {
  logins?: Array<DisplayableRawLogin>;
  total?: number;
}

/**
 * Response for the registration report.
 *
 * @author Brian Pontarelli
 */
export interface RegistrationReportResponse {
  hourlyCounts?: Array<Count>;
  total?: number;
}

/**
 * @author Brett Guy
 */
export interface IPAccessControlListSearchResponse {
  ipAccessControlLists?: Array<IPAccessControlList>;
  total?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface TwoFactorStatusResponse {
  trusts?: Array<TwoFactorTrust>;
  twoFactorTrustId?: string;
}

/**
 * Consent search response
 *
 * @author Spencer Witt
 */
export interface ConsentSearchResponse {
  consents?: Array<Consent>;
  total?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface RefreshResponse {
}

/**
 * Stores an message template used to distribute messages;
 *
 * @author Michael Sleevi
 */
export interface MessageTemplate {
  data?: Record<string, any>;
  id?: UUID;
  insertInstant?: number;
  lastUpdateInstant?: number;
  name?: string;
  type?: MessageType;
}

/**
 * Models the JWT public key Refresh Token Revoke Event. This event might be for a single
 * token, a user or an entire application.
 *
 * @author Brian Pontarelli
 */
export interface JWTPublicKeyUpdateEvent extends BaseEvent {
  applicationIds?: Array<UUID>;
}

/**
 * @author Daniel DeGroff
 */
export interface DeviceUserCodeResponse {
  client_id?: string;
  deviceInfo?: DeviceInfo;
  expires_in?: number;
  pendingIdPLink?: PendingIdPLink;
  scope?: string;
  tenantId?: UUID;
  user_code?: string;
}

/**
 * Models an entity type that has a specific set of permissions. These are global objects and can be used across tenants.
 *
 * @author Brian Pontarelli
 */
export interface EntityType {
  data?: Record<string, any>;
  id?: UUID;
  insertInstant?: number;
  jwtConfiguration?: EntityJWTConfiguration;
  lastUpdateInstant?: number;
  name?: string;
  permissions?: Array<EntityTypePermission>;
}

/**
 * @author Daniel DeGroff
 */
export enum IdentityProviderType {
  Apple = "Apple",
  EpicGames = "EpicGames",
  ExternalJWT = "ExternalJWT",
  Facebook = "Facebook",
  Google = "Google",
  HYPR = "HYPR",
  LinkedIn = "LinkedIn",
  Nintendo = "Nintendo",
  OpenIDConnect = "OpenIDConnect",
  SAMLv2 = "SAMLv2",
  SAMLv2IdPInitiated = "SAMLv2IdPInitiated",
  SonyPSN = "SonyPSN",
  Steam = "Steam",
  Twitch = "Twitch",
  Twitter = "Twitter",
  Xbox = "Xbox"
}

/**
 * @author Seth Musselman
 */
export interface PreviewResponse {
  email?: Email;
  errors?: Errors;
}

/**
 * Event to indicate kickstart has been successfully completed.
 *
 * @author Daniel DeGroff
 */
export interface KickstartSuccessEvent extends BaseEvent {
  instanceId?: UUID;
}

/**
 * @author Daniel DeGroff
 */
export enum SystemTrustedProxyConfigurationPolicy {
  All = "All",
  OnlyConfigured = "OnlyConfigured"
}

/**
 * @author Daniel DeGroff
 */
export interface TenantUsernameConfiguration {
  unique?: UniqueUsernameConfiguration;
}

/**
 * Interface for all identity providers that are passwordless and do not accept a password.
 */
export interface PasswordlessIdentityProvider {
}

/**
 * @author Daniel DeGroff
 */
export interface PasswordBreachDetection extends Enableable {
  matchMode?: BreachMatchMode;
  notifyUserEmailTemplateId?: UUID;
  onLogin?: BreachAction;
}

/**
 * Base class for all FusionAuth events.
 *
 * @author Brian Pontarelli
 */
export interface BaseEvent {
  createInstant?: number;
  id?: UUID;
  info?: EventInfo;
  tenantId?: UUID;
  type?: EventType;
}

/**
 * @author Daniel DeGroff
 */
export interface EmailHeader {
  name?: string;
  value?: string;
}

/**
 * The FormField API request object.
 *
 * @author Brett Guy
 */
export interface FormFieldRequest {
  field?: FormField;
  fields?: Array<FormField>;
}

/**
 * @author Daniel DeGroff
 */
export interface TwoFactorMethod {
  authenticator?: AuthenticatorConfiguration;
  email?: string;
  id?: string;
  lastUsed?: boolean;
  method?: string;
  mobilePhone?: string;
  secret?: string;
}

/**
 * Models the event types that FusionAuth produces.
 *
 * @author Brian Pontarelli
 */
export enum EventType {
  JWTPublicKeyUpdate = "jwt.public-key.update",
  JWTRefreshTokenRevoke = "jwt.refresh-token.revoke",
  JWTRefresh = "jwt.refresh",
  AuditLogCreate = "audit-log.create",
  EventLogCreate = "event-log.create",
  KickstartSuccess = "kickstart.success",
  GroupCreate = "group.create",
  GroupCreateComplete = "group.create.complete",
  GroupDelete = "group.delete",
  GroupDeleteComplete = "group.delete.complete",
  GroupMemberAdd = "group.member.add",
  GroupMemberAddComplete = "group.member.add.complete",
  GroupMemberRemove = "group.member.remove",
  GroupMemberRemoveComplete = "group.member.remove.complete",
  GroupMemberUpdate = "group.member.update",
  GroupMemberUpdateComplete = "group.member.update.complete",
  GroupUpdate = "group.update",
  GroupUpdateComplete = "group.update.complete",
  UserAction = "user.action",
  UserBulkCreate = "user.bulk.create",
  UserCreate = "user.create",
  UserCreateComplete = "user.create.complete",
  UserDeactivate = "user.deactivate",
  UserDelete = "user.delete",
  UserDeleteComplete = "user.delete.complete",
  UserEmailUpdate = "user.email.update",
  UserEmailVerified = "user.email.verified",
  UserIdentityProviderLink = "user.identity-provider.link",
  UserIdentityProviderUnlink = "user.identity-provider.unlink",
  UserLoginIdDuplicateOnCreate = "user.loginId.duplicate.create",
  UserLoginIdDuplicateOnUpdate = "user.loginId.duplicate.update",
  UserLoginFailed = "user.login.failed",
  UserLoginNewDevice = "user.login.new-device",
  UserLoginSuccess = "user.login.success",
  UserLoginSuspicious = "user.login.suspicious",
  UserPasswordBreach = "user.password.breach",
  UserPasswordResetSend = "user.password.reset.send",
  UserPasswordResetStart = "user.password.reset.start",
  UserPasswordResetSuccess = "user.password.reset.success",
  UserPasswordUpdate = "user.password.update",
  UserReactivate = "user.reactivate",
  UserRegistrationCreate = "user.registration.create",
  UserRegistrationCreateComplete = "user.registration.create.complete",
  UserRegistrationDelete = "user.registration.delete",
  UserRegistrationDeleteComplete = "user.registration.delete.complete",
  UserRegistrationUpdate = "user.registration.update",
  UserRegistrationUpdateComplete = "user.registration.update.complete",
  UserRegistrationVerified = "user.registration.verified",
  UserTwoFactorMethodAdd = "user.two-factor.method.add",
  UserTwoFactorMethodRemove = "user.two-factor.method.remove",
  UserUpdate = "user.update",
  UserUpdateComplete = "user.update.complete",
  Test = "test",
  IdentityVerified = "identity.verified"
}

/**
 * Tenant search response
 *
 * @author Mark Manes
 */
export interface TenantSearchResponse {
  tenants?: Array<Tenant>;
  total?: number;
}

/**
 * Search API request.
 *
 * @author Brian Pontarelli
 */
export interface SearchRequest extends ExpandableRequest {
  search?: UserSearchCriteria;
}

/**
 * Lambda search response
 *
 * @author Mark Manes
 */
export interface LambdaSearchResponse {
  lambdas?: Array<Lambda>;
  total?: number;
}

export interface Templates {
  accountEdit?: string;
  accountIndex?: string;
  accountTwoFactorDisable?: string;
  accountTwoFactorEnable?: string;
  accountTwoFactorIndex?: string;
  accountWebAuthnAdd?: string;
  accountWebAuthnDelete?: string;
  accountWebAuthnIndex?: string;
  confirmationRequired?: string;
  emailComplete?: string;
  emailSend?: string;
  emailSent?: string;
  emailVerificationRequired?: string;
  emailVerify?: string;
  helpers?: string;
  index?: string;
  oauth2Authorize?: string;
  oauth2AuthorizedNotRegistered?: string;
  oauth2ChildRegistrationNotAllowed?: string;
  oauth2ChildRegistrationNotAllowedComplete?: string;
  oauth2CompleteRegistration?: string;
  oauth2Consent?: string;
  oauth2Device?: string;
  oauth2DeviceComplete?: string;
  oauth2Error?: string;
  oauth2Logout?: string;
  oauth2Passwordless?: string;
  oauth2Register?: string;
  oauth2StartIdPLink?: string;
  oauth2TwoFactor?: string;
  oauth2TwoFactorEnable?: string;
  oauth2TwoFactorEnableComplete?: string;
  oauth2TwoFactorMethods?: string;
  oauth2Wait?: string;
  oauth2WebAuthn?: string;
  oauth2WebAuthnReauth?: string;
  oauth2WebAuthnReauthEnable?: string;
  passwordChange?: string;
  passwordComplete?: string;
  passwordForgot?: string;
  passwordSent?: string;
  registrationComplete?: string;
  registrationSend?: string;
  registrationSent?: string;
  registrationVerificationRequired?: string;
  registrationVerify?: string;
  samlv2Logout?: string;
  unauthorized?: string;
}

/**
 * Search request for Lambdas
 *
 * @author Mark Manes
 */
export interface LambdaSearchRequest {
  search?: LambdaSearchCriteria;
}

/**
 * Models the User Password Reset Send Event.
 *
 * @author Daniel DeGroff
 */
export interface UserPasswordResetSendEvent extends BaseUserEvent {
}

/**
 * The Integration Request
 *
 * @author Daniel DeGroff
 */
export interface IntegrationRequest {
  integrations?: Integrations;
}

export enum TOTPAlgorithm {
  HmacSHA1 = "HmacSHA1",
  HmacSHA256 = "HmacSHA256",
  HmacSHA512 = "HmacSHA512"
}

export enum LDAPSecurityMethod {
  None = "None",
  LDAPS = "LDAPS",
  StartTLS = "StartTLS"
}

/**
 * User API delete request object.
 *
 * @author Daniel DeGroff
 */
export interface UserDeleteRequest extends BaseEventRequest {
  dryRun?: boolean;
  hardDelete?: boolean;
  limit?: number;
  query?: string;
  queryString?: string;
  userIds?: Array<UUID>;
}

/**
 * @author Daniel DeGroff
 */
export interface IdentityProviderStartLoginRequest extends BaseLoginRequest {
  data?: Record<string, string>;
  identityProviderId?: UUID;
  loginId?: string;
  loginIdTypes?: Array<string>;
  state?: Record<string, any>;
}

export enum UniqueUsernameStrategy {
  Always = "Always",
  OnCollision = "OnCollision"
}

/**
 * @author Daniel DeGroff
 */
export interface ExternalJWTApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
}

/**
 * @author Brian Pontarelli
 */
export interface LoginResponse {
  actions?: Array<LoginPreventedResponse>;
  changePasswordId?: string;
  changePasswordReason?: ChangePasswordReason;
  configurableMethods?: Array<string>;
  emailVerificationId?: string;
  methods?: Array<TwoFactorMethod>;
  pendingIdPLinkId?: string;
  refreshToken?: string;
  refreshTokenId?: UUID;
  registrationVerificationId?: string;
  state?: Record<string, any>;
  threatsDetected?: Array<AuthenticationThreats>;
  token?: string;
  tokenExpirationInstant?: number;
  trustToken?: string;
  twoFactorId?: string;
  twoFactorTrustId?: string;
  user?: User;
}

/**
 * The Application Scope API response.
 *
 * @author Spencer Witt
 */
export interface ApplicationOAuthScopeResponse {
  scope?: ApplicationOAuthScope;
}

/**
 * Search API response.
 *
 * @author Brian Pontarelli
 */
export interface SearchResponse extends ExpandableResponse {
  nextResults?: string;
  total?: number;
  users?: Array<User>;
}

/**
 * @author Daniel DeGroff
 */
export interface SendResponse {
  anonymousResults?: Record<string, EmailTemplateErrors>;
  results?: Record<UUID, EmailTemplateErrors>;
}

/**
 * @author Daniel DeGroff
 */
export interface SystemLogsExportRequest extends BaseExportRequest {
  includeArchived?: boolean;
  lastNBytes?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface ReactorMetricsResponse {
  metrics?: ReactorMetrics;
}

/**
 * Location information. Useful for IP addresses and other displayable data objects.
 *
 * @author Brian Pontarelli
 */
export interface Location {
  city?: string;
  country?: string;
  displayString?: string;
  latitude?: number;
  longitude?: number;
  region?: string;
  zipcode?: string;
}

/**
 * @author Brett Guy
 */
export interface TenantAccessControlConfiguration {
  uiIPAccessControlListId?: UUID;
}

/**
 * @author Daniel DeGroff
 */
export interface TenantResponse {
  tenant?: Tenant;
  tenants?: Array<Tenant>;
}

/**
 * Configuration for encrypted assertions when acting as SAML Service Provider
 *
 * @author Jaret Hendrickson
 */
export interface SAMLv2AssertionDecryptionConfiguration extends Enableable {
  keyTransportDecryptionKeyId?: UUID;
}

/**
 * @author Brett Guy
 */
export interface TwilioMessengerConfiguration extends BaseMessengerConfiguration {
  accountSID?: string;
  authToken?: string;
  fromPhoneNumber?: string;
  messagingServiceSid?: string;
  url?: string;
}

/**
 * @author Daniel DeGroff
 */
export enum VerificationStrategy {
  ClickableLink = "ClickableLink",
  FormField = "FormField"
}

/**
 * Model a user event when a two-factor method has been removed.
 *
 * @author Daniel DeGroff
 */
export interface UserTwoFactorMethodAddEvent extends BaseUserEvent {
  method?: TwoFactorMethod;
}

/**
 * API request to start a WebAuthn registration ceremony
 *
 * @author Spencer Witt
 */
export interface WebAuthnRegisterStartRequest {
  displayName?: string;
  name?: string;
  userAgent?: string;
  userId?: UUID;
  workflow?: WebAuthnWorkflow;
}

/**
 * @author Daniel DeGroff
 */
export interface MaximumPasswordAge extends Enableable {
  days?: number;
}

/**
 * @author Brett Guy
 */
export interface IPAccessControlEntry {
  action?: IPAccessControlEntryAction;
  endIPAddress?: string;
  startIPAddress?: string;
}

/**
 * Models the Group Member Update Event.
 *
 * @author Daniel DeGroff
 */
export interface GroupMemberUpdateEvent extends BaseGroupEvent {
  members?: Array<GroupMember>;
}

/**
 * Models the User Deactivate Event.
 *
 * @author Brian Pontarelli
 */
export interface UserDeactivateEvent extends BaseUserEvent {
}

/**
 * Search criteria for the webhook event log.
 *
 * @author Spencer Witt
 */
export interface WebhookEventLogSearchCriteria extends BaseSearchCriteria {
  end?: number;
  event?: string;
  eventResult?: WebhookEventResult;
  eventType?: EventType;
  start?: number;
}

/**
 * Group Member Response
 *
 * @author Daniel DeGroff
 */
export interface MemberResponse {
  members?: Record<UUID, Array<GroupMember>>;
}

/**
 * Webhook event log search request.
 *
 * @author Spencer Witt
 */
export interface WebhookEventLogSearchRequest {
  search?: WebhookEventLogSearchCriteria;
}

/**
 * API response for completing WebAuthn assertion
 *
 * @author Spencer Witt
 */
export interface WebAuthnAssertResponse {
  credential?: WebAuthnCredential;
}

/**
 * @author Daniel DeGroff
 */
export enum SecureGeneratorType {
  randomDigits = "randomDigits",
  randomBytes = "randomBytes",
  randomAlpha = "randomAlpha",
  randomAlphaNumeric = "randomAlphaNumeric"
}

/**
 * XML canonicalization method enumeration. This is used for the IdP and SP side of FusionAuth SAML.
 *
 * @author Brian Pontarelli
 */
export enum CanonicalizationMethod {
  exclusive = "exclusive",
  exclusive_with_comments = "exclusive_with_comments",
  inclusive = "inclusive",
  inclusive_with_comments = "inclusive_with_comments"
}

/**
 * Search criteria for themes
 *
 * @author Mark Manes
 */
export interface ThemeSearchCriteria extends BaseSearchCriteria {
  name?: string;
  type?: ThemeType;
}

/**
 * @author Daniel DeGroff
 */
export enum RateLimitedRequestType {
  FailedLogin = "FailedLogin",
  ForgotPassword = "ForgotPassword",
  SendEmailVerification = "SendEmailVerification",
  SendPasswordless = "SendPasswordless",
  SendRegistrationVerification = "SendRegistrationVerification",
  SendTwoFactor = "SendTwoFactor"
}

/**
 * @author Daniel DeGroff
 */
export interface LoginHintConfiguration extends Enableable {
  parameterName?: string;
}

/**
 * Controls the policy for whether OAuth workflows will more strictly adhere to the OAuth and OIDC specification
 * or run in backwards compatibility mode.
 *
 * @author David Charles
 */
export enum OAuthScopeHandlingPolicy {
  Compatibility = "Compatibility",
  Strict = "Strict"
}

/**
 * API request for managing families and members.
 *
 * @author Brian Pontarelli
 */
export interface FamilyRequest {
  familyMember?: FamilyMember;
}

/**
 * @author Matthew Altman
 */
export enum LogoutBehavior {
  RedirectOnly = "RedirectOnly",
  AllApplications = "AllApplications"
}

/**
 * The response from the total report. This report stores the total numbers for each application.
 *
 * @author Brian Pontarelli
 */
export interface TotalsReportResponse {
  applicationTotals?: Record<UUID, Totals>;
  globalRegistrations?: number;
  totalGlobalRegistrations?: number;
}

/**
 * A historical state of a user log event. Since events can be modified, this stores the historical state.
 *
 * @author Brian Pontarelli
 */
export interface LogHistory {
  historyItems?: Array<HistoryItem>;
}

/**
 * Models the User Create Registration Event.
 *
 * @author Daniel DeGroff
 */
export interface UserRegistrationCreateEvent extends BaseUserEvent {
  applicationId?: UUID;
  registration?: UserRegistration;
}

/**
 * Search request for Applications
 *
 * @author Spencer Witt
 */
export interface ApplicationSearchRequest extends ExpandableRequest {
  search?: ApplicationSearchCriteria;
}

/**
 * A webhook call response.
 *
 * @author Spencer Witt
 */
export interface WebhookCallResponse {
  exception?: string;
  statusCode?: number;
  url?: string;
}

/**
 * API request for User consent types.
 *
 * @author Daniel DeGroff
 */
export interface ConsentRequest {
  consent?: Consent;
}

/**
 * @author Daniel DeGroff
 */
export interface FacebookApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  appId?: string;
  buttonText?: string;
  client_secret?: string;
  fields?: string;
  loginMethod?: IdentityProviderLoginMethod;
  permissions?: string;
}

/**
 * @author Johnathon Wood
 */
export enum Oauth2AuthorizedURLValidationPolicy {
  AllowWildcards = "AllowWildcards",
  ExactMatch = "ExactMatch"
}

/**
 * Models content user action options.
 *
 * @author Brian Pontarelli
 */
export interface UserActionOption {
  localizedNames?: LocalizedStrings;
  name?: string;
}

/**
 * Identifies the WebAuthn workflow. This will affect the parameters used for credential creation
 * and request based on the Tenant configuration.
 *
 * @author Spencer Witt
 */
export enum WebAuthnWorkflow {
  bootstrap = "bootstrap",
  general = "general",
  reauthentication = "reauthentication"
}

/**
 * An action that can be executed on a user (discipline or reward potentially).
 *
 * @author Brian Pontarelli
 */
export interface UserAction {
  active?: boolean;
  cancelEmailTemplateId?: UUID;
  endEmailTemplateId?: UUID;
  id?: UUID;
  includeEmailInEventJSON?: boolean;
  insertInstant?: number;
  lastUpdateInstant?: number;
  localizedNames?: LocalizedStrings;
  modifyEmailTemplateId?: UUID;
  name?: string;
  options?: Array<UserActionOption>;
  preventLogin?: boolean;
  sendEndEvent?: boolean;
  startEmailTemplateId?: UUID;
  temporal?: boolean;
  transactionType?: TransactionType;
  userEmailingEnabled?: boolean;
  userNotificationsEnabled?: boolean;
}

/**
 * Forgot password response object.
 *
 * @author Daniel DeGroff
 */
export interface ForgotPasswordResponse {
  changePasswordId?: string;
}

/**
 * Models the JWT Refresh Event. This event will be fired when a JWT is "refreshed" (generated) using a Refresh Token.
 *
 * @author Daniel DeGroff
 */
export interface JWTRefreshEvent extends BaseEvent {
  applicationId?: UUID;
  original?: string;
  refreshToken?: string;
  token?: string;
  userId?: UUID;
}

/**
 * Search results.
 *
 * @author Brian Pontarelli
 */
export interface SearchResults<T> {
  nextResults?: string;
  results?: Array<T>;
  total?: number;
  totalEqualToActual?: boolean;
}

/**
 * Models a set of localized Strings that can be stored as JSON.
 *
 * @author Brian Pontarelli
 */
export interface LocalizedStrings extends Record<string, string> {
}

/**
 * Search request for entities
 *
 * @author Brett Guy
 */
export interface EntitySearchResponse {
  entities?: Array<Entity>;
  nextResults?: string;
  total?: number;
}

/**
 * @author Derek Klatt
 */
export interface PasswordValidationRules {
  breachDetection?: PasswordBreachDetection;
  maxLength?: number;
  minLength?: number;
  rememberPreviousPasswords?: RememberPreviousPasswords;
  requireMixedCase?: boolean;
  requireNonAlpha?: boolean;
  requireNumber?: boolean;
  validateOnLogin?: boolean;
}

/**
 * @author Daniel DeGroff
 */
export interface SecretResponse {
  secret?: string;
  secretBase32Encoded?: string;
}

/**
 * Twitter social login provider.
 *
 * @author Daniel DeGroff
 */
export interface TwitterIdentityProvider extends BaseIdentityProvider<TwitterApplicationConfiguration> {
  buttonText?: string;
  consumerKey?: string;
  consumerSecret?: string;
}

/**
 * @author Daniel DeGroff
 */
export interface HYPRIdentityProvider extends BaseIdentityProvider<HYPRApplicationConfiguration> {
  relyingPartyApplicationId?: string;
  relyingPartyURL?: string;
}

/**
 * Models the User Password Reset Success Event.
 *
 * @author Daniel DeGroff
 */
export interface UserPasswordResetSuccessEvent extends BaseUserEvent {
}

/**
 * Something that can be required and thus also optional. This currently extends Enableable because anything that is
 * required/optional is almost always enableable as well.
 *
 * @author Brian Pontarelli
 */
export interface Requirable extends Enableable {
  required?: boolean;
}

/**
 * JWT Configuration for entities.
 */
export interface EntityJWTConfiguration extends Enableable {
  accessTokenKeyId?: UUID;
  timeToLiveInSeconds?: number;
}

/**
 * @author Daniel DeGroff
 */
export interface ReloadRequest {
  names?: Array<string>;
}

/**
 * Search request for user comments
 *
 * @author Spencer Witt
 */
export interface UserCommentSearchRequest {
  search?: UserCommentSearchCriteria;
}

/**
 * Request to complete the WebAuthn registration ceremony
 *
 * @author Spencer Witt
 */
export interface WebAuthnLoginRequest extends BaseLoginRequest {
  credential?: WebAuthnPublicKeyAuthenticationRequest;
  origin?: string;
  rpId?: string;
  twoFactorTrustId?: string;
}

/**
 * domain POJO to represent AuthenticationKey
 *
 * @author sanjay
 */
export interface APIKey {
  expirationInstant?: number;
  id?: UUID;
  insertInstant?: number;
  ipAccessControlListId?: UUID;
  key?: string;
  keyManager?: boolean;
  lastUpdateInstant?: number;
  metaData?: APIKeyMetaData;
  name?: string;
  permissions?: APIKeyPermissions;
  retrievable?: boolean;
  tenantId?: UUID;
}

/**
 * Search criteria for webhooks.
 *
 * @author Spencer Witt
 */
export interface WebhookSearchCriteria extends BaseSearchCriteria {
  description?: string;
  tenantId?: UUID;
  url?: string;
}

/**
 * Policy for handling unknown OAuth scopes in the request
 *
 * @author Spencer Witt
 */
export enum UnknownScopePolicy {
  Allow = "Allow",
  Remove = "Remove",
  Reject = "Reject"
}

/**
 * Models the User Password Reset Start Event.
 *
 * @author Daniel DeGroff
 */
export interface UserPasswordResetStartEvent extends BaseUserEvent {
}

/**
 * Models the Group Delete Event.
 *
 * @author Daniel DeGroff
 */
export interface GroupDeleteEvent extends BaseGroupEvent {
}

export interface MultiFactorEmailTemplate {
  templateId?: UUID;
}

export enum OAuthErrorReason {
  auth_code_not_found = "auth_code_not_found",
  access_token_malformed = "access_token_malformed",
  access_token_expired = "access_token_expired",
  access_token_unavailable_for_processing = "access_token_unavailable_for_processing",
  access_token_failed_processing = "access_token_failed_processing",
  access_token_invalid = "access_token_invalid",
  access_token_required = "access_token_required",
  refresh_token_not_found = "refresh_token_not_found",
  refresh_token_type_not_supported = "refresh_token_type_not_supported",
  invalid_client_id = "invalid_client_id",
  invalid_expires_in = "invalid_expires_in",
  invalid_user_credentials = "invalid_user_credentials",
  invalid_grant_type = "invalid_grant_type",
  invalid_origin = "invalid_origin",
  invalid_origin_opaque = "invalid_origin_opaque",
  invalid_pkce_code_verifier = "invalid_pkce_code_verifier",
  invalid_pkce_code_challenge = "invalid_pkce_code_challenge",
  invalid_pkce_code_challenge_method = "invalid_pkce_code_challenge_method",
  invalid_redirect_uri = "invalid_redirect_uri",
  invalid_response_mode = "invalid_response_mode",
  invalid_response_type = "invalid_response_type",
  invalid_id_token_hint = "invalid_id_token_hint",
  invalid_post_logout_redirect_uri = "invalid_post_logout_redirect_uri",
  invalid_device_code = "invalid_device_code",
  invalid_user_code = "invalid_user_code",
  invalid_additional_client_id = "invalid_additional_client_id",
  invalid_target_entity_scope = "invalid_target_entity_scope",
  invalid_entity_permission_scope = "invalid_entity_permission_scope",
  invalid_user_id = "invalid_user_id",
  grant_type_disabled = "grant_type_disabled",
  missing_client_id = "missing_client_id",
  missing_client_secret = "missing_client_secret",
  missing_code = "missing_code",
  missing_code_challenge = "missing_code_challenge",
  missing_code_verifier = "missing_code_verifier",
  missing_device_code = "missing_device_code",
  missing_grant_type = "missing_grant_type",
  missing_redirect_uri = "missing_redirect_uri",
  missing_refresh_token = "missing_refresh_token",
  missing_response_type = "missing_response_type",
  missing_token = "missing_token",
  missing_user_code = "missing_user_code",
  missing_user_id = "missing_user_id",
  missing_verification_uri = "missing_verification_uri",
  login_prevented = "login_prevented",
  not_licensed = "not_licensed",
  user_code_expired = "user_code_expired",
  user_expired = "user_expired",
  user_locked = "user_locked",
  user_not_found = "user_not_found",
  client_authentication_missing = "client_authentication_missing",
  invalid_client_authentication_scheme = "invalid_client_authentication_scheme",
  invalid_client_authentication = "invalid_client_authentication",
  client_id_mismatch = "client_id_mismatch",
  change_password_administrative = "change_password_administrative",
  change_password_breached = "change_password_breached",
  change_password_expired = "change_password_expired",
  change_password_validation = "change_password_validation",
  unknown = "unknown",
  missing_required_scope = "missing_required_scope",
  unknown_scope = "unknown_scope",
  consent_canceled = "consent_canceled"
}

/**
 * @author Brett Pontarelli
 */
export interface TenantSSOConfiguration {
  deviceTrustTimeToLiveInSeconds?: number;
}

/**
 * Supply information on credential type and algorithm to the <i>authenticator</i>.
 *
 * @author Spencer Witt
 */
export interface PublicKeyCredentialParameters {
  alg?: CoseAlgorithmIdentifier;
  type?: PublicKeyCredentialType;
}

/**
 * API response for consent.
 *
 * @author Daniel DeGroff
 */
export interface ConsentResponse {
  consent?: Consent;
  consents?: Array<Consent>;
}

/**
 * Models the Group Member Remove Event.
 *
 * @author Daniel DeGroff
 */
export interface GroupMemberRemoveEvent extends BaseGroupEvent {
  members?: Array<GroupMember>;
}

/**
 * @author Daniel DeGroff
 */
export interface IdentityProviderPendingLinkResponse {
  identityProviderTenantConfiguration?: IdentityProviderTenantConfiguration;
  linkCount?: number;
  pendingIdPLink?: PendingIdPLink;
}

/**
 * Change password response object.
 *
 * @author Daniel DeGroff
 */
export interface ChangePasswordResponse {
  oneTimePassword?: string;
  state?: Record<string, any>;
}

/**
 * The user action response object.
 *
 * @author Brian Pontarelli
 */
export interface ActionResponse {
  action?: UserActionLog;
  actions?: Array<UserActionLog>;
}

export interface Totals {
  logins?: number;
  registrations?: number;
  totalRegistrations?: number;
}

/**
 * Config for regular SAML IDP configurations that support IdP initiated requests
 *
 * @author Lyle Schemmerling
 */
export interface SAMLv2IdpInitiatedConfiguration extends Enableable {
  issuer?: string;
}

/**
 * Request for the system configuration API.
 *
 * @author Brian Pontarelli
 */
export interface SystemConfigurationRequest {
  systemConfiguration?: SystemConfiguration;
}

/**
 * User Action API request object.
 *
 * @author Brian Pontarelli
 */
export interface UserActionRequest {
  userAction?: UserAction;
}

export enum ClientAuthenticationMethod {
  none = "none",
  client_secret_basic = "client_secret_basic",
  client_secret_post = "client_secret_post"
}

/**
 * @author Brett Guy
 */
export interface IPAccessControlListResponse {
  ipAccessControlList?: IPAccessControlList;
  ipAccessControlLists?: Array<IPAccessControlList>;
}

/**
 * Request for managing FusionAuth Reactor and licenses.
 *
 * @author Brian Pontarelli
 */
export interface ReactorRequest {
  license?: string;
  licenseId?: string;
}

/**
 * Controls the policy for requesting user permission to grant access to requested scopes during an OAuth workflow
 * for a third-party application.
 *
 * @author Spencer Witt
 */
export enum OAuthScopeConsentMode {
  AlwaysPrompt = "AlwaysPrompt",
  RememberDecision = "RememberDecision",
  NeverPrompt = "NeverPrompt"
}

/**
 * @author Michael Sleevi
 */
export interface MessageTemplateResponse {
  messageTemplate?: MessageTemplate;
  messageTemplates?: Array<MessageTemplate>;
}

/**
 * @author Brett Pontarelli
 */
export enum IdentityProviderLoginMethod {
  UsePopup = "UsePopup",
  UseRedirect = "UseRedirect",
  UseVendorJavaScript = "UseVendorJavaScript"
}

/**
 * @author Brett Guy
 */
export interface MessengerRequest {
  messenger?: BaseMessengerConfiguration;
}

/**
 * Request for the Tenant API to delete a tenant rather than using the URL parameters.
 *
 * @author Brian Pontarelli
 */
export interface TenantDeleteRequest extends BaseEventRequest {
  async?: boolean;
}

/**
 * An Event "event" to indicate an event log was created.
 *
 * @author Daniel DeGroff
 */
export interface EventLogCreateEvent extends BaseEvent {
  eventLog?: EventLog;
}

/**
 * The possible result states of a webhook event. This tracks the success of the overall webhook transaction according to the {@link TransactionType}
 * and configured webhooks.
 *
 * @author Spencer Witt
 */
export enum WebhookEventResult {
  Failed = "Failed",
  Running = "Running",
  Succeeded = "Succeeded"
}

export interface UniqueUsernameConfiguration extends Enableable {
  numberOfDigits?: number;
  separator?: string;
  strategy?: UniqueUsernameStrategy;
}

/**
 * @author Daniel DeGroff
 */
export interface SAMLv2IdPInitiatedApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
}

/**
 * Event log response.
 *
 * @author Daniel DeGroff
 */
export interface EventLogResponse {
  eventLog?: EventLog;
}

/**
 * @author Daniel DeGroff
 */
export interface TenantRegistrationConfiguration {
  blockedDomains?: Array<string>;
}

