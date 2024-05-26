// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Email_DataProvider_0_H
#define WINRT_Windows_ApplicationModel_Email_DataProvider_0_H
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Email
{
    enum class EmailBatchStatus : int32_t;
    enum class EmailCertificateValidationStatus : int32_t;
    struct EmailFolder;
    enum class EmailMailboxAutoReplyMessageResponseKind : int32_t;
    struct EmailMailboxAutoReplySettings;
    enum class EmailMailboxCreateFolderStatus : int32_t;
    enum class EmailMailboxDeleteFolderStatus : int32_t;
    enum class EmailMailboxEmptyFolderStatus : int32_t;
    enum class EmailMeetingResponseType : int32_t;
    struct EmailMessage;
    enum class EmailMessageBodyKind : int32_t;
    struct EmailQueryOptions;
    struct EmailRecipient;
    struct EmailRecipientResolutionResult;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct Deferral;
    struct EventRegistrationToken;
    struct IAsyncAction;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Security::Cryptography::Certificates
{
    struct Certificate;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Email::DataProvider
{
    struct IEmailDataProviderConnection;
    struct IEmailDataProviderTriggerDetails;
    struct IEmailMailboxCreateFolderRequest;
    struct IEmailMailboxCreateFolderRequestEventArgs;
    struct IEmailMailboxDeleteFolderRequest;
    struct IEmailMailboxDeleteFolderRequestEventArgs;
    struct IEmailMailboxDownloadAttachmentRequest;
    struct IEmailMailboxDownloadAttachmentRequestEventArgs;
    struct IEmailMailboxDownloadMessageRequest;
    struct IEmailMailboxDownloadMessageRequestEventArgs;
    struct IEmailMailboxEmptyFolderRequest;
    struct IEmailMailboxEmptyFolderRequestEventArgs;
    struct IEmailMailboxForwardMeetingRequest;
    struct IEmailMailboxForwardMeetingRequestEventArgs;
    struct IEmailMailboxGetAutoReplySettingsRequest;
    struct IEmailMailboxGetAutoReplySettingsRequestEventArgs;
    struct IEmailMailboxMoveFolderRequest;
    struct IEmailMailboxMoveFolderRequestEventArgs;
    struct IEmailMailboxProposeNewTimeForMeetingRequest;
    struct IEmailMailboxProposeNewTimeForMeetingRequestEventArgs;
    struct IEmailMailboxResolveRecipientsRequest;
    struct IEmailMailboxResolveRecipientsRequestEventArgs;
    struct IEmailMailboxServerSearchReadBatchRequest;
    struct IEmailMailboxServerSearchReadBatchRequestEventArgs;
    struct IEmailMailboxSetAutoReplySettingsRequest;
    struct IEmailMailboxSetAutoReplySettingsRequestEventArgs;
    struct IEmailMailboxSyncManagerSyncRequest;
    struct IEmailMailboxSyncManagerSyncRequestEventArgs;
    struct IEmailMailboxUpdateMeetingResponseRequest;
    struct IEmailMailboxUpdateMeetingResponseRequestEventArgs;
    struct IEmailMailboxValidateCertificatesRequest;
    struct IEmailMailboxValidateCertificatesRequestEventArgs;
    struct EmailDataProviderConnection;
    struct EmailDataProviderTriggerDetails;
    struct EmailMailboxCreateFolderRequest;
    struct EmailMailboxCreateFolderRequestEventArgs;
    struct EmailMailboxDeleteFolderRequest;
    struct EmailMailboxDeleteFolderRequestEventArgs;
    struct EmailMailboxDownloadAttachmentRequest;
    struct EmailMailboxDownloadAttachmentRequestEventArgs;
    struct EmailMailboxDownloadMessageRequest;
    struct EmailMailboxDownloadMessageRequestEventArgs;
    struct EmailMailboxEmptyFolderRequest;
    struct EmailMailboxEmptyFolderRequestEventArgs;
    struct EmailMailboxForwardMeetingRequest;
    struct EmailMailboxForwardMeetingRequestEventArgs;
    struct EmailMailboxGetAutoReplySettingsRequest;
    struct EmailMailboxGetAutoReplySettingsRequestEventArgs;
    struct EmailMailboxMoveFolderRequest;
    struct EmailMailboxMoveFolderRequestEventArgs;
    struct EmailMailboxProposeNewTimeForMeetingRequest;
    struct EmailMailboxProposeNewTimeForMeetingRequestEventArgs;
    struct EmailMailboxResolveRecipientsRequest;
    struct EmailMailboxResolveRecipientsRequestEventArgs;
    struct EmailMailboxServerSearchReadBatchRequest;
    struct EmailMailboxServerSearchReadBatchRequestEventArgs;
    struct EmailMailboxSetAutoReplySettingsRequest;
    struct EmailMailboxSetAutoReplySettingsRequestEventArgs;
    struct EmailMailboxSyncManagerSyncRequest;
    struct EmailMailboxSyncManagerSyncRequestEventArgs;
    struct EmailMailboxUpdateMeetingResponseRequest;
    struct EmailMailboxUpdateMeetingResponseRequestEventArgs;
    struct EmailMailboxValidateCertificatesRequest;
    struct EmailMailboxValidateCertificatesRequestEventArgs;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderTriggerDetails>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequestEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderTriggerDetails>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequestEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequestEventArgs>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection> = L"Windows.ApplicationModel.Email.DataProvider.EmailDataProviderConnection";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderTriggerDetails> = L"Windows.ApplicationModel.Email.DataProvider.EmailDataProviderTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxCreateFolderRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxCreateFolderRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxDeleteFolderRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxDeleteFolderRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxDownloadAttachmentRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxDownloadAttachmentRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxDownloadMessageRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxDownloadMessageRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxEmptyFolderRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxEmptyFolderRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxForwardMeetingRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxForwardMeetingRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxGetAutoReplySettingsRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxGetAutoReplySettingsRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxMoveFolderRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxMoveFolderRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxProposeNewTimeForMeetingRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxProposeNewTimeForMeetingRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxResolveRecipientsRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxResolveRecipientsRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxServerSearchReadBatchRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxServerSearchReadBatchRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxSetAutoReplySettingsRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxSetAutoReplySettingsRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxSyncManagerSyncRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxSyncManagerSyncRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxUpdateMeetingResponseRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxUpdateMeetingResponseRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequest> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxValidateCertificatesRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.EmailMailboxValidateCertificatesRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection> = L"Windows.ApplicationModel.Email.DataProvider.IEmailDataProviderConnection";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderTriggerDetails> = L"Windows.ApplicationModel.Email.DataProvider.IEmailDataProviderTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxCreateFolderRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxCreateFolderRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxDeleteFolderRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxDeleteFolderRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxDownloadAttachmentRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxDownloadAttachmentRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxDownloadMessageRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxDownloadMessageRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxEmptyFolderRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxEmptyFolderRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxForwardMeetingRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxForwardMeetingRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxGetAutoReplySettingsRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxGetAutoReplySettingsRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxMoveFolderRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxMoveFolderRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxProposeNewTimeForMeetingRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxProposeNewTimeForMeetingRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxResolveRecipientsRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxResolveRecipientsRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxServerSearchReadBatchRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxServerSearchReadBatchRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxSetAutoReplySettingsRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxSetAutoReplySettingsRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxSyncManagerSyncRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxSyncManagerSyncRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxUpdateMeetingResponseRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxUpdateMeetingResponseRequestEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxValidateCertificatesRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequestEventArgs> = L"Windows.ApplicationModel.Email.DataProvider.IEmailMailboxValidateCertificatesRequestEventArgs";
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>{ 0x3B9C9DC7,0x37B2,0x4BF0,{ 0xAE,0x30,0x7B,0x64,0x4A,0x1C,0x96,0xE1 } }; // 3B9C9DC7-37B2-4BF0-AE30-7B644A1C96E1
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderTriggerDetails>{ 0x8F3E4E50,0x341E,0x45F3,{ 0xBB,0xA0,0x84,0xA0,0x05,0xE1,0x31,0x9A } }; // 8F3E4E50-341E-45F3-BBA0-84A005E1319A
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest>{ 0x184D3775,0xC921,0x4C39,{ 0xA3,0x09,0xE1,0x6C,0x9F,0x22,0xB0,0x4B } }; // 184D3775-C921-4C39-A309-E16C9F22B04B
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequestEventArgs>{ 0x03E4C02C,0x241C,0x4EA9,{ 0xA6,0x8F,0xFF,0x20,0xBC,0x5A,0xFC,0x85 } }; // 03E4C02C-241C-4EA9-A68F-FF20BC5AFC85
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest>{ 0x9469E88A,0xA931,0x4779,{ 0x92,0x3D,0x09,0xA3,0xEA,0x29,0x2E,0x29 } }; // 9469E88A-A931-4779-923D-09A3EA292E29
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequestEventArgs>{ 0xB4D32D06,0x2332,0x4678,{ 0x83,0x78,0x28,0xB5,0x79,0x33,0x68,0x46 } }; // B4D32D06-2332-4678-8378-28B579336846
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest>{ 0x0B1DBBB4,0x750C,0x48E1,{ 0xBC,0xE4,0x8D,0x58,0x96,0x84,0xFF,0xBC } }; // 0B1DBBB4-750C-48E1-BCE4-8D589684FFBC
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequestEventArgs>{ 0xCCDDC46D,0xFFA8,0x4877,{ 0x9F,0x9D,0xFE,0xD7,0xBC,0xAF,0x41,0x04 } }; // CCDDC46D-FFA8-4877-9F9D-FED7BCAF4104
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest>{ 0x497B4187,0x5B4D,0x4B23,{ 0x81,0x6C,0xF3,0x84,0x2B,0xEB,0x75,0x3E } }; // 497B4187-5B4D-4B23-816C-F3842BEB753E
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequestEventArgs>{ 0x470409AD,0xD0A0,0x4A5B,{ 0xBB,0x2A,0x37,0x62,0x10,0x39,0xC5,0x3E } }; // 470409AD-D0A0-4A5B-BB2A-37621039C53E
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest>{ 0xFE4B03AB,0xF86D,0x46D9,{ 0xB4,0xCE,0xBC,0x8A,0x6D,0x9E,0x92,0x68 } }; // FE4B03AB-F86D-46D9-B4CE-BC8A6D9E9268
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequestEventArgs>{ 0x7183F484,0x985A,0x4AC0,{ 0xB3,0x3F,0xEE,0x0E,0x26,0x27,0xA3,0xC0 } }; // 7183F484-985A-4AC0-B33F-EE0E2627A3C0
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest>{ 0x616D6AF1,0x70D4,0x4832,{ 0xB8,0x69,0xB8,0x05,0x42,0xAE,0x9B,0xE8 } }; // 616D6AF1-70D4-4832-B869-B80542AE9BE8
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequestEventArgs>{ 0x2BD8F33A,0x2974,0x4759,{ 0xA5,0xA5,0x58,0xF4,0x4D,0x3C,0x02,0x75 } }; // 2BD8F33A-2974-4759-A5A5-58F44D3C0275
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest>{ 0x9B380789,0x1E88,0x4E01,{ 0x84,0xCC,0x13,0x86,0xAD,0x9A,0x2C,0x2F } }; // 9B380789-1E88-4E01-84CC-1386AD9A2C2F
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequestEventArgs>{ 0xD79F55C2,0xFD45,0x4004,{ 0x8A,0x91,0x9B,0xAC,0xF3,0x8B,0x70,0x22 } }; // D79F55C2-FD45-4004-8A91-9BACF38B7022
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest>{ 0x10BA2856,0x4A95,0x4068,{ 0x91,0xCC,0x67,0xCC,0x7A,0xCF,0x45,0x4F } }; // 10BA2856-4A95-4068-91CC-67CC7ACF454F
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequestEventArgs>{ 0x38623020,0x14BA,0x4C88,{ 0x86,0x98,0x72,0x39,0xE3,0xC8,0xAA,0xA7 } }; // 38623020-14BA-4C88-8698-7239E3C8AAA7
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest>{ 0x5AEFF152,0x9799,0x4F9F,{ 0xA3,0x99,0xFF,0x07,0xF3,0xEE,0xF0,0x4E } }; // 5AEFF152-9799-4F9F-A399-FF07F3EEF04E
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequestEventArgs>{ 0xFB480B98,0x33AD,0x4A67,{ 0x82,0x51,0x0F,0x9C,0x24,0x9B,0x6A,0x20 } }; // FB480B98-33AD-4A67-8251-0F9C249B6A20
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest>{ 0xEFA4CF70,0x7B39,0x4C9B,{ 0x81,0x1E,0x41,0xEA,0xF4,0x3A,0x33,0x2D } }; // EFA4CF70-7B39-4C9B-811E-41EAF43A332D
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequestEventArgs>{ 0x260F9E02,0xB2CF,0x40F8,{ 0x8C,0x28,0xE3,0xED,0x43,0xB1,0xE8,0x9A } }; // 260F9E02-B2CF-40F8-8C28-E3ED43B1E89A
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest>{ 0x090EEBDF,0x5A96,0x41D3,{ 0x8A,0xD8,0x34,0x91,0x2F,0x9A,0xA6,0x0E } }; // 090EEBDF-5A96-41D3-8AD8-34912F9AA60E
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequestEventArgs>{ 0x14101B4E,0xED9E,0x45D1,{ 0xAD,0x7A,0xCC,0x9B,0x7F,0x64,0x3A,0xE2 } }; // 14101B4E-ED9E-45D1-AD7A-CC9B7F643AE2
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest>{ 0x75A422D0,0xA88E,0x4E54,{ 0x8D,0xC7,0xC2,0x43,0x18,0x6B,0x77,0x4E } }; // 75A422D0-A88E-4E54-8DC7-C243186B774E
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequestEventArgs>{ 0x09DA11AD,0xD7CA,0x4087,{ 0xAC,0x86,0x53,0xFA,0x67,0xF7,0x62,0x46 } }; // 09DA11AD-D7CA-4087-AC86-53FA67F76246
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequest>{ 0x4E10E8E4,0x7E67,0x405A,{ 0xB6,0x73,0xDC,0x60,0xC9,0x10,0x90,0xFC } }; // 4E10E8E4-7E67-405A-B673-DC60C91090FC
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequestEventArgs>{ 0x439A031A,0x8FCC,0x4AE5,{ 0xB9,0xB5,0xD4,0x34,0xE0,0xA6,0x5A,0xA8 } }; // 439A031A-8FCC-4AE5-B9B5-D434E0A65AA8
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest>{ 0x5B99AC93,0xB2CF,0x4888,{ 0xBA,0x4F,0x30,0x6B,0x6B,0x66,0xDF,0x30 } }; // 5B99AC93-B2CF-4888-BA4F-306B6B66DF30
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequestEventArgs>{ 0x6898D761,0x56C9,0x4F17,{ 0xBE,0x31,0x66,0xFD,0xA9,0x4B,0xA1,0x59 } }; // 6898D761-56C9-4F17-BE31-66FDA94BA159
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest>{ 0xA94D3931,0xE11A,0x4F97,{ 0xB8,0x1A,0x18,0x7A,0x70,0xA8,0xF4,0x1A } }; // A94D3931-E11A-4F97-B81A-187A70A8F41A
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequestEventArgs>{ 0x2583BF17,0x02FF,0x49FE,{ 0xA7,0x3C,0x03,0xF3,0x75,0x66,0xC6,0x91 } }; // 2583BF17-02FF-49FE-A73C-03F37566C691
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderTriggerDetails>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderTriggerDetails; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequestEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequest>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequestEventArgs>{ using type = winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequestEventArgs; };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_MailboxSyncRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_MailboxSyncRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_DownloadMessageRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_DownloadMessageRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_DownloadAttachmentRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_DownloadAttachmentRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_CreateFolderRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_CreateFolderRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_DeleteFolderRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_DeleteFolderRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_EmptyFolderRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_EmptyFolderRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_MoveFolderRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_MoveFolderRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_UpdateMeetingResponseRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_UpdateMeetingResponseRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ForwardMeetingRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ForwardMeetingRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ProposeNewTimeForMeetingRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ProposeNewTimeForMeetingRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_SetAutoReplySettingsRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SetAutoReplySettingsRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_GetAutoReplySettingsRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_GetAutoReplySettingsRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ResolveRecipientsRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ResolveRecipientsRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ValidateCertificatesRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ValidateCertificatesRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ServerSearchReadBatchRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ServerSearchReadBatchRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall Start() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderTriggerDetails>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Connection(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_ParentFolderId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_EmailFolderId(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_EmailMessageId(void**) noexcept = 0;
            virtual int32_t __stdcall get_EmailAttachmentId(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_EmailMessageId(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_EmailFolderId(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_EmailMessageId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Recipients(void**) noexcept = 0;
            virtual int32_t __stdcall get_Subject(void**) noexcept = 0;
            virtual int32_t __stdcall get_ForwardHeaderType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ForwardHeader(void**) noexcept = 0;
            virtual int32_t __stdcall get_Comment(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_RequestedFormat(int32_t*) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_EmailFolderId(void**) noexcept = 0;
            virtual int32_t __stdcall get_NewParentFolderId(void**) noexcept = 0;
            virtual int32_t __stdcall get_NewFolderName(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_EmailMessageId(void**) noexcept = 0;
            virtual int32_t __stdcall get_NewStartTime(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_NewDuration(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Subject(void**) noexcept = 0;
            virtual int32_t __stdcall get_Comment(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Recipients(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SessionId(void**) noexcept = 0;
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_EmailFolderId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Options(void**) noexcept = 0;
            virtual int32_t __stdcall get_SuggestedBatchSize(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall SaveMessageAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_AutoReplySettings(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_EmailMessageId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Response(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Subject(void**) noexcept = 0;
            virtual int32_t __stdcall get_Comment(void**) noexcept = 0;
            virtual int32_t __stdcall get_SendUpdate(bool*) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EmailMailboxId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Certificates(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCompletedAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReportFailedAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequestEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection
    {
        WINRT_IMPL_AUTO(winrt::event_token) MailboxSyncRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequestEventArgs> const& handler) const;
        using MailboxSyncRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_MailboxSyncRequested>;
        [[nodiscard]] MailboxSyncRequested_revoker MailboxSyncRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) MailboxSyncRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) DownloadMessageRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequestEventArgs> const& handler) const;
        using DownloadMessageRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_DownloadMessageRequested>;
        [[nodiscard]] DownloadMessageRequested_revoker DownloadMessageRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) DownloadMessageRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) DownloadAttachmentRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequestEventArgs> const& handler) const;
        using DownloadAttachmentRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_DownloadAttachmentRequested>;
        [[nodiscard]] DownloadAttachmentRequested_revoker DownloadAttachmentRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) DownloadAttachmentRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) CreateFolderRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequestEventArgs> const& handler) const;
        using CreateFolderRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_CreateFolderRequested>;
        [[nodiscard]] CreateFolderRequested_revoker CreateFolderRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) CreateFolderRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) DeleteFolderRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequestEventArgs> const& handler) const;
        using DeleteFolderRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_DeleteFolderRequested>;
        [[nodiscard]] DeleteFolderRequested_revoker DeleteFolderRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) DeleteFolderRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) EmptyFolderRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequestEventArgs> const& handler) const;
        using EmptyFolderRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_EmptyFolderRequested>;
        [[nodiscard]] EmptyFolderRequested_revoker EmptyFolderRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) EmptyFolderRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) MoveFolderRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequestEventArgs> const& handler) const;
        using MoveFolderRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_MoveFolderRequested>;
        [[nodiscard]] MoveFolderRequested_revoker MoveFolderRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) MoveFolderRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) UpdateMeetingResponseRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequestEventArgs> const& handler) const;
        using UpdateMeetingResponseRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_UpdateMeetingResponseRequested>;
        [[nodiscard]] UpdateMeetingResponseRequested_revoker UpdateMeetingResponseRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) UpdateMeetingResponseRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ForwardMeetingRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequestEventArgs> const& handler) const;
        using ForwardMeetingRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_ForwardMeetingRequested>;
        [[nodiscard]] ForwardMeetingRequested_revoker ForwardMeetingRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ForwardMeetingRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ProposeNewTimeForMeetingRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequestEventArgs> const& handler) const;
        using ProposeNewTimeForMeetingRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_ProposeNewTimeForMeetingRequested>;
        [[nodiscard]] ProposeNewTimeForMeetingRequested_revoker ProposeNewTimeForMeetingRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ProposeNewTimeForMeetingRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) SetAutoReplySettingsRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequestEventArgs> const& handler) const;
        using SetAutoReplySettingsRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_SetAutoReplySettingsRequested>;
        [[nodiscard]] SetAutoReplySettingsRequested_revoker SetAutoReplySettingsRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) SetAutoReplySettingsRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) GetAutoReplySettingsRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequestEventArgs> const& handler) const;
        using GetAutoReplySettingsRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_GetAutoReplySettingsRequested>;
        [[nodiscard]] GetAutoReplySettingsRequested_revoker GetAutoReplySettingsRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) GetAutoReplySettingsRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ResolveRecipientsRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequestEventArgs> const& handler) const;
        using ResolveRecipientsRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_ResolveRecipientsRequested>;
        [[nodiscard]] ResolveRecipientsRequested_revoker ResolveRecipientsRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ResolveRecipientsRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ValidateCertificatesRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequestEventArgs> const& handler) const;
        using ValidateCertificatesRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_ValidateCertificatesRequested>;
        [[nodiscard]] ValidateCertificatesRequested_revoker ValidateCertificatesRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ValidateCertificatesRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ServerSearchReadBatchRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequestEventArgs> const& handler) const;
        using ServerSearchReadBatchRequested_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection, &impl::abi_t<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>::remove_ServerSearchReadBatchRequested>;
        [[nodiscard]] ServerSearchReadBatchRequested_revoker ServerSearchReadBatchRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequestEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ServerSearchReadBatchRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(void) Start() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderTriggerDetails
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection) Connection() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderTriggerDetails>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderTriggerDetails<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxCreateFolderRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ParentFolderId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync(winrt::Windows::ApplicationModel::Email::EmailFolder const& folder) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync(winrt::Windows::ApplicationModel::Email::EmailMailboxCreateFolderStatus const& status) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxCreateFolderRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxCreateFolderRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxCreateFolderRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDeleteFolderRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailFolderId() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync(winrt::Windows::ApplicationModel::Email::EmailMailboxDeleteFolderStatus const& status) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDeleteFolderRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDeleteFolderRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDeleteFolderRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadAttachmentRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMessageId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailAttachmentId() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadAttachmentRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadAttachmentRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadAttachmentRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadMessageRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMessageId() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadMessageRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadMessageRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadMessageRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxEmptyFolderRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailFolderId() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync(winrt::Windows::ApplicationModel::Email::EmailMailboxEmptyFolderStatus const& status) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxEmptyFolderRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxEmptyFolderRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxEmptyFolderRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMessageId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailRecipient>) Recipients() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Subject() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMessageBodyKind) ForwardHeaderType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ForwardHeader() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Comment() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxGetAutoReplySettingsRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind) RequestedFormat() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync(winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings const& autoReplySettings) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxGetAutoReplySettingsRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxGetAutoReplySettingsRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxGetAutoReplySettingsRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxMoveFolderRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailFolderId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) NewParentFolderId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) NewFolderName() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxMoveFolderRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxMoveFolderRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxMoveFolderRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMessageId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) NewStartTime() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) NewDuration() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Subject() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Comment() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxResolveRecipientsRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Recipients() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync(param::async_iterable<winrt::Windows::ApplicationModel::Email::EmailRecipientResolutionResult> const& resolutionResults) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxResolveRecipientsRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxResolveRecipientsRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxResolveRecipientsRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SessionId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailFolderId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailQueryOptions) Options() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SuggestedBatchSize() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SaveMessageAsync(winrt::Windows::ApplicationModel::Email::EmailMessage const& message) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync(winrt::Windows::ApplicationModel::Email::EmailBatchStatus const& batchStatus) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSetAutoReplySettingsRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings) AutoReplySettings() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSetAutoReplySettingsRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSetAutoReplySettingsRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSetAutoReplySettingsRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSyncManagerSyncRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSyncManagerSyncRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSyncManagerSyncRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSyncManagerSyncRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMessageId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMeetingResponseType) Response() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Subject() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Comment() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) SendUpdate() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequestEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxValidateCertificatesRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EmailMailboxId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>) Certificates() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportCompletedAsync(param::async_iterable<winrt::Windows::ApplicationModel::Email::EmailCertificateValidationStatus> const& validationStatuses) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReportFailedAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxValidateCertificatesRequest<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxValidateCertificatesRequestEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequest) Request() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequestEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxValidateCertificatesRequestEventArgs<D>;
    };
}
#endif
