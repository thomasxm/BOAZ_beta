// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Email_DataProvider_1_H
#define WINRT_Windows_ApplicationModel_Email_DataProvider_1_H
#include "winrt/impl/Windows.ApplicationModel.Email.DataProvider.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Email::DataProvider
{
    struct __declspec(empty_bases) IEmailDataProviderConnection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailDataProviderConnection>
    {
        IEmailDataProviderConnection(std::nullptr_t = nullptr) noexcept {}
        IEmailDataProviderConnection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailDataProviderTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailDataProviderTriggerDetails>
    {
        IEmailDataProviderTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IEmailDataProviderTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxCreateFolderRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxCreateFolderRequest>
    {
        IEmailMailboxCreateFolderRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxCreateFolderRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxCreateFolderRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxCreateFolderRequestEventArgs>
    {
        IEmailMailboxCreateFolderRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxCreateFolderRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxDeleteFolderRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxDeleteFolderRequest>
    {
        IEmailMailboxDeleteFolderRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxDeleteFolderRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxDeleteFolderRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxDeleteFolderRequestEventArgs>
    {
        IEmailMailboxDeleteFolderRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxDeleteFolderRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxDownloadAttachmentRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxDownloadAttachmentRequest>
    {
        IEmailMailboxDownloadAttachmentRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxDownloadAttachmentRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxDownloadAttachmentRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxDownloadAttachmentRequestEventArgs>
    {
        IEmailMailboxDownloadAttachmentRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxDownloadAttachmentRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxDownloadMessageRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxDownloadMessageRequest>
    {
        IEmailMailboxDownloadMessageRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxDownloadMessageRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxDownloadMessageRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxDownloadMessageRequestEventArgs>
    {
        IEmailMailboxDownloadMessageRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxDownloadMessageRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxEmptyFolderRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxEmptyFolderRequest>
    {
        IEmailMailboxEmptyFolderRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxEmptyFolderRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxEmptyFolderRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxEmptyFolderRequestEventArgs>
    {
        IEmailMailboxEmptyFolderRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxEmptyFolderRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxForwardMeetingRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxForwardMeetingRequest>
    {
        IEmailMailboxForwardMeetingRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxForwardMeetingRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxForwardMeetingRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxForwardMeetingRequestEventArgs>
    {
        IEmailMailboxForwardMeetingRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxForwardMeetingRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxGetAutoReplySettingsRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxGetAutoReplySettingsRequest>
    {
        IEmailMailboxGetAutoReplySettingsRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxGetAutoReplySettingsRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxGetAutoReplySettingsRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxGetAutoReplySettingsRequestEventArgs>
    {
        IEmailMailboxGetAutoReplySettingsRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxGetAutoReplySettingsRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxMoveFolderRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxMoveFolderRequest>
    {
        IEmailMailboxMoveFolderRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxMoveFolderRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxMoveFolderRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxMoveFolderRequestEventArgs>
    {
        IEmailMailboxMoveFolderRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxMoveFolderRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxProposeNewTimeForMeetingRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxProposeNewTimeForMeetingRequest>
    {
        IEmailMailboxProposeNewTimeForMeetingRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxProposeNewTimeForMeetingRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxProposeNewTimeForMeetingRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxProposeNewTimeForMeetingRequestEventArgs>
    {
        IEmailMailboxProposeNewTimeForMeetingRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxProposeNewTimeForMeetingRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxResolveRecipientsRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxResolveRecipientsRequest>
    {
        IEmailMailboxResolveRecipientsRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxResolveRecipientsRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxResolveRecipientsRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxResolveRecipientsRequestEventArgs>
    {
        IEmailMailboxResolveRecipientsRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxResolveRecipientsRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxServerSearchReadBatchRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxServerSearchReadBatchRequest>
    {
        IEmailMailboxServerSearchReadBatchRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxServerSearchReadBatchRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxServerSearchReadBatchRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxServerSearchReadBatchRequestEventArgs>
    {
        IEmailMailboxServerSearchReadBatchRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxServerSearchReadBatchRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxSetAutoReplySettingsRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxSetAutoReplySettingsRequest>
    {
        IEmailMailboxSetAutoReplySettingsRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxSetAutoReplySettingsRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxSetAutoReplySettingsRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxSetAutoReplySettingsRequestEventArgs>
    {
        IEmailMailboxSetAutoReplySettingsRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxSetAutoReplySettingsRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxSyncManagerSyncRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxSyncManagerSyncRequest>
    {
        IEmailMailboxSyncManagerSyncRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxSyncManagerSyncRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxSyncManagerSyncRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxSyncManagerSyncRequestEventArgs>
    {
        IEmailMailboxSyncManagerSyncRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxSyncManagerSyncRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxUpdateMeetingResponseRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxUpdateMeetingResponseRequest>
    {
        IEmailMailboxUpdateMeetingResponseRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxUpdateMeetingResponseRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxUpdateMeetingResponseRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxUpdateMeetingResponseRequestEventArgs>
    {
        IEmailMailboxUpdateMeetingResponseRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxUpdateMeetingResponseRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxValidateCertificatesRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxValidateCertificatesRequest>
    {
        IEmailMailboxValidateCertificatesRequest(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxValidateCertificatesRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxValidateCertificatesRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxValidateCertificatesRequestEventArgs>
    {
        IEmailMailboxValidateCertificatesRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxValidateCertificatesRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
