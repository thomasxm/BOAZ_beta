// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Email_1_H
#define WINRT_Windows_ApplicationModel_Email_1_H
#include "winrt/impl/Windows.ApplicationModel.Email.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Email
{
    struct __declspec(empty_bases) IEmailAttachment :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailAttachment>
    {
        IEmailAttachment(std::nullptr_t = nullptr) noexcept {}
        IEmailAttachment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailAttachment2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailAttachment2>
    {
        IEmailAttachment2(std::nullptr_t = nullptr) noexcept {}
        IEmailAttachment2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailAttachmentFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailAttachmentFactory>
    {
        IEmailAttachmentFactory(std::nullptr_t = nullptr) noexcept {}
        IEmailAttachmentFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailAttachmentFactory2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailAttachmentFactory2>
    {
        IEmailAttachmentFactory2(std::nullptr_t = nullptr) noexcept {}
        IEmailAttachmentFactory2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailConversation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailConversation>
    {
        IEmailConversation(std::nullptr_t = nullptr) noexcept {}
        IEmailConversation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailConversationBatch :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailConversationBatch>
    {
        IEmailConversationBatch(std::nullptr_t = nullptr) noexcept {}
        IEmailConversationBatch(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailConversationReader :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailConversationReader>
    {
        IEmailConversationReader(std::nullptr_t = nullptr) noexcept {}
        IEmailConversationReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailFolder :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailFolder>
    {
        IEmailFolder(std::nullptr_t = nullptr) noexcept {}
        IEmailFolder(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailIrmInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailIrmInfo>
    {
        IEmailIrmInfo(std::nullptr_t = nullptr) noexcept {}
        IEmailIrmInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailIrmInfoFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailIrmInfoFactory>
    {
        IEmailIrmInfoFactory(std::nullptr_t = nullptr) noexcept {}
        IEmailIrmInfoFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailIrmTemplate :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailIrmTemplate>
    {
        IEmailIrmTemplate(std::nullptr_t = nullptr) noexcept {}
        IEmailIrmTemplate(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailIrmTemplateFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailIrmTemplateFactory>
    {
        IEmailIrmTemplateFactory(std::nullptr_t = nullptr) noexcept {}
        IEmailIrmTemplateFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailItemCounts :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailItemCounts>
    {
        IEmailItemCounts(std::nullptr_t = nullptr) noexcept {}
        IEmailItemCounts(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailbox :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailbox>
    {
        IEmailMailbox(std::nullptr_t = nullptr) noexcept {}
        IEmailMailbox(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailbox2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailbox2>,
        impl::require<winrt::Windows::ApplicationModel::Email::IEmailMailbox2, winrt::Windows::ApplicationModel::Email::IEmailMailbox>
    {
        IEmailMailbox2(std::nullptr_t = nullptr) noexcept {}
        IEmailMailbox2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailbox3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailbox3>,
        impl::require<winrt::Windows::ApplicationModel::Email::IEmailMailbox3, winrt::Windows::ApplicationModel::Email::IEmailMailbox, winrt::Windows::ApplicationModel::Email::IEmailMailbox2>
    {
        IEmailMailbox3(std::nullptr_t = nullptr) noexcept {}
        IEmailMailbox3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailbox4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailbox4>
    {
        IEmailMailbox4(std::nullptr_t = nullptr) noexcept {}
        IEmailMailbox4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailbox5 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailbox5>
    {
        IEmailMailbox5(std::nullptr_t = nullptr) noexcept {}
        IEmailMailbox5(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxAction :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxAction>
    {
        IEmailMailboxAction(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxAction(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxAutoReply :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxAutoReply>
    {
        IEmailMailboxAutoReply(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxAutoReply(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxAutoReplySettings :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxAutoReplySettings>
    {
        IEmailMailboxAutoReplySettings(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxAutoReplySettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxCapabilities :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxCapabilities>
    {
        IEmailMailboxCapabilities(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxCapabilities2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxCapabilities2>
    {
        IEmailMailboxCapabilities2(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxCapabilities2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxCapabilities3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxCapabilities3>
    {
        IEmailMailboxCapabilities3(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxCapabilities3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxChange :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxChange>
    {
        IEmailMailboxChange(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxChange(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxChangeReader :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxChangeReader>
    {
        IEmailMailboxChangeReader(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxChangeReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxChangeTracker :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxChangeTracker>
    {
        IEmailMailboxChangeTracker(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxChangeTracker(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxChangedDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxChangedDeferral>
    {
        IEmailMailboxChangedDeferral(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxChangedDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxChangedEventArgs>
    {
        IEmailMailboxChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxCreateFolderResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxCreateFolderResult>
    {
        IEmailMailboxCreateFolderResult(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxCreateFolderResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxPolicies :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxPolicies>
    {
        IEmailMailboxPolicies(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxPolicies(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxPolicies2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxPolicies2>
    {
        IEmailMailboxPolicies2(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxPolicies2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxPolicies3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxPolicies3>
    {
        IEmailMailboxPolicies3(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxPolicies3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxSyncManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxSyncManager>
    {
        IEmailMailboxSyncManager(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxSyncManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMailboxSyncManager2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMailboxSyncManager2>
    {
        IEmailMailboxSyncManager2(std::nullptr_t = nullptr) noexcept {}
        IEmailMailboxSyncManager2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailManagerForUser :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailManagerForUser>
    {
        IEmailManagerForUser(std::nullptr_t = nullptr) noexcept {}
        IEmailManagerForUser(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailManagerStatics>
    {
        IEmailManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IEmailManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailManagerStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailManagerStatics2>
    {
        IEmailManagerStatics2(std::nullptr_t = nullptr) noexcept {}
        IEmailManagerStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailManagerStatics3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailManagerStatics3>
    {
        IEmailManagerStatics3(std::nullptr_t = nullptr) noexcept {}
        IEmailManagerStatics3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMeetingInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMeetingInfo>
    {
        IEmailMeetingInfo(std::nullptr_t = nullptr) noexcept {}
        IEmailMeetingInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMeetingInfo2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMeetingInfo2>
    {
        IEmailMeetingInfo2(std::nullptr_t = nullptr) noexcept {}
        IEmailMeetingInfo2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMessage>
    {
        IEmailMessage(std::nullptr_t = nullptr) noexcept {}
        IEmailMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMessage2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMessage2>
    {
        IEmailMessage2(std::nullptr_t = nullptr) noexcept {}
        IEmailMessage2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMessage3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMessage3>
    {
        IEmailMessage3(std::nullptr_t = nullptr) noexcept {}
        IEmailMessage3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMessage4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMessage4>
    {
        IEmailMessage4(std::nullptr_t = nullptr) noexcept {}
        IEmailMessage4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMessageBatch :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMessageBatch>
    {
        IEmailMessageBatch(std::nullptr_t = nullptr) noexcept {}
        IEmailMessageBatch(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailMessageReader :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailMessageReader>
    {
        IEmailMessageReader(std::nullptr_t = nullptr) noexcept {}
        IEmailMessageReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailQueryOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailQueryOptions>
    {
        IEmailQueryOptions(std::nullptr_t = nullptr) noexcept {}
        IEmailQueryOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailQueryOptionsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailQueryOptionsFactory>
    {
        IEmailQueryOptionsFactory(std::nullptr_t = nullptr) noexcept {}
        IEmailQueryOptionsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailQueryTextSearch :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailQueryTextSearch>
    {
        IEmailQueryTextSearch(std::nullptr_t = nullptr) noexcept {}
        IEmailQueryTextSearch(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailRecipient :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailRecipient>
    {
        IEmailRecipient(std::nullptr_t = nullptr) noexcept {}
        IEmailRecipient(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailRecipientFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailRecipientFactory>
    {
        IEmailRecipientFactory(std::nullptr_t = nullptr) noexcept {}
        IEmailRecipientFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailRecipientResolutionResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailRecipientResolutionResult>
    {
        IEmailRecipientResolutionResult(std::nullptr_t = nullptr) noexcept {}
        IEmailRecipientResolutionResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailRecipientResolutionResult2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailRecipientResolutionResult2>
    {
        IEmailRecipientResolutionResult2(std::nullptr_t = nullptr) noexcept {}
        IEmailRecipientResolutionResult2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailStore :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailStore>
    {
        IEmailStore(std::nullptr_t = nullptr) noexcept {}
        IEmailStore(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEmailStoreNotificationTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEmailStoreNotificationTriggerDetails>
    {
        IEmailStoreNotificationTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IEmailStoreNotificationTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
