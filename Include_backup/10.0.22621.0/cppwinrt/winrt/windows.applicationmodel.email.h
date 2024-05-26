// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Email_H
#define WINRT_Windows_ApplicationModel_Email_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.h"
#include "winrt/impl/Windows.ApplicationModel.Appointments.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.Cryptography.Certificates.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.ApplicationModel.Email.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailAttachment<D>::FileName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment)->get_FileName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailAttachment<D>::FileName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment)->put_FileName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Email_IEmailAttachment<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment)->get_Data(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailAttachment<D>::Data(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment)->put_Data(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::ContentId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->get_ContentId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::ContentId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->put_ContentId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::ContentLocation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->get_ContentLocation(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::ContentLocation(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->put_ContentLocation(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailAttachmentDownloadState) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::DownloadState() const
    {
        winrt::Windows::ApplicationModel::Email::EmailAttachmentDownloadState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->get_DownloadState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::DownloadState(winrt::Windows::ApplicationModel::Email::EmailAttachmentDownloadState const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->put_DownloadState(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::EstimatedDownloadSizeInBytes() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->get_EstimatedDownloadSizeInBytes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::EstimatedDownloadSizeInBytes(uint64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->put_EstimatedDownloadSizeInBytes(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::IsFromBaseMessage() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->get_IsFromBaseMessage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::IsInline() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->get_IsInline(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::IsInline(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->put_IsInline(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::MimeType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->get_MimeType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::MimeType(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachment2)->put_MimeType(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailAttachment) consume_Windows_ApplicationModel_Email_IEmailAttachmentFactory<D>::Create(param::hstring const& fileName, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& data) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachmentFactory)->Create(*(void**)(&fileName), *(void**)(&data), &result));
        return winrt::Windows::ApplicationModel::Email::EmailAttachment{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailAttachment) consume_Windows_ApplicationModel_Email_IEmailAttachmentFactory2<D>::Create(param::hstring const& fileName, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& data, param::hstring const& mimeType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailAttachmentFactory2)->Create(*(void**)(&fileName), *(void**)(&data), *(void**)(&mimeType), &result));
        return winrt::Windows::ApplicationModel::Email::EmailAttachment{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::MailboxId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->get_MailboxId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailFlagState) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::FlagState() const
    {
        winrt::Windows::ApplicationModel::Email::EmailFlagState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->get_FlagState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::HasAttachment() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->get_HasAttachment(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailImportance) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::Importance() const
    {
        winrt::Windows::ApplicationModel::Email::EmailImportance value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->get_Importance(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMessageResponseKind) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::LastEmailResponseKind() const
    {
        winrt::Windows::ApplicationModel::Email::EmailMessageResponseKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->get_LastEmailResponseKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::MessageCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->get_MessageCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::MostRecentMessageId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->get_MostRecentMessageId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::MostRecentMessageTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->get_MostRecentMessageTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::Preview() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->get_Preview(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailRecipient) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::LatestSender() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->get_LatestSender(&value));
        return winrt::Windows::ApplicationModel::Email::EmailRecipient{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::Subject() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->get_Subject(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::UnreadMessageCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->get_UnreadMessageCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMessage>>) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::FindMessagesAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->FindMessagesAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMessage>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMessage>>) consume_Windows_ApplicationModel_Email_IEmailConversation<D>::FindMessagesAsync(uint32_t count) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversation)->FindMessagesWithCountAsync(count, &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMessage>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailConversation>) consume_Windows_ApplicationModel_Email_IEmailConversationBatch<D>::Conversations() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversationBatch)->get_Conversations(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailConversation>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailBatchStatus) consume_Windows_ApplicationModel_Email_IEmailConversationBatch<D>::Status() const
    {
        winrt::Windows::ApplicationModel::Email::EmailBatchStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversationBatch)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailConversationBatch>) consume_Windows_ApplicationModel_Email_IEmailConversationReader<D>::ReadBatchAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailConversationReader)->ReadBatchAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailConversationBatch>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::RemoteId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->get_RemoteId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::RemoteId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->put_RemoteId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::MailboxId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->get_MailboxId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::ParentFolderId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->get_ParentFolderId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::DisplayName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->put_DisplayName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::IsSyncEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->get_IsSyncEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::IsSyncEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->put_IsSyncEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::LastSuccessfulSyncTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->get_LastSuccessfulSyncTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::LastSuccessfulSyncTime(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->put_LastSuccessfulSyncTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailSpecialFolderKind) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::Kind() const
    {
        winrt::Windows::ApplicationModel::Email::EmailSpecialFolderKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailFolder>) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::CreateFolderAsync(param::hstring const& name) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->CreateFolderAsync(*(void**)(&name), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailFolder>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::DeleteAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->DeleteAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailFolder>>) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::FindChildFoldersAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->FindChildFoldersAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailFolder>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailConversationReader) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::GetConversationReader() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->GetConversationReader(&result));
        return winrt::Windows::ApplicationModel::Email::EmailConversationReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailConversationReader) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::GetConversationReader(winrt::Windows::ApplicationModel::Email::EmailQueryOptions const& options) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->GetConversationReaderWithOptions(*(void**)(&options), &result));
        return winrt::Windows::ApplicationModel::Email::EmailConversationReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessage>) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::GetMessageAsync(param::hstring const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->GetMessageAsync(*(void**)(&id), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessage>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMessageReader) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::GetMessageReader() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->GetMessageReader(&result));
        return winrt::Windows::ApplicationModel::Email::EmailMessageReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMessageReader) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::GetMessageReader(winrt::Windows::ApplicationModel::Email::EmailQueryOptions const& options) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->GetMessageReaderWithOptions(*(void**)(&options), &result));
        return winrt::Windows::ApplicationModel::Email::EmailMessageReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailItemCounts>) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::GetMessageCountsAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->GetMessageCountsAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailItemCounts>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::TryMoveAsync(winrt::Windows::ApplicationModel::Email::EmailFolder const& newParentFolder) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->TryMoveAsync(*(void**)(&newParentFolder), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::TryMoveAsync(winrt::Windows::ApplicationModel::Email::EmailFolder const& newParentFolder, param::hstring const& newFolderName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->TryMoveWithNewNameAsync(*(void**)(&newParentFolder), *(void**)(&newFolderName), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::TrySaveAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->TrySaveAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailFolder<D>::SaveMessageAsync(winrt::Windows::ApplicationModel::Email::EmailMessage const& message) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailFolder)->SaveMessageAsync(*(void**)(&message), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanEdit() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanEdit(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanEdit(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanEdit(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanExtractData() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanExtractData(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanExtractData(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanExtractData(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanForward() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanForward(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanForward(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanForward(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanModifyRecipientsOnResponse() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanModifyRecipientsOnResponse(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanModifyRecipientsOnResponse(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanModifyRecipientsOnResponse(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanPrintData() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanPrintData(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanPrintData(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanPrintData(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanRemoveIrmOnResponse() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanRemoveIrmOnResponse(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanRemoveIrmOnResponse(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanRemoveIrmOnResponse(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanReply() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanReply(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanReply(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanReply(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanReplyAll() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanReplyAll(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanReplyAll(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanReplyAll(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::ExpirationDate() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->get_ExpirationDate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::ExpirationDate(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->put_ExpirationDate(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::IsIrmOriginator() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->get_IsIrmOriginator(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::IsIrmOriginator(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->put_IsIrmOriginator(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::IsProgramaticAccessAllowed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->get_IsProgramaticAccessAllowed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::IsProgramaticAccessAllowed(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->put_IsProgramaticAccessAllowed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailIrmTemplate) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::Template() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->get_Template(&value));
        return winrt::Windows::ApplicationModel::Email::EmailIrmTemplate{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::Template(winrt::Windows::ApplicationModel::Email::EmailIrmTemplate const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfo)->put_Template(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailIrmInfo) consume_Windows_ApplicationModel_Email_IEmailIrmInfoFactory<D>::Create(winrt::Windows::Foundation::DateTime const& expiration, winrt::Windows::ApplicationModel::Email::EmailIrmTemplate const& irmTemplate) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmInfoFactory)->Create(impl::bind_in(expiration), *(void**)(&irmTemplate), &result));
        return winrt::Windows::ApplicationModel::Email::EmailIrmInfo{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailIrmTemplate<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmTemplate)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmTemplate<D>::Id(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmTemplate)->put_Id(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailIrmTemplate<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmTemplate)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmTemplate<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmTemplate)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailIrmTemplate<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmTemplate)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailIrmTemplate<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmTemplate)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailIrmTemplate) consume_Windows_ApplicationModel_Email_IEmailIrmTemplateFactory<D>::Create(param::hstring const& id, param::hstring const& name, param::hstring const& description) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailIrmTemplateFactory)->Create(*(void**)(&id), *(void**)(&name), *(void**)(&description), &result));
        return winrt::Windows::ApplicationModel::Email::EmailIrmTemplate{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_ApplicationModel_Email_IEmailItemCounts<D>::Flagged() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailItemCounts)->get_Flagged(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_ApplicationModel_Email_IEmailItemCounts<D>::Important() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailItemCounts)->get_Important(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_ApplicationModel_Email_IEmailItemCounts<D>::Total() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailItemCounts)->get_Total(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_ApplicationModel_Email_IEmailItemCounts<D>::Unread() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailItemCounts)->get_Unread(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxCapabilities) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::Capabilities() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_Capabilities(&value));
        return winrt::Windows::ApplicationModel::Email::EmailMailboxCapabilities{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxChangeTracker) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::ChangeTracker() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_ChangeTracker(&value));
        return winrt::Windows::ApplicationModel::Email::EmailMailboxChangeTracker{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::DisplayName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->put_DisplayName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::IsOwnedByCurrentApp() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_IsOwnedByCurrentApp(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::IsDataEncryptedUnderLock() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_IsDataEncryptedUnderLock(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_MailAddress(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailAddress(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->put_MailAddress(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailAddressAliases() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_MailAddressAliases(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::OtherAppReadAccess() const
    {
        winrt::Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_OtherAppReadAccess(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::OtherAppReadAccess(winrt::Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->put_OtherAppReadAccess(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::OtherAppWriteAccess() const
    {
        winrt::Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_OtherAppWriteAccess(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::OtherAppWriteAccess(winrt::Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->put_OtherAppWriteAccess(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxPolicies) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::Policies() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_Policies(&value));
        return winrt::Windows::ApplicationModel::Email::EmailMailboxPolicies{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::SourceDisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_SourceDisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxSyncManager) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::SyncManager() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_SyncManager(&value));
        return winrt::Windows::ApplicationModel::Email::EmailMailboxSyncManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::UserDataAccountId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->get_UserDataAccountId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailConversationReader) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetConversationReader() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->GetConversationReader(&result));
        return winrt::Windows::ApplicationModel::Email::EmailConversationReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailConversationReader) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetConversationReader(winrt::Windows::ApplicationModel::Email::EmailQueryOptions const& options) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->GetConversationReaderWithOptions(*(void**)(&options), &result));
        return winrt::Windows::ApplicationModel::Email::EmailConversationReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMessageReader) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetMessageReader() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->GetMessageReader(&result));
        return winrt::Windows::ApplicationModel::Email::EmailMessageReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMessageReader) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetMessageReader(winrt::Windows::ApplicationModel::Email::EmailQueryOptions const& options) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->GetMessageReaderWithOptions(*(void**)(&options), &result));
        return winrt::Windows::ApplicationModel::Email::EmailMessageReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::DeleteAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->DeleteAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailConversation>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetConversationAsync(param::hstring const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->GetConversationAsync(*(void**)(&id), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailConversation>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailFolder>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetFolderAsync(param::hstring const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->GetFolderAsync(*(void**)(&id), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailFolder>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessage>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetMessageAsync(param::hstring const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->GetMessageAsync(*(void**)(&id), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessage>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailFolder>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetSpecialFolderAsync(winrt::Windows::ApplicationModel::Email::EmailSpecialFolderKind const& folderType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->GetSpecialFolderAsync(static_cast<int32_t>(folderType), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailFolder>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::SaveAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->SaveAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MarkMessageAsSeenAsync(param::hstring const& messageId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->MarkMessageAsSeenAsync(*(void**)(&messageId), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MarkFolderAsSeenAsync(param::hstring const& folderId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->MarkFolderAsSeenAsync(*(void**)(&folderId), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MarkMessageReadAsync(param::hstring const& messageId, bool isRead) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->MarkMessageReadAsync(*(void**)(&messageId), isRead, &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::ChangeMessageFlagStateAsync(param::hstring const& messageId, winrt::Windows::ApplicationModel::Email::EmailFlagState const& flagState) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->ChangeMessageFlagStateAsync(*(void**)(&messageId), static_cast<int32_t>(flagState), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryMoveMessageAsync(param::hstring const& messageId, param::hstring const& newParentFolderId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->TryMoveMessageAsync(*(void**)(&messageId), *(void**)(&newParentFolderId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryMoveFolderAsync(param::hstring const& folderId, param::hstring const& newParentFolderId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->TryMoveFolderAsync(*(void**)(&folderId), *(void**)(&newParentFolderId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryMoveFolderAsync(param::hstring const& folderId, param::hstring const& newParentFolderId, param::hstring const& newFolderName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->TryMoveFolderWithNewNameAsync(*(void**)(&folderId), *(void**)(&newParentFolderId), *(void**)(&newFolderName), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::DeleteMessageAsync(param::hstring const& messageId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->DeleteMessageAsync(*(void**)(&messageId), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MarkFolderSyncEnabledAsync(param::hstring const& folderId, bool isSyncEnabled) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->MarkFolderSyncEnabledAsync(*(void**)(&folderId), isSyncEnabled, &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::SendMessageAsync(winrt::Windows::ApplicationModel::Email::EmailMessage const& message) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->SendMessageAsync(*(void**)(&message), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::SaveDraftAsync(winrt::Windows::ApplicationModel::Email::EmailMessage const& message) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->SaveDraftAsync(*(void**)(&message), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::DownloadMessageAsync(param::hstring const& messageId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->DownloadMessageAsync(*(void**)(&messageId), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::DownloadAttachmentAsync(param::hstring const& attachmentId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->DownloadAttachmentAsync(*(void**)(&attachmentId), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessage>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::CreateResponseMessageAsync(param::hstring const& messageId, winrt::Windows::ApplicationModel::Email::EmailMessageResponseKind const& responseType, param::hstring const& subject, winrt::Windows::ApplicationModel::Email::EmailMessageBodyKind const& responseHeaderType, param::hstring const& responseHeader) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->CreateResponseMessageAsync(*(void**)(&messageId), static_cast<int32_t>(responseType), *(void**)(&subject), static_cast<int32_t>(responseHeaderType), *(void**)(&responseHeader), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessage>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryUpdateMeetingResponseAsync(winrt::Windows::ApplicationModel::Email::EmailMessage const& meeting, winrt::Windows::ApplicationModel::Email::EmailMeetingResponseType const& response, param::hstring const& subject, param::hstring const& comment, bool sendUpdate) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->TryUpdateMeetingResponseAsync(*(void**)(&meeting), static_cast<int32_t>(response), *(void**)(&subject), *(void**)(&comment), sendUpdate, &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryForwardMeetingAsync(winrt::Windows::ApplicationModel::Email::EmailMessage const& meeting, param::async_iterable<winrt::Windows::ApplicationModel::Email::EmailRecipient> const& recipients, param::hstring const& subject, winrt::Windows::ApplicationModel::Email::EmailMessageBodyKind const& forwardHeaderType, param::hstring const& forwardHeader, param::hstring const& comment) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->TryForwardMeetingAsync(*(void**)(&meeting), *(void**)(&recipients), *(void**)(&subject), static_cast<int32_t>(forwardHeaderType), *(void**)(&forwardHeader), *(void**)(&comment), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryProposeNewTimeForMeetingAsync(winrt::Windows::ApplicationModel::Email::EmailMessage const& meeting, winrt::Windows::Foundation::DateTime const& newStartTime, winrt::Windows::Foundation::TimeSpan const& newDuration, param::hstring const& subject, param::hstring const& comment) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->TryProposeNewTimeForMeetingAsync(*(void**)(&meeting), impl::bind_in(newStartTime), impl::bind_in(newDuration), *(void**)(&subject), *(void**)(&comment), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailboxChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::EmailMailbox, winrt::Windows::ApplicationModel::Email::EmailMailboxChangedEventArgs> const& pHandler) const
    {
        winrt::event_token pToken{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->add_MailboxChanged(*(void**)(&pHandler), put_abi(pToken)));
        return pToken;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailboxChanged_revoker consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailboxChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::EmailMailbox, winrt::Windows::ApplicationModel::Email::EmailMailboxChangedEventArgs> const& pHandler) const
    {
        return impl::make_event_revoker<D, MailboxChanged_revoker>(this, MailboxChanged(pHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailboxChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->remove_MailboxChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::SendMessageAsync(winrt::Windows::ApplicationModel::Email::EmailMessage const& message, bool smartSend) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->SmartSendMessageAsync(*(void**)(&message), smartSend, &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TrySetAutoReplySettingsAsync(winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings const& autoReplySettings) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->TrySetAutoReplySettingsAsync(*(void**)(&autoReplySettings), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings>) consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryGetAutoReplySettingsAsync(winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind const& requestedFormat) const
    {
        void* autoReplySettings{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox)->TryGetAutoReplySettingsAsync(static_cast<int32_t>(requestedFormat), &autoReplySettings));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings>{ autoReplySettings, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMailbox2<D>::LinkedMailboxId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox2)->get_LinkedMailboxId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMailbox2<D>::NetworkAccountId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox2)->get_NetworkAccountId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMailbox2<D>::NetworkId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox2)->get_NetworkId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailRecipientResolutionResult>>) consume_Windows_ApplicationModel_Email_IEmailMailbox3<D>::ResolveRecipientsAsync(param::async_iterable<hstring> const& recipients) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox3)->ResolveRecipientsAsync(*(void**)(&recipients), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailRecipientResolutionResult>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailCertificateValidationStatus>>) consume_Windows_ApplicationModel_Email_IEmailMailbox3<D>::ValidateCertificatesAsync(param::async_iterable<winrt::Windows::Security::Cryptography::Certificates::Certificate> const& certificates) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox3)->ValidateCertificatesAsync(*(void**)(&certificates), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailCertificateValidationStatus>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailboxEmptyFolderStatus>) consume_Windows_ApplicationModel_Email_IEmailMailbox3<D>::TryEmptyFolderAsync(param::hstring const& folderId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox3)->TryEmptyFolderAsync(*(void**)(&folderId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailboxEmptyFolderStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailboxCreateFolderResult>) consume_Windows_ApplicationModel_Email_IEmailMailbox3<D>::TryCreateFolderAsync(param::hstring const& parentFolderId, param::hstring const& name) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox3)->TryCreateFolderAsync(*(void**)(&parentFolderId), *(void**)(&name), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailboxCreateFolderResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailboxDeleteFolderStatus>) consume_Windows_ApplicationModel_Email_IEmailMailbox3<D>::TryDeleteFolderAsync(param::hstring const& folderId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox3)->TryDeleteFolderAsync(*(void**)(&folderId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailboxDeleteFolderStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailMailbox4<D>::RegisterSyncManagerAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox4)->RegisterSyncManagerAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxChangeTracker) consume_Windows_ApplicationModel_Email_IEmailMailbox5<D>::GetChangeTracker(param::hstring const& identity) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailbox5)->GetChangeTracker(*(void**)(&identity), &result));
        return winrt::Windows::ApplicationModel::Email::EmailMailboxChangeTracker{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxActionKind) consume_Windows_ApplicationModel_Email_IEmailMailboxAction<D>::Kind() const
    {
        winrt::Windows::ApplicationModel::Email::EmailMailboxActionKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAction)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_ApplicationModel_Email_IEmailMailboxAction<D>::ChangeNumber() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAction)->get_ChangeNumber(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReply<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReply)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReply<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReply)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReply<D>::Response() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReply)->get_Response(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReply<D>::Response(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReply)->put_Response(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::ResponseKind() const
    {
        winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_ResponseKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::ResponseKind(winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->put_ResponseKind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::StartTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_StartTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::StartTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->put_StartTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::EndTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_EndTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::EndTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->put_EndTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReply) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::InternalReply() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_InternalReply(&value));
        return winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReply{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReply) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::KnownExternalReply() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_KnownExternalReply(&value));
        return winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReply{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReply) consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::UnknownExternalReply() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_UnknownExternalReply(&value));
        return winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReply{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanForwardMeetings() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanForwardMeetings(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanGetAndSetExternalAutoReplies() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanGetAndSetExternalAutoReplies(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanGetAndSetInternalAutoReplies() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanGetAndSetInternalAutoReplies(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanUpdateMeetingResponses() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanUpdateMeetingResponses(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanServerSearchFolders() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanServerSearchFolders(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanServerSearchMailbox() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanServerSearchMailbox(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanProposeNewTimeForMeetings() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanProposeNewTimeForMeetings(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanSmartSend() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanSmartSend(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities2<D>::CanResolveRecipients() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities2)->get_CanResolveRecipients(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities2<D>::CanValidateCertificates() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities2)->get_CanValidateCertificates(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities2<D>::CanEmptyFolder() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities2)->get_CanEmptyFolder(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities2<D>::CanCreateFolder() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities2)->get_CanCreateFolder(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities2<D>::CanDeleteFolder() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities2)->get_CanDeleteFolder(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities2<D>::CanMoveFolder() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities2)->get_CanMoveFolder(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanForwardMeetings(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanForwardMeetings(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanGetAndSetExternalAutoReplies(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanGetAndSetExternalAutoReplies(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanGetAndSetInternalAutoReplies(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanGetAndSetInternalAutoReplies(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanUpdateMeetingResponses(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanUpdateMeetingResponses(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanServerSearchFolders(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanServerSearchFolders(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanServerSearchMailbox(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanServerSearchMailbox(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanProposeNewTimeForMeetings(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanProposeNewTimeForMeetings(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanSmartSend(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanSmartSend(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanResolveRecipients(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanResolveRecipients(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanValidateCertificates(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanValidateCertificates(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanEmptyFolder(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanEmptyFolder(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanCreateFolder(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanCreateFolder(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanDeleteFolder(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanDeleteFolder(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanMoveFolder(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanMoveFolder(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxChangeType) consume_Windows_ApplicationModel_Email_IEmailMailboxChange<D>::ChangeType() const
    {
        winrt::Windows::ApplicationModel::Email::EmailMailboxChangeType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxChange)->get_ChangeType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailMailboxAction>) consume_Windows_ApplicationModel_Email_IEmailMailboxChange<D>::MailboxActions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxChange)->get_MailboxActions(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailMailboxAction>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMessage) consume_Windows_ApplicationModel_Email_IEmailMailboxChange<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxChange)->get_Message(&value));
        return winrt::Windows::ApplicationModel::Email::EmailMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailFolder) consume_Windows_ApplicationModel_Email_IEmailMailboxChange<D>::Folder() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxChange)->get_Folder(&value));
        return winrt::Windows::ApplicationModel::Email::EmailFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxChangeReader<D>::AcceptChanges() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeReader)->AcceptChanges());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxChangeReader<D>::AcceptChangesThrough(winrt::Windows::ApplicationModel::Email::EmailMailboxChange const& lastChangeToAcknowledge) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeReader)->AcceptChangesThrough(*(void**)(&lastChangeToAcknowledge)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMailboxChange>>) consume_Windows_ApplicationModel_Email_IEmailMailboxChangeReader<D>::ReadBatchAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeReader)->ReadBatchAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMailboxChange>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxChangeTracker<D>::IsTracking() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeTracker)->get_IsTracking(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxChangeTracker<D>::Enable() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeTracker)->Enable());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxChangeReader) consume_Windows_ApplicationModel_Email_IEmailMailboxChangeTracker<D>::GetChangeReader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeTracker)->GetChangeReader(&value));
        return winrt::Windows::ApplicationModel::Email::EmailMailboxChangeReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxChangeTracker<D>::Reset() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeTracker)->Reset());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxChangedDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxChangedDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxChangedDeferral) consume_Windows_ApplicationModel_Email_IEmailMailboxChangedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxChangedEventArgs)->GetDeferral(&result));
        return winrt::Windows::ApplicationModel::Email::EmailMailboxChangedDeferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxCreateFolderStatus) consume_Windows_ApplicationModel_Email_IEmailMailboxCreateFolderResult<D>::Status() const
    {
        winrt::Windows::ApplicationModel::Email::EmailMailboxCreateFolderStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCreateFolderResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailFolder) consume_Windows_ApplicationModel_Email_IEmailMailboxCreateFolderResult<D>::Folder() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxCreateFolderResult)->get_Folder(&value));
        return winrt::Windows::ApplicationModel::Email::EmailFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation) consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies<D>::AllowedSmimeEncryptionAlgorithmNegotiation() const
    {
        winrt::Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies)->get_AllowedSmimeEncryptionAlgorithmNegotiation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies<D>::AllowSmimeSoftCertificates() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies)->get_AllowSmimeSoftCertificates(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::ApplicationModel::Email::EmailMailboxSmimeEncryptionAlgorithm>) consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies<D>::RequiredSmimeEncryptionAlgorithm() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies)->get_RequiredSmimeEncryptionAlgorithm(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::ApplicationModel::Email::EmailMailboxSmimeEncryptionAlgorithm>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::ApplicationModel::Email::EmailMailboxSmimeSigningAlgorithm>) consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies<D>::RequiredSmimeSigningAlgorithm() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies)->get_RequiredSmimeSigningAlgorithm(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::ApplicationModel::Email::EmailMailboxSmimeSigningAlgorithm>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies2<D>::MustEncryptSmimeMessages() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies2)->get_MustEncryptSmimeMessages(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies2<D>::MustSignSmimeMessages() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies2)->get_MustSignSmimeMessages(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies3<D>::AllowedSmimeEncryptionAlgorithmNegotiation(winrt::Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies3)->put_AllowedSmimeEncryptionAlgorithmNegotiation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies3<D>::AllowSmimeSoftCertificates(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies3)->put_AllowSmimeSoftCertificates(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies3<D>::RequiredSmimeEncryptionAlgorithm(winrt::Windows::Foundation::IReference<winrt::Windows::ApplicationModel::Email::EmailMailboxSmimeEncryptionAlgorithm> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies3)->put_RequiredSmimeEncryptionAlgorithm(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies3<D>::RequiredSmimeSigningAlgorithm(winrt::Windows::Foundation::IReference<winrt::Windows::ApplicationModel::Email::EmailMailboxSmimeSigningAlgorithm> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies3)->put_RequiredSmimeSigningAlgorithm(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies3<D>::MustEncryptSmimeMessages(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies3)->put_MustEncryptSmimeMessages(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies3<D>::MustSignSmimeMessages(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies3)->put_MustSignSmimeMessages(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMailboxSyncStatus) consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::Status() const
    {
        winrt::Windows::ApplicationModel::Email::EmailMailboxSyncStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::LastSuccessfulSyncTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager)->get_LastSuccessfulSyncTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::LastAttemptedSyncTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager)->get_LastAttemptedSyncTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::SyncAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager)->SyncAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::SyncStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::EmailMailboxSyncManager, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager)->add_SyncStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::SyncStatusChanged_revoker consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::SyncStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::EmailMailboxSyncManager, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SyncStatusChanged_revoker>(this, SyncStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::SyncStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager)->remove_SyncStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager2<D>::Status(winrt::Windows::ApplicationModel::Email::EmailMailboxSyncStatus const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager2)->put_Status(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager2<D>::LastSuccessfulSyncTime(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager2)->put_LastSuccessfulSyncTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager2<D>::LastAttemptedSyncTime(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager2)->put_LastAttemptedSyncTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailManagerForUser<D>::ShowComposeNewEmailAsync(winrt::Windows::ApplicationModel::Email::EmailMessage const& message) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailManagerForUser)->ShowComposeNewEmailAsync(*(void**)(&message), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailStore>) consume_Windows_ApplicationModel_Email_IEmailManagerForUser<D>::RequestStoreAsync(winrt::Windows::ApplicationModel::Email::EmailStoreAccessType const& accessType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailManagerForUser)->RequestStoreAsync(static_cast<int32_t>(accessType), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailStore>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_ApplicationModel_Email_IEmailManagerForUser<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailManagerForUser)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Email_IEmailManagerStatics<D>::ShowComposeNewEmailAsync(winrt::Windows::ApplicationModel::Email::EmailMessage const& message) const
    {
        void* asyncAction{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailManagerStatics)->ShowComposeNewEmailAsync(*(void**)(&message), &asyncAction));
        return winrt::Windows::Foundation::IAsyncAction{ asyncAction, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailStore>) consume_Windows_ApplicationModel_Email_IEmailManagerStatics2<D>::RequestStoreAsync(winrt::Windows::ApplicationModel::Email::EmailStoreAccessType const& accessType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailManagerStatics2)->RequestStoreAsync(static_cast<int32_t>(accessType), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailStore>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailManagerForUser) consume_Windows_ApplicationModel_Email_IEmailManagerStatics3<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailManagerStatics3)->GetForUser(*(void**)(&user), &result));
        return winrt::Windows::ApplicationModel::Email::EmailManagerForUser{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::AllowNewTimeProposal() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_AllowNewTimeProposal(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::AllowNewTimeProposal(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_AllowNewTimeProposal(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::AppointmentRoamingId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_AppointmentRoamingId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::AppointmentRoamingId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_AppointmentRoamingId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::AppointmentOriginalStartTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_AppointmentOriginalStartTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::AppointmentOriginalStartTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_AppointmentOriginalStartTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::Duration(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_Duration(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::IsAllDay() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_IsAllDay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::IsAllDay(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_IsAllDay(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::IsResponseRequested() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_IsResponseRequested(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::IsResponseRequested(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_IsResponseRequested(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::Location() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_Location(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::Location(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_Location(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::ProposedStartTime() const
    {
        void* proposedStartTime{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_ProposedStartTime(&proposedStartTime));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ proposedStartTime, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::ProposedStartTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& proposedStartTime) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_ProposedStartTime(*(void**)(&proposedStartTime)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::ProposedDuration() const
    {
        void* duration{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_ProposedDuration(&duration));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ duration, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::ProposedDuration(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& duration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_ProposedDuration(*(void**)(&duration)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::RecurrenceStartTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_RecurrenceStartTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::RecurrenceStartTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_RecurrenceStartTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Appointments::AppointmentRecurrence) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::Recurrence() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_Recurrence(&value));
        return winrt::Windows::ApplicationModel::Appointments::AppointmentRecurrence{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::Recurrence(winrt::Windows::ApplicationModel::Appointments::AppointmentRecurrence const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_Recurrence(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::RemoteChangeNumber() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_RemoteChangeNumber(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::RemoteChangeNumber(uint64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_RemoteChangeNumber(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::StartTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_StartTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::StartTime(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_StartTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMeetingInfo2<D>::IsReportedOutOfDateByServer() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo2)->get_IsReportedOutOfDateByServer(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMessage<D>::Subject() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage)->get_Subject(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage<D>::Subject(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage)->put_Subject(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMessage<D>::Body() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage)->get_Body(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage<D>::Body(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage)->put_Body(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailRecipient>) consume_Windows_ApplicationModel_Email_IEmailMessage<D>::To() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage)->get_To(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailRecipient>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailRecipient>) consume_Windows_ApplicationModel_Email_IEmailMessage<D>::CC() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage)->get_CC(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailRecipient>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailRecipient>) consume_Windows_ApplicationModel_Email_IEmailMessage<D>::Bcc() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage)->get_Bcc(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailRecipient>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailAttachment>) consume_Windows_ApplicationModel_Email_IEmailMessage<D>::Attachments() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage)->get_Attachments(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailAttachment>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::RemoteId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_RemoteId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::RemoteId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_RemoteId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::MailboxId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_MailboxId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::ConversationId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_ConversationId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::FolderId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_FolderId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::AllowInternetImages() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_AllowInternetImages(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::AllowInternetImages(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_AllowInternetImages(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::ChangeNumber() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_ChangeNumber(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMessageDownloadState) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::DownloadState() const
    {
        winrt::Windows::ApplicationModel::Email::EmailMessageDownloadState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_DownloadState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::DownloadState(winrt::Windows::ApplicationModel::Email::EmailMessageDownloadState const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_DownloadState(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::EstimatedDownloadSizeInBytes() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_EstimatedDownloadSizeInBytes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::EstimatedDownloadSizeInBytes(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_EstimatedDownloadSizeInBytes(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailFlagState) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::FlagState() const
    {
        winrt::Windows::ApplicationModel::Email::EmailFlagState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_FlagState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::FlagState(winrt::Windows::ApplicationModel::Email::EmailFlagState const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_FlagState(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::HasPartialBodies() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_HasPartialBodies(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailImportance) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Importance() const
    {
        winrt::Windows::ApplicationModel::Email::EmailImportance value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_Importance(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Importance(winrt::Windows::ApplicationModel::Email::EmailImportance const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_Importance(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::InResponseToMessageId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_InResponseToMessageId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailIrmInfo) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IrmInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_IrmInfo(&value));
        return winrt::Windows::ApplicationModel::Email::EmailIrmInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IrmInfo(winrt::Windows::ApplicationModel::Email::EmailIrmInfo const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_IrmInfo(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsDraftMessage() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_IsDraftMessage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsRead() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_IsRead(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsRead(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_IsRead(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsSeen() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_IsSeen(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsSeen(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_IsSeen(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsServerSearchMessage() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_IsServerSearchMessage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsSmartSendable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_IsSmartSendable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::MessageClass() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_MessageClass(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::MessageClass(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_MessageClass(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::NormalizedSubject() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_NormalizedSubject(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::OriginalCodePage() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_OriginalCodePage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::OriginalCodePage(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_OriginalCodePage(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Preview() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_Preview(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Preview(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_Preview(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMessageResponseKind) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::LastResponseKind() const
    {
        winrt::Windows::ApplicationModel::Email::EmailMessageResponseKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_LastResponseKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::LastResponseKind(winrt::Windows::ApplicationModel::Email::EmailMessageResponseKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_LastResponseKind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailRecipient) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Sender() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_Sender(&value));
        return winrt::Windows::ApplicationModel::Email::EmailRecipient{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Sender(winrt::Windows::ApplicationModel::Email::EmailRecipient const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_Sender(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::SentTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_SentTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::SentTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_SentTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMeetingInfo) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::MeetingInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->get_MeetingInfo(&value));
        return winrt::Windows::ApplicationModel::Email::EmailMeetingInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::MeetingInfo(winrt::Windows::ApplicationModel::Email::EmailMeetingInfo const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->put_MeetingInfo(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::GetBodyStream(winrt::Windows::ApplicationModel::Email::EmailMessageBodyKind const& type) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->GetBodyStream(static_cast<int32_t>(type), &result));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::SetBodyStream(winrt::Windows::ApplicationModel::Email::EmailMessageBodyKind const& type, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& stream) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage2)->SetBodyStream(static_cast<int32_t>(type), *(void**)(&stream)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Email_IEmailMessage3<D>::SmimeData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage3)->get_SmimeData(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage3<D>::SmimeData(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage3)->put_SmimeData(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMessageSmimeKind) consume_Windows_ApplicationModel_Email_IEmailMessage3<D>::SmimeKind() const
    {
        winrt::Windows::ApplicationModel::Email::EmailMessageSmimeKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage3)->get_SmimeKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage3<D>::SmimeKind(winrt::Windows::ApplicationModel::Email::EmailMessageSmimeKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage3)->put_SmimeKind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailRecipient>) consume_Windows_ApplicationModel_Email_IEmailMessage4<D>::ReplyTo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage4)->get_ReplyTo(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailRecipient>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailRecipient) consume_Windows_ApplicationModel_Email_IEmailMessage4<D>::SentRepresenting() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage4)->get_SentRepresenting(&value));
        return winrt::Windows::ApplicationModel::Email::EmailRecipient{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailMessage4<D>::SentRepresenting(winrt::Windows::ApplicationModel::Email::EmailRecipient const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessage4)->put_SentRepresenting(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMessage>) consume_Windows_ApplicationModel_Email_IEmailMessageBatch<D>::Messages() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessageBatch)->get_Messages(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMessage>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailBatchStatus) consume_Windows_ApplicationModel_Email_IEmailMessageBatch<D>::Status() const
    {
        winrt::Windows::ApplicationModel::Email::EmailBatchStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessageBatch)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessageBatch>) consume_Windows_ApplicationModel_Email_IEmailMessageReader<D>::ReadBatchAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailMessageReader)->ReadBatchAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessageBatch>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailQueryTextSearch) consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::TextSearch() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryOptions)->get_TextSearch(&value));
        return winrt::Windows::ApplicationModel::Email::EmailQueryTextSearch{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailQuerySortDirection) consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::SortDirection() const
    {
        winrt::Windows::ApplicationModel::Email::EmailQuerySortDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryOptions)->get_SortDirection(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::SortDirection(winrt::Windows::ApplicationModel::Email::EmailQuerySortDirection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryOptions)->put_SortDirection(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailQuerySortProperty) consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::SortProperty() const
    {
        winrt::Windows::ApplicationModel::Email::EmailQuerySortProperty value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryOptions)->get_SortProperty(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::SortProperty(winrt::Windows::ApplicationModel::Email::EmailQuerySortProperty const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryOptions)->put_SortProperty(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailQueryKind) consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::Kind() const
    {
        winrt::Windows::ApplicationModel::Email::EmailQueryKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryOptions)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::Kind(winrt::Windows::ApplicationModel::Email::EmailQueryKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryOptions)->put_Kind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::FolderIds() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryOptions)->get_FolderIds(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailQueryOptions) consume_Windows_ApplicationModel_Email_IEmailQueryOptionsFactory<D>::CreateWithText(param::hstring const& text) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryOptionsFactory)->CreateWithText(*(void**)(&text), &result));
        return winrt::Windows::ApplicationModel::Email::EmailQueryOptions{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailQueryOptions) consume_Windows_ApplicationModel_Email_IEmailQueryOptionsFactory<D>::CreateWithTextAndFields(param::hstring const& text, winrt::Windows::ApplicationModel::Email::EmailQuerySearchFields const& fields) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryOptionsFactory)->CreateWithTextAndFields(*(void**)(&text), static_cast<uint32_t>(fields), &result));
        return winrt::Windows::ApplicationModel::Email::EmailQueryOptions{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailQuerySearchFields) consume_Windows_ApplicationModel_Email_IEmailQueryTextSearch<D>::Fields() const
    {
        winrt::Windows::ApplicationModel::Email::EmailQuerySearchFields value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryTextSearch)->get_Fields(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailQueryTextSearch<D>::Fields(winrt::Windows::ApplicationModel::Email::EmailQuerySearchFields const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryTextSearch)->put_Fields(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailQuerySearchScope) consume_Windows_ApplicationModel_Email_IEmailQueryTextSearch<D>::SearchScope() const
    {
        winrt::Windows::ApplicationModel::Email::EmailQuerySearchScope value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryTextSearch)->get_SearchScope(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailQueryTextSearch<D>::SearchScope(winrt::Windows::ApplicationModel::Email::EmailQuerySearchScope const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryTextSearch)->put_SearchScope(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailQueryTextSearch<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryTextSearch)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailQueryTextSearch<D>::Text(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailQueryTextSearch)->put_Text(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailRecipient<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailRecipient)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailRecipient<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailRecipient)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Email_IEmailRecipient<D>::Address() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailRecipient)->get_Address(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailRecipient<D>::Address(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailRecipient)->put_Address(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailRecipient) consume_Windows_ApplicationModel_Email_IEmailRecipientFactory<D>::Create(param::hstring const& address) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailRecipientFactory)->Create(*(void**)(&address), &result));
        return winrt::Windows::ApplicationModel::Email::EmailRecipient{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailRecipient) consume_Windows_ApplicationModel_Email_IEmailRecipientFactory<D>::CreateWithName(param::hstring const& address, param::hstring const& name) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailRecipientFactory)->CreateWithName(*(void**)(&address), *(void**)(&name), &result));
        return winrt::Windows::ApplicationModel::Email::EmailRecipient{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailRecipientResolutionStatus) consume_Windows_ApplicationModel_Email_IEmailRecipientResolutionResult<D>::Status() const
    {
        winrt::Windows::ApplicationModel::Email::EmailRecipientResolutionStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>) consume_Windows_ApplicationModel_Email_IEmailRecipientResolutionResult<D>::PublicKeys() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult)->get_PublicKeys(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailRecipientResolutionResult2<D>::Status(winrt::Windows::ApplicationModel::Email::EmailRecipientResolutionStatus const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult2)->put_Status(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Email_IEmailRecipientResolutionResult2<D>::SetPublicKeys(param::iterable<winrt::Windows::Security::Cryptography::Certificates::Certificate> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult2)->SetPublicKeys(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMailbox>>) consume_Windows_ApplicationModel_Email_IEmailStore<D>::FindMailboxesAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailStore)->FindMailboxesAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMailbox>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailConversationReader) consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetConversationReader() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailStore)->GetConversationReader(&result));
        return winrt::Windows::ApplicationModel::Email::EmailConversationReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailConversationReader) consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetConversationReader(winrt::Windows::ApplicationModel::Email::EmailQueryOptions const& options) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailStore)->GetConversationReaderWithOptions(*(void**)(&options), &result));
        return winrt::Windows::ApplicationModel::Email::EmailConversationReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMessageReader) consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetMessageReader() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailStore)->GetMessageReader(&result));
        return winrt::Windows::ApplicationModel::Email::EmailMessageReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Email::EmailMessageReader) consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetMessageReader(winrt::Windows::ApplicationModel::Email::EmailQueryOptions const& options) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailStore)->GetMessageReaderWithOptions(*(void**)(&options), &result));
        return winrt::Windows::ApplicationModel::Email::EmailMessageReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailbox>) consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetMailboxAsync(param::hstring const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailStore)->GetMailboxAsync(*(void**)(&id), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailbox>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailConversation>) consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetConversationAsync(param::hstring const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailStore)->GetConversationAsync(*(void**)(&id), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailConversation>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailFolder>) consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetFolderAsync(param::hstring const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailStore)->GetFolderAsync(*(void**)(&id), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailFolder>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessage>) consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetMessageAsync(param::hstring const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailStore)->GetMessageAsync(*(void**)(&id), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessage>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailbox>) consume_Windows_ApplicationModel_Email_IEmailStore<D>::CreateMailboxAsync(param::hstring const& accountName, param::hstring const& accountAddress) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailStore)->CreateMailboxAsync(*(void**)(&accountName), *(void**)(&accountAddress), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailbox>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailbox>) consume_Windows_ApplicationModel_Email_IEmailStore<D>::CreateMailboxAsync(param::hstring const& accountName, param::hstring const& accountAddress, param::hstring const& userDataAccountId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Email::IEmailStore)->CreateMailboxInAccountAsync(*(void**)(&accountName), *(void**)(&accountAddress), *(void**)(&userDataAccountId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailbox>{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailAttachment> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailAttachment>
    {
        int32_t __stdcall get_FileName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FileName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FileName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FileName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Data(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Data(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailAttachment2> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailAttachment2>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContentId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentLocation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContentLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentLocation(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentLocation(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DownloadState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailAttachmentDownloadState>(this->shim().DownloadState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DownloadState(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DownloadState(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailAttachmentDownloadState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EstimatedDownloadSizeInBytes(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().EstimatedDownloadSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EstimatedDownloadSizeInBytes(uint64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EstimatedDownloadSizeInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsFromBaseMessage(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsFromBaseMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInline(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInline());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsInline(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsInline(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MimeType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MimeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MimeType(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MimeType(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailAttachmentFactory> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailAttachmentFactory>
    {
        int32_t __stdcall Create(void* fileName, void* data, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailAttachment>(this->shim().Create(*reinterpret_cast<hstring const*>(&fileName), *reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailAttachmentFactory2> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailAttachmentFactory2>
    {
        int32_t __stdcall Create(void* fileName, void* data, void* mimeType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailAttachment>(this->shim().Create(*reinterpret_cast<hstring const*>(&fileName), *reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&data), *reinterpret_cast<hstring const*>(&mimeType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailConversation> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailConversation>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MailboxId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FlagState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailFlagState>(this->shim().FlagState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasAttachment(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasAttachment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Importance(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailImportance>(this->shim().Importance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastEmailResponseKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMessageResponseKind>(this->shim().LastEmailResponseKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MessageCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MessageCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MostRecentMessageId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MostRecentMessageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MostRecentMessageTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().MostRecentMessageTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Preview(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Preview());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LatestSender(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailRecipient>(this->shim().LatestSender());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Subject(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Subject());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UnreadMessageCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UnreadMessageCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindMessagesAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMessage>>>(this->shim().FindMessagesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindMessagesWithCountAsync(uint32_t count, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMessage>>>(this->shim().FindMessagesAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailConversationBatch> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailConversationBatch>
    {
        int32_t __stdcall get_Conversations(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailConversation>>(this->shim().Conversations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailBatchStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailConversationReader> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailConversationReader>
    {
        int32_t __stdcall ReadBatchAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailConversationBatch>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailFolder> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailFolder>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemoteId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RemoteId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoteId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MailboxId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ParentFolderId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ParentFolderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSyncEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSyncEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsSyncEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsSyncEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastSuccessfulSyncTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().LastSuccessfulSyncTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LastSuccessfulSyncTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LastSuccessfulSyncTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailSpecialFolderKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFolderAsync(void* name, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailFolder>>(this->shim().CreateFolderAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindChildFoldersAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailFolder>>>(this->shim().FindChildFoldersAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversationReader(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailConversationReader>(this->shim().GetConversationReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversationReaderWithOptions(void* options, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailConversationReader>(this->shim().GetConversationReader(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageAsync(void* id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessage>>(this->shim().GetMessageAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageReader(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailMessageReader>(this->shim().GetMessageReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageReaderWithOptions(void* options, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailMessageReader>(this->shim().GetMessageReader(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageCountsAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailItemCounts>>(this->shim().GetMessageCountsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryMoveAsync(void* newParentFolder, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryMoveAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailFolder const*>(&newParentFolder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryMoveWithNewNameAsync(void* newParentFolder, void* newFolderName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryMoveAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailFolder const*>(&newParentFolder), *reinterpret_cast<hstring const*>(&newFolderName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySaveAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SaveMessageAsync(void* message, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SaveMessageAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailIrmInfo> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailIrmInfo>
    {
        int32_t __stdcall get_CanEdit(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanEdit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanEdit(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanEdit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanExtractData(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanExtractData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanExtractData(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanExtractData(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanForward(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanForward());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanForward(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanForward(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanModifyRecipientsOnResponse(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanModifyRecipientsOnResponse());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanModifyRecipientsOnResponse(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanModifyRecipientsOnResponse(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanPrintData(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanPrintData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanPrintData(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanPrintData(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanRemoveIrmOnResponse(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanRemoveIrmOnResponse());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanRemoveIrmOnResponse(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanRemoveIrmOnResponse(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanReply(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanReply());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanReply(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanReply(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanReplyAll(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanReplyAll());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanReplyAll(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanReplyAll(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationDate(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExpirationDate(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExpirationDate(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsIrmOriginator(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsIrmOriginator());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsIrmOriginator(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsIrmOriginator(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsProgramaticAccessAllowed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsProgramaticAccessAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsProgramaticAccessAllowed(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsProgramaticAccessAllowed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Template(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailIrmTemplate>(this->shim().Template());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Template(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Template(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailIrmTemplate const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailIrmInfoFactory> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailIrmInfoFactory>
    {
        int32_t __stdcall Create(int64_t expiration, void* irmTemplate, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailIrmInfo>(this->shim().Create(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&expiration), *reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailIrmTemplate const*>(&irmTemplate)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailIrmTemplate> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailIrmTemplate>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Id(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Description(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Name(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailIrmTemplateFactory> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailIrmTemplateFactory>
    {
        int32_t __stdcall Create(void* id, void* name, void* description, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailIrmTemplate>(this->shim().Create(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&description)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailItemCounts> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailItemCounts>
    {
        int32_t __stdcall get_Flagged(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Flagged());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Important(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Important());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Total(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Total());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Unread(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Unread());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailbox> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailbox>
    {
        int32_t __stdcall get_Capabilities(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChangeTracker(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxChangeTracker>(this->shim().ChangeTracker());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOwnedByCurrentApp(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOwnedByCurrentApp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDataEncryptedUnderLock(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDataEncryptedUnderLock());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MailAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MailAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MailAddress(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MailAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MailAddressAliases(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().MailAddressAliases());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OtherAppReadAccess(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess>(this->shim().OtherAppReadAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OtherAppReadAccess(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OtherAppReadAccess(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OtherAppWriteAccess(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess>(this->shim().OtherAppWriteAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OtherAppWriteAccess(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OtherAppWriteAccess(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Policies(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxPolicies>(this->shim().Policies());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceDisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SourceDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SyncManager(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxSyncManager>(this->shim().SyncManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserDataAccountId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UserDataAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversationReader(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailConversationReader>(this->shim().GetConversationReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversationReaderWithOptions(void* options, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailConversationReader>(this->shim().GetConversationReader(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageReader(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailMessageReader>(this->shim().GetMessageReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageReaderWithOptions(void* options, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailMessageReader>(this->shim().GetMessageReader(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversationAsync(void* id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailConversation>>(this->shim().GetConversationAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFolderAsync(void* id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailFolder>>(this->shim().GetFolderAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageAsync(void* id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessage>>(this->shim().GetMessageAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSpecialFolderAsync(int32_t folderType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailFolder>>(this->shim().GetSpecialFolderAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailSpecialFolderKind const*>(&folderType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SaveAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MarkMessageAsSeenAsync(void* messageId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MarkMessageAsSeenAsync(*reinterpret_cast<hstring const*>(&messageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MarkFolderAsSeenAsync(void* folderId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MarkFolderAsSeenAsync(*reinterpret_cast<hstring const*>(&folderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MarkMessageReadAsync(void* messageId, bool isRead, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MarkMessageReadAsync(*reinterpret_cast<hstring const*>(&messageId), isRead));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ChangeMessageFlagStateAsync(void* messageId, int32_t flagState, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ChangeMessageFlagStateAsync(*reinterpret_cast<hstring const*>(&messageId), *reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailFlagState const*>(&flagState)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryMoveMessageAsync(void* messageId, void* newParentFolderId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryMoveMessageAsync(*reinterpret_cast<hstring const*>(&messageId), *reinterpret_cast<hstring const*>(&newParentFolderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryMoveFolderAsync(void* folderId, void* newParentFolderId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryMoveFolderAsync(*reinterpret_cast<hstring const*>(&folderId), *reinterpret_cast<hstring const*>(&newParentFolderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryMoveFolderWithNewNameAsync(void* folderId, void* newParentFolderId, void* newFolderName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryMoveFolderAsync(*reinterpret_cast<hstring const*>(&folderId), *reinterpret_cast<hstring const*>(&newParentFolderId), *reinterpret_cast<hstring const*>(&newFolderName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteMessageAsync(void* messageId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteMessageAsync(*reinterpret_cast<hstring const*>(&messageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MarkFolderSyncEnabledAsync(void* folderId, bool isSyncEnabled, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MarkFolderSyncEnabledAsync(*reinterpret_cast<hstring const*>(&folderId), isSyncEnabled));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendMessageAsync(void* message, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SendMessageAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SaveDraftAsync(void* message, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SaveDraftAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DownloadMessageAsync(void* messageId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DownloadMessageAsync(*reinterpret_cast<hstring const*>(&messageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DownloadAttachmentAsync(void* attachmentId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DownloadAttachmentAsync(*reinterpret_cast<hstring const*>(&attachmentId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateResponseMessageAsync(void* messageId, int32_t responseType, void* subject, int32_t responseHeaderType, void* responseHeader, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessage>>(this->shim().CreateResponseMessageAsync(*reinterpret_cast<hstring const*>(&messageId), *reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessageResponseKind const*>(&responseType), *reinterpret_cast<hstring const*>(&subject), *reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessageBodyKind const*>(&responseHeaderType), *reinterpret_cast<hstring const*>(&responseHeader)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryUpdateMeetingResponseAsync(void* meeting, int32_t response, void* subject, void* comment, bool sendUpdate, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryUpdateMeetingResponseAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessage const*>(&meeting), *reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMeetingResponseType const*>(&response), *reinterpret_cast<hstring const*>(&subject), *reinterpret_cast<hstring const*>(&comment), sendUpdate));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryForwardMeetingAsync(void* meeting, void* recipients, void* subject, int32_t forwardHeaderType, void* forwardHeader, void* comment, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryForwardMeetingAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessage const*>(&meeting), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Email::EmailRecipient> const*>(&recipients), *reinterpret_cast<hstring const*>(&subject), *reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessageBodyKind const*>(&forwardHeaderType), *reinterpret_cast<hstring const*>(&forwardHeader), *reinterpret_cast<hstring const*>(&comment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryProposeNewTimeForMeetingAsync(void* meeting, int64_t newStartTime, int64_t newDuration, void* subject, void* comment, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryProposeNewTimeForMeetingAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessage const*>(&meeting), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&newStartTime), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&newDuration), *reinterpret_cast<hstring const*>(&subject), *reinterpret_cast<hstring const*>(&comment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_MailboxChanged(void* pHandler, winrt::event_token* pToken) noexcept final try
        {
            zero_abi<winrt::event_token>(pToken);
            typename D::abi_guard guard(this->shim());
            *pToken = detach_from<winrt::event_token>(this->shim().MailboxChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::EmailMailbox, winrt::Windows::ApplicationModel::Email::EmailMailboxChangedEventArgs> const*>(&pHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MailboxChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MailboxChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall SmartSendMessageAsync(void* message, bool smartSend, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SendMessageAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessage const*>(&message), smartSend));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySetAutoReplySettingsAsync(void* autoReplySettings, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetAutoReplySettingsAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings const*>(&autoReplySettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetAutoReplySettingsAsync(int32_t requestedFormat, void** autoReplySettings) noexcept final try
        {
            clear_abi(autoReplySettings);
            typename D::abi_guard guard(this->shim());
            *autoReplySettings = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings>>(this->shim().TryGetAutoReplySettingsAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind const*>(&requestedFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailbox2> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailbox2>
    {
        int32_t __stdcall get_LinkedMailboxId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LinkedMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NetworkAccountId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NetworkAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NetworkId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NetworkId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailbox3> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailbox3>
    {
        int32_t __stdcall ResolveRecipientsAsync(void* recipients, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailRecipientResolutionResult>>>(this->shim().ResolveRecipientsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&recipients)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ValidateCertificatesAsync(void* certificates, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailCertificateValidationStatus>>>(this->shim().ValidateCertificatesAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Security::Cryptography::Certificates::Certificate> const*>(&certificates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryEmptyFolderAsync(void* folderId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailboxEmptyFolderStatus>>(this->shim().TryEmptyFolderAsync(*reinterpret_cast<hstring const*>(&folderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCreateFolderAsync(void* parentFolderId, void* name, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailboxCreateFolderResult>>(this->shim().TryCreateFolderAsync(*reinterpret_cast<hstring const*>(&parentFolderId), *reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryDeleteFolderAsync(void* folderId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailboxDeleteFolderStatus>>(this->shim().TryDeleteFolderAsync(*reinterpret_cast<hstring const*>(&folderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailbox4> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailbox4>
    {
        int32_t __stdcall RegisterSyncManagerAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RegisterSyncManagerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailbox5> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailbox5>
    {
        int32_t __stdcall GetChangeTracker(void* identity, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxChangeTracker>(this->shim().GetChangeTracker(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxAction> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxAction>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxActionKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChangeNumber(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().ChangeNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReply> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReply>
    {
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Response(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Response());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Response(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Response(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings>
    {
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResponseKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind>(this->shim().ResponseKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ResponseKind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResponseKind(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StartTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StartTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EndTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().EndTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EndTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EndTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InternalReply(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReply>(this->shim().InternalReply());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KnownExternalReply(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReply>(this->shim().KnownExternalReply());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UnknownExternalReply(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReply>(this->shim().UnknownExternalReply());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities>
    {
        int32_t __stdcall get_CanForwardMeetings(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanForwardMeetings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanGetAndSetExternalAutoReplies(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanGetAndSetExternalAutoReplies());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanGetAndSetInternalAutoReplies(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanGetAndSetInternalAutoReplies());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanUpdateMeetingResponses(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanUpdateMeetingResponses());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanServerSearchFolders(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanServerSearchFolders());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanServerSearchMailbox(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanServerSearchMailbox());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanProposeNewTimeForMeetings(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanProposeNewTimeForMeetings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanSmartSend(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanSmartSend());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities2> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities2>
    {
        int32_t __stdcall get_CanResolveRecipients(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanResolveRecipients());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanValidateCertificates(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanValidateCertificates());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanEmptyFolder(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanEmptyFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanCreateFolder(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanCreateFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanDeleteFolder(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanDeleteFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanMoveFolder(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanMoveFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3>
    {
        int32_t __stdcall put_CanForwardMeetings(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanForwardMeetings(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanGetAndSetExternalAutoReplies(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanGetAndSetExternalAutoReplies(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanGetAndSetInternalAutoReplies(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanGetAndSetInternalAutoReplies(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanUpdateMeetingResponses(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanUpdateMeetingResponses(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanServerSearchFolders(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanServerSearchFolders(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanServerSearchMailbox(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanServerSearchMailbox(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanProposeNewTimeForMeetings(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanProposeNewTimeForMeetings(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanSmartSend(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanSmartSend(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanResolveRecipients(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanResolveRecipients(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanValidateCertificates(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanValidateCertificates(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanEmptyFolder(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanEmptyFolder(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanCreateFolder(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanCreateFolder(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanDeleteFolder(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanDeleteFolder(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanMoveFolder(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanMoveFolder(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxChange> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxChange>
    {
        int32_t __stdcall get_ChangeType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxChangeType>(this->shim().ChangeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MailboxActions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailMailboxAction>>(this->shim().MailboxActions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Folder(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailFolder>(this->shim().Folder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeReader> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeReader>
    {
        int32_t __stdcall AcceptChanges() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AcceptChanges();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AcceptChangesThrough(void* lastChangeToAcknowledge) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AcceptChangesThrough(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMailboxChange const*>(&lastChangeToAcknowledge));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadBatchAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMailboxChange>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeTracker> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeTracker>
    {
        int32_t __stdcall get_IsTracking(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTracking());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Enable() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Enable();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetChangeReader(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxChangeReader>(this->shim().GetChangeReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Reset() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Reset();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxChangedDeferral> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxChangedDeferral>
    {
        int32_t __stdcall Complete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxChangedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxChangedEventArgs>
    {
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxChangedDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxCreateFolderResult> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxCreateFolderResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxCreateFolderStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Folder(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailFolder>(this->shim().Folder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies>
    {
        int32_t __stdcall get_AllowedSmimeEncryptionAlgorithmNegotiation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation>(this->shim().AllowedSmimeEncryptionAlgorithmNegotiation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowSmimeSoftCertificates(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowSmimeSoftCertificates());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequiredSmimeEncryptionAlgorithm(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::ApplicationModel::Email::EmailMailboxSmimeEncryptionAlgorithm>>(this->shim().RequiredSmimeEncryptionAlgorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequiredSmimeSigningAlgorithm(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::ApplicationModel::Email::EmailMailboxSmimeSigningAlgorithm>>(this->shim().RequiredSmimeSigningAlgorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies2> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies2>
    {
        int32_t __stdcall get_MustEncryptSmimeMessages(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().MustEncryptSmimeMessages());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MustSignSmimeMessages(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().MustSignSmimeMessages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies3> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies3>
    {
        int32_t __stdcall put_AllowedSmimeEncryptionAlgorithmNegotiation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowedSmimeEncryptionAlgorithmNegotiation(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowSmimeSoftCertificates(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowSmimeSoftCertificates(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RequiredSmimeEncryptionAlgorithm(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequiredSmimeEncryptionAlgorithm(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::ApplicationModel::Email::EmailMailboxSmimeEncryptionAlgorithm> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RequiredSmimeSigningAlgorithm(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequiredSmimeSigningAlgorithm(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::ApplicationModel::Email::EmailMailboxSmimeSigningAlgorithm> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MustEncryptSmimeMessages(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MustEncryptSmimeMessages(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MustSignSmimeMessages(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MustSignSmimeMessages(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMailboxSyncStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastSuccessfulSyncTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().LastSuccessfulSyncTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastAttemptedSyncTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().LastAttemptedSyncTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SyncAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().SyncAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SyncStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SyncStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Email::EmailMailboxSyncManager, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SyncStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SyncStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager2> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager2>
    {
        int32_t __stdcall put_Status(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Status(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMailboxSyncStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LastSuccessfulSyncTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LastSuccessfulSyncTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LastAttemptedSyncTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LastAttemptedSyncTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailManagerForUser> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailManagerForUser>
    {
        int32_t __stdcall ShowComposeNewEmailAsync(void* message, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ShowComposeNewEmailAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestStoreAsync(int32_t accessType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailStore>>(this->shim().RequestStoreAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailStoreAccessType const*>(&accessType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailManagerStatics>
    {
        int32_t __stdcall ShowComposeNewEmailAsync(void* message, void** asyncAction) noexcept final try
        {
            clear_abi(asyncAction);
            typename D::abi_guard guard(this->shim());
            *asyncAction = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ShowComposeNewEmailAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailManagerStatics2> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailManagerStatics2>
    {
        int32_t __stdcall RequestStoreAsync(int32_t accessType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailStore>>(this->shim().RequestStoreAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailStoreAccessType const*>(&accessType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailManagerStatics3> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailManagerStatics3>
    {
        int32_t __stdcall GetForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailManagerForUser>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo>
    {
        int32_t __stdcall get_AllowNewTimeProposal(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowNewTimeProposal());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowNewTimeProposal(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowNewTimeProposal(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppointmentRoamingId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppointmentRoamingId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AppointmentRoamingId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppointmentRoamingId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppointmentOriginalStartTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().AppointmentOriginalStartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AppointmentOriginalStartTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppointmentOriginalStartTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Duration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Duration(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Duration(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAllDay(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAllDay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAllDay(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAllDay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsResponseRequested(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsResponseRequested());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsResponseRequested(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsResponseRequested(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Location(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Location(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Location(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProposedStartTime(void** proposedStartTime) noexcept final try
        {
            clear_abi(proposedStartTime);
            typename D::abi_guard guard(this->shim());
            *proposedStartTime = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ProposedStartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProposedStartTime(void* proposedStartTime) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProposedStartTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&proposedStartTime));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProposedDuration(void** duration) noexcept final try
        {
            clear_abi(duration);
            typename D::abi_guard guard(this->shim());
            *duration = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().ProposedDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProposedDuration(void* duration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProposedDuration(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&duration));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecurrenceStartTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().RecurrenceStartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RecurrenceStartTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RecurrenceStartTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Recurrence(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Appointments::AppointmentRecurrence>(this->shim().Recurrence());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Recurrence(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Recurrence(*reinterpret_cast<winrt::Windows::ApplicationModel::Appointments::AppointmentRecurrence const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteChangeNumber(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().RemoteChangeNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RemoteChangeNumber(uint64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoteChangeNumber(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StartTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StartTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo2> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo2>
    {
        int32_t __stdcall get_IsReportedOutOfDateByServer(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReportedOutOfDateByServer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMessage> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMessage>
    {
        int32_t __stdcall get_Subject(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Subject());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Subject(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Subject(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Body(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Body());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Body(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Body(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_To(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailRecipient>>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CC(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailRecipient>>(this->shim().CC());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bcc(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailRecipient>>(this->shim().Bcc());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Attachments(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailAttachment>>(this->shim().Attachments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMessage2> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMessage2>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemoteId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RemoteId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoteId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MailboxId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConversationId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ConversationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FolderId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FolderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowInternetImages(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowInternetImages());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowInternetImages(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowInternetImages(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChangeNumber(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().ChangeNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DownloadState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMessageDownloadState>(this->shim().DownloadState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DownloadState(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DownloadState(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessageDownloadState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EstimatedDownloadSizeInBytes(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().EstimatedDownloadSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EstimatedDownloadSizeInBytes(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EstimatedDownloadSizeInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FlagState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailFlagState>(this->shim().FlagState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FlagState(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FlagState(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailFlagState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasPartialBodies(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasPartialBodies());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Importance(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailImportance>(this->shim().Importance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Importance(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Importance(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailImportance const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InResponseToMessageId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().InResponseToMessageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IrmInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailIrmInfo>(this->shim().IrmInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IrmInfo(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IrmInfo(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailIrmInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDraftMessage(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDraftMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsRead(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRead());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsRead(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsRead(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSeen(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSeen());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsSeen(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsSeen(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsServerSearchMessage(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsServerSearchMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSmartSendable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSmartSendable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MessageClass(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MessageClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MessageClass(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MessageClass(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NormalizedSubject(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NormalizedSubject());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OriginalCodePage(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().OriginalCodePage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OriginalCodePage(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OriginalCodePage(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Preview(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Preview());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Preview(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Preview(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastResponseKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMessageResponseKind>(this->shim().LastResponseKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LastResponseKind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LastResponseKind(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessageResponseKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Sender(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailRecipient>(this->shim().Sender());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Sender(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Sender(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailRecipient const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SentTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().SentTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SentTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SentTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MeetingInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMeetingInfo>(this->shim().MeetingInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MeetingInfo(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MeetingInfo(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMeetingInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBodyStream(int32_t type, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().GetBodyStream(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessageBodyKind const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetBodyStream(int32_t type, void* stream) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetBodyStream(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessageBodyKind const*>(&type), *reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&stream));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMessage3> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMessage3>
    {
        int32_t __stdcall get_SmimeData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().SmimeData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SmimeData(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SmimeData(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SmimeKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailMessageSmimeKind>(this->shim().SmimeKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SmimeKind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SmimeKind(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailMessageSmimeKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMessage4> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMessage4>
    {
        int32_t __stdcall get_ReplyTo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Email::EmailRecipient>>(this->shim().ReplyTo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SentRepresenting(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailRecipient>(this->shim().SentRepresenting());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SentRepresenting(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SentRepresenting(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailRecipient const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMessageBatch> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMessageBatch>
    {
        int32_t __stdcall get_Messages(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMessage>>(this->shim().Messages());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailBatchStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailMessageReader> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailMessageReader>
    {
        int32_t __stdcall ReadBatchAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessageBatch>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailQueryOptions> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailQueryOptions>
    {
        int32_t __stdcall get_TextSearch(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailQueryTextSearch>(this->shim().TextSearch());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SortDirection(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailQuerySortDirection>(this->shim().SortDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SortDirection(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SortDirection(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailQuerySortDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SortProperty(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailQuerySortProperty>(this->shim().SortProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SortProperty(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SortProperty(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailQuerySortProperty const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailQueryKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Kind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Kind(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailQueryKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FolderIds(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().FolderIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailQueryOptionsFactory> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailQueryOptionsFactory>
    {
        int32_t __stdcall CreateWithText(void* text, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailQueryOptions>(this->shim().CreateWithText(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithTextAndFields(void* text, uint32_t fields, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailQueryOptions>(this->shim().CreateWithTextAndFields(*reinterpret_cast<hstring const*>(&text), *reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailQuerySearchFields const*>(&fields)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailQueryTextSearch> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailQueryTextSearch>
    {
        int32_t __stdcall get_Fields(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailQuerySearchFields>(this->shim().Fields());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Fields(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Fields(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailQuerySearchFields const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SearchScope(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailQuerySearchScope>(this->shim().SearchScope());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SearchScope(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SearchScope(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailQuerySearchScope const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Text(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailRecipient> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailRecipient>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Name(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Address(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Address());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Address(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Address(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailRecipientFactory> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailRecipientFactory>
    {
        int32_t __stdcall Create(void* address, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailRecipient>(this->shim().Create(*reinterpret_cast<hstring const*>(&address)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithName(void* address, void* name, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailRecipient>(this->shim().CreateWithName(*reinterpret_cast<hstring const*>(&address), *reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Email::EmailRecipientResolutionStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PublicKeys(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>>(this->shim().PublicKeys());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult2> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult2>
    {
        int32_t __stdcall put_Status(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Status(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailRecipientResolutionStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPublicKeys(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPublicKeys(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Security::Cryptography::Certificates::Certificate> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailStore> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailStore>
    {
        int32_t __stdcall FindMailboxesAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Email::EmailMailbox>>>(this->shim().FindMailboxesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversationReader(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailConversationReader>(this->shim().GetConversationReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversationReaderWithOptions(void* options, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailConversationReader>(this->shim().GetConversationReader(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageReader(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailMessageReader>(this->shim().GetMessageReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageReaderWithOptions(void* options, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Email::EmailMessageReader>(this->shim().GetMessageReader(*reinterpret_cast<winrt::Windows::ApplicationModel::Email::EmailQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMailboxAsync(void* id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailbox>>(this->shim().GetMailboxAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversationAsync(void* id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailConversation>>(this->shim().GetConversationAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFolderAsync(void* id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailFolder>>(this->shim().GetFolderAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageAsync(void* id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMessage>>(this->shim().GetMessageAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateMailboxAsync(void* accountName, void* accountAddress, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailbox>>(this->shim().CreateMailboxAsync(*reinterpret_cast<hstring const*>(&accountName), *reinterpret_cast<hstring const*>(&accountAddress)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateMailboxInAccountAsync(void* accountName, void* accountAddress, void* userDataAccountId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Email::EmailMailbox>>(this->shim().CreateMailboxAsync(*reinterpret_cast<hstring const*>(&accountName), *reinterpret_cast<hstring const*>(&accountAddress), *reinterpret_cast<hstring const*>(&userDataAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Email::IEmailStoreNotificationTriggerDetails> : produce_base<D, winrt::Windows::ApplicationModel::Email::IEmailStoreNotificationTriggerDetails>
    {
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Email
{
    constexpr auto operator|(EmailQuerySearchFields const left, EmailQuerySearchFields const right) noexcept
    {
        return static_cast<EmailQuerySearchFields>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(EmailQuerySearchFields& left, EmailQuerySearchFields const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(EmailQuerySearchFields const left, EmailQuerySearchFields const right) noexcept
    {
        return static_cast<EmailQuerySearchFields>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(EmailQuerySearchFields& left, EmailQuerySearchFields const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(EmailQuerySearchFields const value) noexcept
    {
        return static_cast<EmailQuerySearchFields>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(EmailQuerySearchFields const left, EmailQuerySearchFields const right) noexcept
    {
        return static_cast<EmailQuerySearchFields>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(EmailQuerySearchFields& left, EmailQuerySearchFields const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline EmailAttachment::EmailAttachment() :
        EmailAttachment(impl::call_factory_cast<EmailAttachment(*)(winrt::Windows::Foundation::IActivationFactory const&), EmailAttachment>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EmailAttachment>(); }))
    {
    }
    inline EmailAttachment::EmailAttachment(param::hstring const& fileName, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& data) :
        EmailAttachment(impl::call_factory<EmailAttachment, IEmailAttachmentFactory>([&](IEmailAttachmentFactory const& f) { return f.Create(fileName, data); }))
    {
    }
    inline EmailAttachment::EmailAttachment(param::hstring const& fileName, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& data, param::hstring const& mimeType) :
        EmailAttachment(impl::call_factory<EmailAttachment, IEmailAttachmentFactory2>([&](IEmailAttachmentFactory2 const& f) { return f.Create(fileName, data, mimeType); }))
    {
    }
    inline EmailIrmInfo::EmailIrmInfo() :
        EmailIrmInfo(impl::call_factory_cast<EmailIrmInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), EmailIrmInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EmailIrmInfo>(); }))
    {
    }
    inline EmailIrmInfo::EmailIrmInfo(winrt::Windows::Foundation::DateTime const& expiration, winrt::Windows::ApplicationModel::Email::EmailIrmTemplate const& irmTemplate) :
        EmailIrmInfo(impl::call_factory<EmailIrmInfo, IEmailIrmInfoFactory>([&](IEmailIrmInfoFactory const& f) { return f.Create(expiration, irmTemplate); }))
    {
    }
    inline EmailIrmTemplate::EmailIrmTemplate() :
        EmailIrmTemplate(impl::call_factory_cast<EmailIrmTemplate(*)(winrt::Windows::Foundation::IActivationFactory const&), EmailIrmTemplate>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EmailIrmTemplate>(); }))
    {
    }
    inline EmailIrmTemplate::EmailIrmTemplate(param::hstring const& id, param::hstring const& name, param::hstring const& description) :
        EmailIrmTemplate(impl::call_factory<EmailIrmTemplate, IEmailIrmTemplateFactory>([&](IEmailIrmTemplateFactory const& f) { return f.Create(id, name, description); }))
    {
    }
    inline EmailMailboxAutoReplySettings::EmailMailboxAutoReplySettings() :
        EmailMailboxAutoReplySettings(impl::call_factory_cast<EmailMailboxAutoReplySettings(*)(winrt::Windows::Foundation::IActivationFactory const&), EmailMailboxAutoReplySettings>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EmailMailboxAutoReplySettings>(); }))
    {
    }
    inline auto EmailManager::ShowComposeNewEmailAsync(winrt::Windows::ApplicationModel::Email::EmailMessage const& message)
    {
        return impl::call_factory<EmailManager, IEmailManagerStatics>([&](IEmailManagerStatics const& f) { return f.ShowComposeNewEmailAsync(message); });
    }
    inline auto EmailManager::RequestStoreAsync(winrt::Windows::ApplicationModel::Email::EmailStoreAccessType const& accessType)
    {
        return impl::call_factory<EmailManager, IEmailManagerStatics2>([&](IEmailManagerStatics2 const& f) { return f.RequestStoreAsync(accessType); });
    }
    inline auto EmailManager::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<EmailManager, IEmailManagerStatics3>([&](IEmailManagerStatics3 const& f) { return f.GetForUser(user); });
    }
    inline EmailMeetingInfo::EmailMeetingInfo() :
        EmailMeetingInfo(impl::call_factory_cast<EmailMeetingInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), EmailMeetingInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EmailMeetingInfo>(); }))
    {
    }
    inline EmailMessage::EmailMessage() :
        EmailMessage(impl::call_factory_cast<EmailMessage(*)(winrt::Windows::Foundation::IActivationFactory const&), EmailMessage>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EmailMessage>(); }))
    {
    }
    inline EmailQueryOptions::EmailQueryOptions() :
        EmailQueryOptions(impl::call_factory_cast<EmailQueryOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), EmailQueryOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EmailQueryOptions>(); }))
    {
    }
    inline EmailQueryOptions::EmailQueryOptions(param::hstring const& text) :
        EmailQueryOptions(impl::call_factory<EmailQueryOptions, IEmailQueryOptionsFactory>([&](IEmailQueryOptionsFactory const& f) { return f.CreateWithText(text); }))
    {
    }
    inline EmailQueryOptions::EmailQueryOptions(param::hstring const& text, winrt::Windows::ApplicationModel::Email::EmailQuerySearchFields const& fields) :
        EmailQueryOptions(impl::call_factory<EmailQueryOptions, IEmailQueryOptionsFactory>([&](IEmailQueryOptionsFactory const& f) { return f.CreateWithTextAndFields(text, fields); }))
    {
    }
    inline EmailRecipient::EmailRecipient() :
        EmailRecipient(impl::call_factory_cast<EmailRecipient(*)(winrt::Windows::Foundation::IActivationFactory const&), EmailRecipient>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EmailRecipient>(); }))
    {
    }
    inline EmailRecipient::EmailRecipient(param::hstring const& address) :
        EmailRecipient(impl::call_factory<EmailRecipient, IEmailRecipientFactory>([&](IEmailRecipientFactory const& f) { return f.Create(address); }))
    {
    }
    inline EmailRecipient::EmailRecipient(param::hstring const& address, param::hstring const& name) :
        EmailRecipient(impl::call_factory<EmailRecipient, IEmailRecipientFactory>([&](IEmailRecipientFactory const& f) { return f.CreateWithName(address, name); }))
    {
    }
    inline EmailRecipientResolutionResult::EmailRecipientResolutionResult() :
        EmailRecipientResolutionResult(impl::call_factory_cast<EmailRecipientResolutionResult(*)(winrt::Windows::Foundation::IActivationFactory const&), EmailRecipientResolutionResult>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EmailRecipientResolutionResult>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailAttachment> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailAttachment2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailAttachmentFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailAttachmentFactory2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailConversation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailConversationBatch> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailConversationReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailFolder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailIrmInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailIrmInfoFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailIrmTemplate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailIrmTemplateFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailItemCounts> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailbox> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailbox2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailbox3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailbox4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailbox5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxAction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReply> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxChange> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeTracker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxChangedDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxCreateFolderResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailManagerForUser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailManagerStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMessage2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMessage3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMessage4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMessageBatch> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMessageReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailQueryOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailQueryOptionsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailQueryTextSearch> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailRecipient> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailRecipientFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailStoreNotificationTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailAttachment> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailConversation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailConversationBatch> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailConversationReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailFolder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailIrmInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailIrmTemplate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailItemCounts> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailbox> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxAction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReply> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxChange> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxChangeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxChangeTracker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxChangedDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxCreateFolderResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxPolicies> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxSyncManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailManagerForUser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMeetingInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMessageBatch> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMessageReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailQueryOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailQueryTextSearch> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailRecipient> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailRecipientResolutionResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailStoreNotificationTriggerDetails> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
