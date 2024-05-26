// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Chat_H
#define WINRT_Windows_ApplicationModel_Chat_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.ApplicationModel.Chat.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatCapabilities<D>::IsOnline() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatCapabilities)->get_IsOnline(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatCapabilities<D>::IsChatCapable() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatCapabilities)->get_IsChatCapable(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatCapabilities<D>::IsFileTransferCapable() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatCapabilities)->get_IsFileTransferCapable(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatCapabilities<D>::IsGeoLocationPushCapable() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatCapabilities)->get_IsGeoLocationPushCapable(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatCapabilities<D>::IsIntegratedMessagingCapable() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatCapabilities)->get_IsIntegratedMessagingCapable(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatCapabilities>) consume_Windows_ApplicationModel_Chat_IChatCapabilitiesManagerStatics<D>::GetCachedCapabilitiesAsync(param::hstring const& address) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics)->GetCachedCapabilitiesAsync(*(void**)(&address), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatCapabilities>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatCapabilities>) consume_Windows_ApplicationModel_Chat_IChatCapabilitiesManagerStatics<D>::GetCapabilitiesFromNetworkAsync(param::hstring const& address) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics)->GetCapabilitiesFromNetworkAsync(*(void**)(&address), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatCapabilities>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatCapabilities>) consume_Windows_ApplicationModel_Chat_IChatCapabilitiesManagerStatics2<D>::GetCachedCapabilitiesAsync(param::hstring const& address, param::hstring const& transportId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2)->GetCachedCapabilitiesForTransportAsync(*(void**)(&address), *(void**)(&transportId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatCapabilities>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatCapabilities>) consume_Windows_ApplicationModel_Chat_IChatCapabilitiesManagerStatics2<D>::GetCapabilitiesFromNetworkAsync(param::hstring const& address, param::hstring const& transportId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2)->GetCapabilitiesFromNetworkForTransportAsync(*(void**)(&address), *(void**)(&transportId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatCapabilities>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::HasUnreadMessages() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->get_HasUnreadMessages(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::Id() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->get_Id(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::Subject() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->get_Subject(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::Subject(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->put_Subject(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::IsConversationMuted() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->get_IsConversationMuted(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::IsConversationMuted(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->put_IsConversationMuted(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::MostRecentMessageId() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->get_MostRecentMessageId(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::Participants() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->get_Participants(&result));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingInfo) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::ThreadingInfo() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->get_ThreadingInfo(&result));
        return winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingInfo{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::DeleteAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->DeleteAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageReader) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::GetMessageReader() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->GetMessageReader(&result));
        return winrt::Windows::ApplicationModel::Chat::ChatMessageReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::MarkMessagesAsReadAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->MarkAllMessagesAsReadAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::MarkMessagesAsReadAsync(winrt::Windows::Foundation::DateTime const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->MarkMessagesAsReadAsync(impl::bind_in(value), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::SaveAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->SaveAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::NotifyLocalParticipantComposing(param::hstring const& transportId, param::hstring const& participantAddress, bool isComposing) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->NotifyLocalParticipantComposing(*(void**)(&transportId), *(void**)(&participantAddress), isComposing));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::NotifyRemoteParticipantComposing(param::hstring const& transportId, param::hstring const& participantAddress, bool isComposing) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->NotifyRemoteParticipantComposing(*(void**)(&transportId), *(void**)(&participantAddress), isComposing));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::RemoteParticipantComposingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::ChatConversation, winrt::Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->add_RemoteParticipantComposingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Chat_IChatConversation<D>::RemoteParticipantComposingChanged_revoker consume_Windows_ApplicationModel_Chat_IChatConversation<D>::RemoteParticipantComposingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::ChatConversation, winrt::Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RemoteParticipantComposingChanged_revoker>(this, RemoteParticipantComposingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatConversation<D>::RemoteParticipantComposingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation)->remove_RemoteParticipantComposingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatConversation2<D>::CanModifyParticipants() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation2)->get_CanModifyParticipants(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatConversation2<D>::CanModifyParticipants(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversation2)->put_CanModifyParticipants(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatConversation>>) consume_Windows_ApplicationModel_Chat_IChatConversationReader<D>::ReadBatchAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversationReader)->ReadBatchAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatConversation>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatConversation>>) consume_Windows_ApplicationModel_Chat_IChatConversationReader<D>::ReadBatchAsync(int32_t count) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversationReader)->ReadBatchWithCountAsync(count, &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatConversation>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::ContactId() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->get_ContactId(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::ContactId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->put_ContactId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::Custom() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->get_Custom(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::Custom(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->put_Custom(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::ConversationId() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->get_ConversationId(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::ConversationId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->put_ConversationId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::Participants() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->get_Participants(&result));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingKind) consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::Kind() const
    {
        winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingKind result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->get_Kind(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::Kind(winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->put_Kind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatItemKind) consume_Windows_ApplicationModel_Chat_IChatItem<D>::ItemKind() const
    {
        winrt::Windows::ApplicationModel::Chat::ChatItemKind result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatItem)->get_ItemKind(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Chat::ChatMessageAttachment>) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Attachments() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_Attachments(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Chat::ChatMessageAttachment>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Body() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_Body(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Body(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->put_Body(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::From() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_From(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::IsForwardingDisabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_IsForwardingDisabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::IsIncoming() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_IsIncoming(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::IsRead() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_IsRead(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::LocalTimestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_LocalTimestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::NetworkTimestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_NetworkTimestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Recipients() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_Recipients(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Chat::ChatMessageStatus>) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::RecipientSendStatuses() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_RecipientSendStatuses(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Chat::ChatMessageStatus>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageStatus) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Status() const
    {
        winrt::Windows::ApplicationModel::Chat::ChatMessageStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Subject() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_Subject(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::TransportFriendlyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_TransportFriendlyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::TransportId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->get_TransportId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage<D>::TransportId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage)->put_TransportId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::EstimatedDownloadSize() const
    {
        uint64_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->get_EstimatedDownloadSize(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::EstimatedDownloadSize(uint64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_EstimatedDownloadSize(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::From(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_From(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsAutoReply() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->get_IsAutoReply(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsAutoReply(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_IsAutoReply(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsForwardingDisabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_IsForwardingDisabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsReplyDisabled() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->get_IsReplyDisabled(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsIncoming(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_IsIncoming(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsRead(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_IsRead(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsSeen() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->get_IsSeen(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsSeen(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_IsSeen(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsSimMessage() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->get_IsSimMessage(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::LocalTimestamp(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_LocalTimestamp(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageKind) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::MessageKind() const
    {
        winrt::Windows::ApplicationModel::Chat::ChatMessageKind result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->get_MessageKind(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::MessageKind(winrt::Windows::ApplicationModel::Chat::ChatMessageKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_MessageKind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageOperatorKind) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::MessageOperatorKind() const
    {
        winrt::Windows::ApplicationModel::Chat::ChatMessageOperatorKind result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->get_MessageOperatorKind(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::MessageOperatorKind(winrt::Windows::ApplicationModel::Chat::ChatMessageOperatorKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_MessageOperatorKind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::NetworkTimestamp(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_NetworkTimestamp(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsReceivedDuringQuietHours() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->get_IsReceivedDuringQuietHours(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsReceivedDuringQuietHours(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_IsReceivedDuringQuietHours(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::RemoteId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_RemoteId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::Status(winrt::Windows::ApplicationModel::Chat::ChatMessageStatus const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_Status(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::Subject(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_Subject(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::ShouldSuppressNotification() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->get_ShouldSuppressNotification(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::ShouldSuppressNotification(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_ShouldSuppressNotification(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingInfo) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::ThreadingInfo() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->get_ThreadingInfo(&result));
        return winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingInfo{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::ThreadingInfo(winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingInfo const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->put_ThreadingInfo(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo>) consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::RecipientsDeliveryInfos() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage2)->get_RecipientsDeliveryInfos(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessage3<D>::RemoteId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage3)->get_RemoteId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessage4<D>::SyncId() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage4)->get_SyncId(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessage4<D>::SyncId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessage4)->put_SyncId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::DataStreamReference() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment)->get_DataStreamReference(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::DataStreamReference(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment)->put_DataStreamReference(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::GroupId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment)->get_GroupId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::GroupId(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment)->put_GroupId(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::MimeType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment)->get_MimeType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::MimeType(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment)->put_MimeType(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::Text(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment)->put_Text(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2<D>::Thumbnail() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment2)->get_Thumbnail(&result));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2<D>::Thumbnail(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment2)->put_Thumbnail(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2<D>::TransferProgress() const
    {
        double result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment2)->get_TransferProgress(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2<D>::TransferProgress(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment2)->put_TransferProgress(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2<D>::OriginalFileName() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment2)->get_OriginalFileName(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2<D>::OriginalFileName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment2)->put_OriginalFileName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageAttachment) consume_Windows_ApplicationModel_Chat_IChatMessageAttachmentFactory<D>::CreateChatMessageAttachment(param::hstring const& mimeType, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& dataStreamReference) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory)->CreateChatMessageAttachment(*(void**)(&mimeType), *(void**)(&dataStreamReference), &value));
        return winrt::Windows::ApplicationModel::Chat::ChatMessageAttachment{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatMessageBlockingStatic<D>::MarkMessageAsBlockedAsync(param::hstring const& localChatMessageId, bool blocked) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageBlockingStatic)->MarkMessageAsBlockedAsync(*(void**)(&localChatMessageId), blocked, &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageChangeType) consume_Windows_ApplicationModel_Chat_IChatMessageChange<D>::ChangeType() const
    {
        winrt::Windows::ApplicationModel::Chat::ChatMessageChangeType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageChange)->get_ChangeType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessage) consume_Windows_ApplicationModel_Chat_IChatMessageChange<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageChange)->get_Message(&value));
        return winrt::Windows::ApplicationModel::Chat::ChatMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageChangeReader<D>::AcceptChanges() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageChangeReader)->AcceptChanges());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageChangeReader<D>::AcceptChangesThrough(winrt::Windows::ApplicationModel::Chat::ChatMessageChange const& lastChangeToAcknowledge) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageChangeReader)->AcceptChangesThrough(*(void**)(&lastChangeToAcknowledge)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatMessageChange>>) consume_Windows_ApplicationModel_Chat_IChatMessageChangeReader<D>::ReadBatchAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageChangeReader)->ReadBatchAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatMessageChange>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageChangeTracker<D>::Enable() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageChangeTracker)->Enable());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageChangeReader) consume_Windows_ApplicationModel_Chat_IChatMessageChangeTracker<D>::GetChangeReader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageChangeTracker)->GetChangeReader(&value));
        return winrt::Windows::ApplicationModel::Chat::ChatMessageChangeReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageChangeTracker<D>::Reset() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageChangeTracker)->Reset());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageChangedDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageChangedDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageChangedDeferral) consume_Windows_ApplicationModel_Chat_IChatMessageChangedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs)->GetDeferral(&result));
        return winrt::Windows::ApplicationModel::Chat::ChatMessageChangedDeferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_Chat_IChatMessageManager2Statics<D>::RegisterTransportAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageManager2Statics)->RegisterTransportAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessageTransport>) consume_Windows_ApplicationModel_Chat_IChatMessageManager2Statics<D>::GetTransportAsync(param::hstring const& transportId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageManager2Statics)->GetTransportAsync(*(void**)(&transportId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessageTransport>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatMessageTransport>>) consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatic<D>::GetTransportsAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatic)->GetTransportsAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatMessageTransport>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessageStore>) consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatic<D>::RequestStoreAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatic)->RequestStoreAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessageStore>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatic<D>::ShowComposeSmsMessageAsync(winrt::Windows::ApplicationModel::Chat::ChatMessage const& message) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatic)->ShowComposeSmsMessageAsync(*(void**)(&message), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatic<D>::ShowSmsSettings() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatic)->ShowSmsSettings());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatSyncManager>) consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatics3<D>::RequestSyncManagerAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatics3)->RequestSyncManagerAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatSyncManager>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessage) consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails<D>::ChatMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails)->get_ChatMessage(&value));
        return winrt::Windows::ApplicationModel::Chat::ChatMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails2<D>::ShouldDisplayToast() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2)->get_ShouldDisplayToast(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails2<D>::ShouldUpdateDetailText() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2)->get_ShouldUpdateDetailText(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails2<D>::ShouldUpdateBadge() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2)->get_ShouldUpdateBadge(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails2<D>::ShouldUpdateActionCenter() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2)->get_ShouldUpdateActionCenter(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatMessage>>) consume_Windows_ApplicationModel_Chat_IChatMessageReader<D>::ReadBatchAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageReader)->ReadBatchAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatMessage>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatMessage>>) consume_Windows_ApplicationModel_Chat_IChatMessageReader2<D>::ReadBatchAsync(int32_t count) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageReader2)->ReadBatchWithCountAsync(count, &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatMessage>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageChangeTracker) consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::ChangeTracker() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore)->get_ChangeTracker(&value));
        return winrt::Windows::ApplicationModel::Chat::ChatMessageChangeTracker{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::DeleteMessageAsync(param::hstring const& localMessageId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore)->DeleteMessageAsync(*(void**)(&localMessageId), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::DownloadMessageAsync(param::hstring const& localChatMessageId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore)->DownloadMessageAsync(*(void**)(&localChatMessageId), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessage>) consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::GetMessageAsync(param::hstring const& localChatMessageId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore)->GetMessageAsync(*(void**)(&localChatMessageId), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessage>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageReader) consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::GetMessageReader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore)->GetMessageReader1(&value));
        return winrt::Windows::ApplicationModel::Chat::ChatMessageReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageReader) consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::GetMessageReader(winrt::Windows::Foundation::TimeSpan const& recentTimeLimit) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore)->GetMessageReader2(impl::bind_in(recentTimeLimit), &value));
        return winrt::Windows::ApplicationModel::Chat::ChatMessageReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::MarkMessageReadAsync(param::hstring const& localChatMessageId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore)->MarkMessageReadAsync(*(void**)(&localChatMessageId), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::RetrySendMessageAsync(param::hstring const& localChatMessageId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore)->RetrySendMessageAsync(*(void**)(&localChatMessageId), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::SendMessageAsync(winrt::Windows::ApplicationModel::Chat::ChatMessage const& chatMessage) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore)->SendMessageAsync(*(void**)(&chatMessage), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageValidationResult) consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::ValidateMessage(winrt::Windows::ApplicationModel::Chat::ChatMessage const& chatMessage) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore)->ValidateMessage(*(void**)(&chatMessage), &value));
        return winrt::Windows::ApplicationModel::Chat::ChatMessageValidationResult{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::MessageChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::ChatMessageStore, winrt::Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs> const& value) const
    {
        winrt::event_token returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore)->add_MessageChanged(*(void**)(&value), put_abi(returnValue)));
        return returnValue;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::MessageChanged_revoker consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::MessageChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::ChatMessageStore, winrt::Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, MessageChanged_revoker>(this, MessageChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::MessageChanged(winrt::event_token const& value) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore)->remove_MessageChanged(impl::bind_in(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessage>) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::ForwardMessageAsync(param::hstring const& localChatMessageId, param::async_iterable<hstring> const& addresses) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->ForwardMessageAsync(*(void**)(&localChatMessageId), *(void**)(&addresses), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessage>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatConversation>) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetConversationAsync(param::hstring const& conversationId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->GetConversationAsync(*(void**)(&conversationId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatConversation>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatConversation>) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetConversationAsync(param::hstring const& conversationId, param::async_iterable<hstring> const& transportIds) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->GetConversationForTransportsAsync(*(void**)(&conversationId), *(void**)(&transportIds), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatConversation>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatConversation>) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetConversationFromThreadingInfoAsync(winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingInfo const& threadingInfo) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->GetConversationFromThreadingInfoAsync(*(void**)(&threadingInfo), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatConversation>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatConversationReader) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetConversationReader() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->GetConversationReader(&result));
        return winrt::Windows::ApplicationModel::Chat::ChatConversationReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatConversationReader) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetConversationReader(param::iterable<hstring> const& transportIds) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->GetConversationForTransportsReader(*(void**)(&transportIds), &result));
        return winrt::Windows::ApplicationModel::Chat::ChatConversationReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessage>) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetMessageByRemoteIdAsync(param::hstring const& transportId, param::hstring const& remoteId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->GetMessageByRemoteIdAsync(*(void**)(&transportId), *(void**)(&remoteId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessage>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<int32_t>) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetUnseenCountAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->GetUnseenCountAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<int32_t>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<int32_t>) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetUnseenCountAsync(param::async_iterable<hstring> const& transportIds) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->GetUnseenCountForTransportsReaderAsync(*(void**)(&transportIds), &result));
        return winrt::Windows::Foundation::IAsyncOperation<int32_t>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::MarkAsSeenAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->MarkAsSeenAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::MarkAsSeenAsync(param::async_iterable<hstring> const& transportIds) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->MarkAsSeenForTransportsAsync(*(void**)(&transportIds), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatSearchReader) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetSearchReader(winrt::Windows::ApplicationModel::Chat::ChatQueryOptions const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->GetSearchReader(*(void**)(&value), &result));
        return winrt::Windows::ApplicationModel::Chat::ChatSearchReader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::SaveMessageAsync(winrt::Windows::ApplicationModel::Chat::ChatMessage const& chatMessage) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->SaveMessageAsync(*(void**)(&chatMessage), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::TryCancelDownloadMessageAsync(param::hstring const& localChatMessageId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->TryCancelDownloadMessageAsync(*(void**)(&localChatMessageId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::TryCancelSendMessageAsync(param::hstring const& localChatMessageId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->TryCancelSendMessageAsync(*(void**)(&localChatMessageId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::StoreChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::ChatMessageStore, winrt::Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->add_StoreChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::StoreChanged_revoker consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::StoreChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::ChatMessageStore, winrt::Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StoreChanged_revoker>(this, StoreChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::StoreChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore2)->remove_StoreChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessage>) consume_Windows_ApplicationModel_Chat_IChatMessageStore3<D>::GetMessageBySyncIdAsync(param::hstring const& syncId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStore3)->GetMessageBySyncIdAsync(*(void**)(&syncId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessage>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessageStoreChangedEventArgs<D>::Id() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs)->get_Id(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatStoreChangedEventKind) consume_Windows_ApplicationModel_Chat_IChatMessageStoreChangedEventArgs<D>::Kind() const
    {
        winrt::Windows::ApplicationModel::Chat::ChatStoreChangedEventKind result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs)->get_Kind(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessageTransport<D>::IsAppSetAsNotificationProvider() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageTransport)->get_IsAppSetAsNotificationProvider(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatMessageTransport<D>::IsActive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageTransport)->get_IsActive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessageTransport<D>::TransportFriendlyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageTransport)->get_TransportFriendlyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatMessageTransport<D>::TransportId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageTransport)->get_TransportId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatMessageTransport<D>::RequestSetAsNotificationProviderAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageTransport)->RequestSetAsNotificationProviderAsync(&value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration) consume_Windows_ApplicationModel_Chat_IChatMessageTransport2<D>::Configuration() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageTransport2)->get_Configuration(&result));
        return winrt::Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageTransportKind) consume_Windows_ApplicationModel_Chat_IChatMessageTransport2<D>::TransportKind() const
    {
        winrt::Windows::ApplicationModel::Chat::ChatMessageTransportKind result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageTransport2)->get_TransportKind(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_Chat_IChatMessageTransportConfiguration<D>::MaxAttachmentCount() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration)->get_MaxAttachmentCount(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_Chat_IChatMessageTransportConfiguration<D>::MaxMessageSizeInKilobytes() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration)->get_MaxMessageSizeInKilobytes(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_Chat_IChatMessageTransportConfiguration<D>::MaxRecipientCount() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration)->get_MaxRecipientCount(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_ApplicationModel_Chat_IChatMessageTransportConfiguration<D>::SupportedVideoFormat() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration)->get_SupportedVideoFormat(&result));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_ApplicationModel_Chat_IChatMessageTransportConfiguration<D>::ExtendedProperties() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration)->get_ExtendedProperties(&result));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_ApplicationModel_Chat_IChatMessageValidationResult<D>::MaxPartCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageValidationResult)->get_MaxPartCount(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_ApplicationModel_Chat_IChatMessageValidationResult<D>::PartCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageValidationResult)->get_PartCount(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_ApplicationModel_Chat_IChatMessageValidationResult<D>::RemainingCharacterCountInPart() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageValidationResult)->get_RemainingCharacterCountInPart(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageValidationStatus) consume_Windows_ApplicationModel_Chat_IChatMessageValidationResult<D>::Status() const
    {
        winrt::Windows::ApplicationModel::Chat::ChatMessageValidationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatMessageValidationResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatQueryOptions<D>::SearchString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatQueryOptions)->get_SearchString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatQueryOptions<D>::SearchString(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatQueryOptions)->put_SearchString(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::TransportAddress() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_TransportAddress(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::TransportAddress(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->put_TransportAddress(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::DeliveryTime() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_DeliveryTime(&result));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::DeliveryTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->put_DeliveryTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::ReadTime() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_ReadTime(&result));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::ReadTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->put_ReadTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatTransportErrorCodeCategory) consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::TransportErrorCodeCategory() const
    {
        winrt::Windows::ApplicationModel::Chat::ChatTransportErrorCodeCategory result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_TransportErrorCodeCategory(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatTransportInterpretedErrorCode) consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::TransportInterpretedErrorCode() const
    {
        winrt::Windows::ApplicationModel::Chat::ChatTransportInterpretedErrorCode result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_TransportInterpretedErrorCode(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::TransportErrorCode() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_TransportErrorCode(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::IsErrorPermanent() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_IsErrorPermanent(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatMessageStatus) consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::Status() const
    {
        winrt::Windows::ApplicationModel::Chat::ChatMessageStatus result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_Status(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::IChatItem>>) consume_Windows_ApplicationModel_Chat_IChatSearchReader<D>::ReadBatchAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatSearchReader)->ReadBatchAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::IChatItem>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::IChatItem>>) consume_Windows_ApplicationModel_Chat_IChatSearchReader<D>::ReadBatchAsync(int32_t count) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatSearchReader)->ReadBatchWithCountAsync(count, &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::IChatItem>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatSyncConfiguration<D>::IsSyncEnabled() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatSyncConfiguration)->get_IsSyncEnabled(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatSyncConfiguration<D>::IsSyncEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatSyncConfiguration)->put_IsSyncEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatRestoreHistorySpan) consume_Windows_ApplicationModel_Chat_IChatSyncConfiguration<D>::RestoreHistorySpan() const
    {
        winrt::Windows::ApplicationModel::Chat::ChatRestoreHistorySpan result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatSyncConfiguration)->get_RestoreHistorySpan(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatSyncConfiguration<D>::RestoreHistorySpan(winrt::Windows::ApplicationModel::Chat::ChatRestoreHistorySpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatSyncConfiguration)->put_RestoreHistorySpan(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::ChatSyncConfiguration) consume_Windows_ApplicationModel_Chat_IChatSyncManager<D>::Configuration() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatSyncManager)->get_Configuration(&result));
        return winrt::Windows::ApplicationModel::Chat::ChatSyncConfiguration{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatSyncManager<D>::AssociateAccountAsync(winrt::Windows::Security::Credentials::WebAccount const& webAccount) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatSyncManager)->AssociateAccountAsync(*(void**)(&webAccount), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatSyncManager<D>::UnassociateAccountAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatSyncManager)->UnassociateAccountAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IChatSyncManager<D>::IsAccountAssociated(winrt::Windows::Security::Credentials::WebAccount const& webAccount) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatSyncManager)->IsAccountAssociated(*(void**)(&webAccount), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IChatSyncManager<D>::StartSync() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatSyncManager)->StartSync());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IChatSyncManager<D>::SetConfigurationAsync(winrt::Windows::ApplicationModel::Chat::ChatSyncConfiguration const& configuration) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IChatSyncManager)->SetConfigurationAsync(*(void**)(&configuration), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::TransportId() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessage)->get_TransportId(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::Title() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessage)->get_Title(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::Text() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessage)->get_Text(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::IsPinRequired() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessage)->get_IsPinRequired(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAction>) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::Actions() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessage)->get_Actions(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAction>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::SendResponseAsync(winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAction const& action) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessage)->SendResponseAsync(*(void**)(&action), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::SendResponseWithPinAsync(winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAction const& action, param::hstring const& pin) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessage)->SendResponseWithPinAsync(*(void**)(&action), *(void**)(&pin), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAction<D>::Label() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAction)->get_Label(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAvailableEventArgs<D>::IsMessageAvailable() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs)->get_IsMessageAvailable(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::RcsEndUserMessage) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAvailableEventArgs<D>::Message() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs)->get_Message(&result));
        return winrt::Windows::ApplicationModel::Chat::RcsEndUserMessage{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAvailableTriggerDetails<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAvailableTriggerDetails<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageManager<D>::MessageAvailableChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageManager, winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageManager)->add_MessageAvailableChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageManager<D>::MessageAvailableChanged_revoker consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageManager<D>::MessageAvailableChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageManager, winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, MessageAvailableChanged_revoker>(this, MessageAvailableChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageManager<D>::MessageAvailableChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageManager)->remove_MessageAvailableChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageManager) consume_Windows_ApplicationModel_Chat_IRcsManagerStatics<D>::GetEndUserMessageManager() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics)->GetEndUserMessageManager(&result));
        return winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::RcsTransport>>) consume_Windows_ApplicationModel_Chat_IRcsManagerStatics<D>::GetTransportsAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics)->GetTransportsAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::RcsTransport>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::RcsTransport>) consume_Windows_ApplicationModel_Chat_IRcsManagerStatics<D>::GetTransportAsync(param::hstring const& transportId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics)->GetTransportAsync(*(void**)(&transportId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::RcsTransport>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Chat_IRcsManagerStatics<D>::LeaveConversationAsync(winrt::Windows::ApplicationModel::Chat::ChatConversation const& conversation) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics)->LeaveConversationAsync(*(void**)(&conversation), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Chat_IRcsManagerStatics2<D>::TransportListChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics2)->add_TransportListChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Chat_IRcsManagerStatics2<D>::TransportListChanged_revoker consume_Windows_ApplicationModel_Chat_IRcsManagerStatics2<D>::TransportListChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, TransportListChanged_revoker>(this, TransportListChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IRcsManagerStatics2<D>::TransportListChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics2)->remove_TransportListChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::RcsServiceKind) consume_Windows_ApplicationModel_Chat_IRcsServiceKindSupportedChangedEventArgs<D>::ServiceKind() const
    {
        winrt::Windows::ApplicationModel::Chat::RcsServiceKind result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs)->get_ServiceKind(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::ExtendedProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransport)->get_ExtendedProperties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::IsActive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransport)->get_IsActive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::TransportFriendlyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransport)->get_TransportFriendlyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::TransportId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransport)->get_TransportId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Chat::RcsTransportConfiguration) consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::Configuration() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransport)->get_Configuration(&result));
        return winrt::Windows::ApplicationModel::Chat::RcsTransportConfiguration{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::IsStoreAndForwardEnabled(winrt::Windows::ApplicationModel::Chat::RcsServiceKind const& serviceKind) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransport)->IsStoreAndForwardEnabled(static_cast<int32_t>(serviceKind), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::IsServiceKindSupported(winrt::Windows::ApplicationModel::Chat::RcsServiceKind const& serviceKind) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransport)->IsServiceKindSupported(static_cast<int32_t>(serviceKind), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::ServiceKindSupportedChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::RcsTransport, winrt::Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransport)->add_ServiceKindSupportedChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::ServiceKindSupportedChanged_revoker consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::ServiceKindSupportedChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::RcsTransport, winrt::Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ServiceKindSupportedChanged_revoker>(this, ServiceKindSupportedChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::ServiceKindSupportedChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransport)->remove_ServiceKindSupportedChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration<D>::MaxAttachmentCount() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransportConfiguration)->get_MaxAttachmentCount(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration<D>::MaxMessageSizeInKilobytes() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransportConfiguration)->get_MaxMessageSizeInKilobytes(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration<D>::MaxGroupMessageSizeInKilobytes() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransportConfiguration)->get_MaxGroupMessageSizeInKilobytes(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration<D>::MaxRecipientCount() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransportConfiguration)->get_MaxRecipientCount(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration<D>::MaxFileSizeInKilobytes() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransportConfiguration)->get_MaxFileSizeInKilobytes(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration<D>::WarningFileSizeInKilobytes() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRcsTransportConfiguration)->get_WarningFileSizeInKilobytes(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IRemoteParticipantComposingChangedEventArgs<D>::TransportId() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs)->get_TransportId(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Chat_IRemoteParticipantComposingChangedEventArgs<D>::ParticipantAddress() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs)->get_ParticipantAddress(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Chat_IRemoteParticipantComposingChangedEventArgs<D>::IsComposing() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs)->get_IsComposing(&result));
        return result;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatCapabilities> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatCapabilities>
    {
        int32_t __stdcall get_IsOnline(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsOnline());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsChatCapable(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsChatCapable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsFileTransferCapable(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsFileTransferCapable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsGeoLocationPushCapable(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsGeoLocationPushCapable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsIntegratedMessagingCapable(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsIntegratedMessagingCapable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics>
    {
        int32_t __stdcall GetCachedCapabilitiesAsync(void* address, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatCapabilities>>(this->shim().GetCachedCapabilitiesAsync(*reinterpret_cast<hstring const*>(&address)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCapabilitiesFromNetworkAsync(void* address, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatCapabilities>>(this->shim().GetCapabilitiesFromNetworkAsync(*reinterpret_cast<hstring const*>(&address)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2>
    {
        int32_t __stdcall GetCachedCapabilitiesForTransportAsync(void* address, void* transportId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatCapabilities>>(this->shim().GetCachedCapabilitiesAsync(*reinterpret_cast<hstring const*>(&address), *reinterpret_cast<hstring const*>(&transportId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCapabilitiesFromNetworkForTransportAsync(void* address, void* transportId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatCapabilities>>(this->shim().GetCapabilitiesFromNetworkAsync(*reinterpret_cast<hstring const*>(&address), *reinterpret_cast<hstring const*>(&transportId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatConversation> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatConversation>
    {
        int32_t __stdcall get_HasUnreadMessages(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().HasUnreadMessages());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Subject(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().Subject());
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
        int32_t __stdcall get_IsConversationMuted(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsConversationMuted());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsConversationMuted(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsConversationMuted(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MostRecentMessageId(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().MostRecentMessageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Participants(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().Participants());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ThreadingInfo(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingInfo>(this->shim().ThreadingInfo());
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
        int32_t __stdcall GetMessageReader(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageReader>(this->shim().GetMessageReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MarkAllMessagesAsReadAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MarkMessagesAsReadAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MarkMessagesAsReadAsync(int64_t value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MarkMessagesAsReadAsync(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value)));
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
        int32_t __stdcall NotifyLocalParticipantComposing(void* transportId, void* participantAddress, bool isComposing) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyLocalParticipantComposing(*reinterpret_cast<hstring const*>(&transportId), *reinterpret_cast<hstring const*>(&participantAddress), isComposing);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifyRemoteParticipantComposing(void* transportId, void* participantAddress, bool isComposing) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyRemoteParticipantComposing(*reinterpret_cast<hstring const*>(&transportId), *reinterpret_cast<hstring const*>(&participantAddress), isComposing);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_RemoteParticipantComposingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RemoteParticipantComposingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::ChatConversation, winrt::Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RemoteParticipantComposingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoteParticipantComposingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatConversation2> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatConversation2>
    {
        int32_t __stdcall get_CanModifyParticipants(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().CanModifyParticipants());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanModifyParticipants(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanModifyParticipants(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatConversationReader> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatConversationReader>
    {
        int32_t __stdcall ReadBatchAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatConversation>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadBatchWithCountAsync(int32_t count, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatConversation>>>(this->shim().ReadBatchAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo>
    {
        int32_t __stdcall get_ContactId(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().ContactId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContactId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContactId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Custom(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().Custom());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Custom(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Custom(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConversationId(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().ConversationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ConversationId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConversationId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Participants(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().Participants());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Kind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Kind(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatItem> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatItem>
    {
        int32_t __stdcall get_ItemKind(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatItemKind>(this->shim().ItemKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessage> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessage>
    {
        int32_t __stdcall get_Attachments(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Chat::ChatMessageAttachment>>(this->shim().Attachments());
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
        int32_t __stdcall get_From(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().From());
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
        int32_t __stdcall get_IsForwardingDisabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsForwardingDisabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsIncoming(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsIncoming());
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
        int32_t __stdcall get_LocalTimestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().LocalTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NetworkTimestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().NetworkTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Recipients(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().Recipients());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecipientSendStatuses(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Chat::ChatMessageStatus>>(this->shim().RecipientSendStatuses());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageStatus>(this->shim().Status());
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
        int32_t __stdcall get_TransportFriendlyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TransportFriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransportId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TransportId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TransportId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransportId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessage2> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessage2>
    {
        int32_t __stdcall get_EstimatedDownloadSize(uint64_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<uint64_t>(this->shim().EstimatedDownloadSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EstimatedDownloadSize(uint64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EstimatedDownloadSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_From(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().From(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAutoReply(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsAutoReply());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAutoReply(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAutoReply(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsForwardingDisabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsForwardingDisabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReplyDisabled(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsReplyDisabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsIncoming(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsIncoming(value);
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
        int32_t __stdcall get_IsSeen(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSeen());
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
        int32_t __stdcall get_IsSimMessage(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSimMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LocalTimestamp(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LocalTimestamp(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MessageKind(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageKind>(this->shim().MessageKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MessageKind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MessageKind(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatMessageKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MessageOperatorKind(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageOperatorKind>(this->shim().MessageOperatorKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MessageOperatorKind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MessageOperatorKind(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatMessageOperatorKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NetworkTimestamp(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NetworkTimestamp(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReceivedDuringQuietHours(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsReceivedDuringQuietHours());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsReceivedDuringQuietHours(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsReceivedDuringQuietHours(value);
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
        int32_t __stdcall put_Status(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Status(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatMessageStatus const*>(&value));
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
        int32_t __stdcall get_ShouldSuppressNotification(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().ShouldSuppressNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShouldSuppressNotification(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShouldSuppressNotification(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ThreadingInfo(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingInfo>(this->shim().ThreadingInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ThreadingInfo(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ThreadingInfo(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecipientsDeliveryInfos(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo>>(this->shim().RecipientsDeliveryInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessage3> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessage3>
    {
        int32_t __stdcall get_RemoteId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemoteId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessage4> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessage4>
    {
        int32_t __stdcall get_SyncId(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().SyncId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SyncId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SyncId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment>
    {
        int32_t __stdcall get_DataStreamReference(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().DataStreamReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DataStreamReference(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DataStreamReference(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GroupId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().GroupId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_GroupId(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GroupId(value);
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
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment2> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment2>
    {
        int32_t __stdcall get_Thumbnail(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Thumbnail(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Thumbnail(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransferProgress(double* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<double>(this->shim().TransferProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TransferProgress(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferProgress(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OriginalFileName(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().OriginalFileName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OriginalFileName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OriginalFileName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory>
    {
        int32_t __stdcall CreateChatMessageAttachment(void* mimeType, void* dataStreamReference, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageAttachment>(this->shim().CreateChatMessageAttachment(*reinterpret_cast<hstring const*>(&mimeType), *reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&dataStreamReference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageBlockingStatic> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageBlockingStatic>
    {
        int32_t __stdcall MarkMessageAsBlockedAsync(void* localChatMessageId, bool blocked, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MarkMessageAsBlockedAsync(*reinterpret_cast<hstring const*>(&localChatMessageId), blocked));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageChange> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageChange>
    {
        int32_t __stdcall get_ChangeType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageChangeType>(this->shim().ChangeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageChangeReader> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageChangeReader>
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
            this->shim().AcceptChangesThrough(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatMessageChange const*>(&lastChangeToAcknowledge));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadBatchAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatMessageChange>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageChangeTracker> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageChangeTracker>
    {
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
            *value = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageChangeReader>(this->shim().GetChangeReader());
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
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageChangedDeferral> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageChangedDeferral>
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
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs>
    {
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageChangedDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageManager2Statics> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageManager2Statics>
    {
        int32_t __stdcall RegisterTransportAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().RegisterTransportAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTransportAsync(void* transportId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessageTransport>>(this->shim().GetTransportAsync(*reinterpret_cast<hstring const*>(&transportId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatic> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatic>
    {
        int32_t __stdcall GetTransportsAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatMessageTransport>>>(this->shim().GetTransportsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestStoreAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessageStore>>(this->shim().RequestStoreAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowComposeSmsMessageAsync(void* message, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ShowComposeSmsMessageAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowSmsSettings() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowSmsSettings();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatics3> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatics3>
    {
        int32_t __stdcall RequestSyncManagerAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatSyncManager>>(this->shim().RequestSyncManagerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails>
    {
        int32_t __stdcall get_ChatMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessage>(this->shim().ChatMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2>
    {
        int32_t __stdcall get_ShouldDisplayToast(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().ShouldDisplayToast());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShouldUpdateDetailText(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().ShouldUpdateDetailText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShouldUpdateBadge(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().ShouldUpdateBadge());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShouldUpdateActionCenter(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().ShouldUpdateActionCenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageReader> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageReader>
    {
        int32_t __stdcall ReadBatchAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatMessage>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageReader2> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageReader2>
    {
        int32_t __stdcall ReadBatchWithCountAsync(int32_t count, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatMessage>>>(this->shim().ReadBatchAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageStore> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageStore>
    {
        int32_t __stdcall get_ChangeTracker(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageChangeTracker>(this->shim().ChangeTracker());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteMessageAsync(void* localMessageId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteMessageAsync(*reinterpret_cast<hstring const*>(&localMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DownloadMessageAsync(void* localChatMessageId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DownloadMessageAsync(*reinterpret_cast<hstring const*>(&localChatMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageAsync(void* localChatMessageId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessage>>(this->shim().GetMessageAsync(*reinterpret_cast<hstring const*>(&localChatMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageReader1(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageReader>(this->shim().GetMessageReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageReader2(int64_t recentTimeLimit, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageReader>(this->shim().GetMessageReader(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&recentTimeLimit)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MarkMessageReadAsync(void* localChatMessageId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MarkMessageReadAsync(*reinterpret_cast<hstring const*>(&localChatMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetrySendMessageAsync(void* localChatMessageId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RetrySendMessageAsync(*reinterpret_cast<hstring const*>(&localChatMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendMessageAsync(void* chatMessage, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SendMessageAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatMessage const*>(&chatMessage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ValidateMessage(void* chatMessage, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageValidationResult>(this->shim().ValidateMessage(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatMessage const*>(&chatMessage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_MessageChanged(void* value, winrt::event_token* returnValue) noexcept final try
        {
            zero_abi<winrt::event_token>(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::event_token>(this->shim().MessageChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::ChatMessageStore, winrt::Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MessageChanged(winrt::event_token value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MessageChanged(*reinterpret_cast<winrt::event_token const*>(&value));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageStore2> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageStore2>
    {
        int32_t __stdcall ForwardMessageAsync(void* localChatMessageId, void* addresses, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessage>>(this->shim().ForwardMessageAsync(*reinterpret_cast<hstring const*>(&localChatMessageId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&addresses)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversationAsync(void* conversationId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatConversation>>(this->shim().GetConversationAsync(*reinterpret_cast<hstring const*>(&conversationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversationForTransportsAsync(void* conversationId, void* transportIds, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatConversation>>(this->shim().GetConversationAsync(*reinterpret_cast<hstring const*>(&conversationId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&transportIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversationFromThreadingInfoAsync(void* threadingInfo, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatConversation>>(this->shim().GetConversationFromThreadingInfoAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingInfo const*>(&threadingInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversationReader(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatConversationReader>(this->shim().GetConversationReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversationForTransportsReader(void* transportIds, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatConversationReader>(this->shim().GetConversationReader(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&transportIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMessageByRemoteIdAsync(void* transportId, void* remoteId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessage>>(this->shim().GetMessageByRemoteIdAsync(*reinterpret_cast<hstring const*>(&transportId), *reinterpret_cast<hstring const*>(&remoteId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetUnseenCountAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<int32_t>>(this->shim().GetUnseenCountAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetUnseenCountForTransportsReaderAsync(void* transportIds, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<int32_t>>(this->shim().GetUnseenCountAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&transportIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MarkAsSeenAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MarkAsSeenAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MarkAsSeenForTransportsAsync(void* transportIds, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MarkAsSeenAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&transportIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSearchReader(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatSearchReader>(this->shim().GetSearchReader(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatQueryOptions const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SaveMessageAsync(void* chatMessage, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SaveMessageAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatMessage const*>(&chatMessage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCancelDownloadMessageAsync(void* localChatMessageId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryCancelDownloadMessageAsync(*reinterpret_cast<hstring const*>(&localChatMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCancelSendMessageAsync(void* localChatMessageId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryCancelSendMessageAsync(*reinterpret_cast<hstring const*>(&localChatMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StoreChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StoreChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::ChatMessageStore, winrt::Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StoreChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StoreChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageStore3> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageStore3>
    {
        int32_t __stdcall GetMessageBySyncIdAsync(void* syncId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessage>>(this->shim().GetMessageBySyncIdAsync(*reinterpret_cast<hstring const*>(&syncId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs>
    {
        int32_t __stdcall get_Id(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatStoreChangedEventKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageTransport> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageTransport>
    {
        int32_t __stdcall get_IsAppSetAsNotificationProvider(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAppSetAsNotificationProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsActive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransportFriendlyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TransportFriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransportId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TransportId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestSetAsNotificationProviderAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RequestSetAsNotificationProviderAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageTransport2> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageTransport2>
    {
        int32_t __stdcall get_Configuration(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration>(this->shim().Configuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransportKind(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageTransportKind>(this->shim().TransportKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration>
    {
        int32_t __stdcall get_MaxAttachmentCount(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().MaxAttachmentCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxMessageSizeInKilobytes(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().MaxMessageSizeInKilobytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxRecipientCount(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().MaxRecipientCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedVideoFormat(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().SupportedVideoFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedProperties(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().ExtendedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatMessageValidationResult> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatMessageValidationResult>
    {
        int32_t __stdcall get_MaxPartCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().MaxPartCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PartCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().PartCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemainingCharacterCountInPart(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().RemainingCharacterCountInPart());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageValidationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatQueryOptions> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatQueryOptions>
    {
        int32_t __stdcall get_SearchString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().SearchString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SearchString(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SearchString(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo>
    {
        int32_t __stdcall get_TransportAddress(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().TransportAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TransportAddress(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransportAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeliveryTime(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().DeliveryTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DeliveryTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeliveryTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReadTime(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ReadTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReadTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransportErrorCodeCategory(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatTransportErrorCodeCategory>(this->shim().TransportErrorCodeCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransportInterpretedErrorCode(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatTransportInterpretedErrorCode>(this->shim().TransportInterpretedErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransportErrorCode(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().TransportErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsErrorPermanent(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsErrorPermanent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatMessageStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatSearchReader> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatSearchReader>
    {
        int32_t __stdcall ReadBatchAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::IChatItem>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadBatchWithCountAsync(int32_t count, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::IChatItem>>>(this->shim().ReadBatchAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatSyncConfiguration> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatSyncConfiguration>
    {
        int32_t __stdcall get_IsSyncEnabled(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSyncEnabled());
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
        int32_t __stdcall get_RestoreHistorySpan(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatRestoreHistorySpan>(this->shim().RestoreHistorySpan());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RestoreHistorySpan(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RestoreHistorySpan(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatRestoreHistorySpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IChatSyncManager> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IChatSyncManager>
    {
        int32_t __stdcall get_Configuration(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::ChatSyncConfiguration>(this->shim().Configuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AssociateAccountAsync(void* webAccount, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AssociateAccountAsync(*reinterpret_cast<winrt::Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnassociateAccountAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().UnassociateAccountAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsAccountAssociated(void* webAccount, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsAccountAssociated(*reinterpret_cast<winrt::Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartSync() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartSync();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetConfigurationAsync(void* configuration, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetConfigurationAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatSyncConfiguration const*>(&configuration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessage> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessage>
    {
        int32_t __stdcall get_TransportId(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().TransportId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Title(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Text(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPinRequired(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsPinRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Actions(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAction>>(this->shim().Actions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendResponseAsync(void* action, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SendResponseAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAction const*>(&action)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendResponseWithPinAsync(void* action, void* pin, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SendResponseWithPinAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAction const*>(&action), *reinterpret_cast<hstring const*>(&pin)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAction> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAction>
    {
        int32_t __stdcall get_Label(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs>
    {
        int32_t __stdcall get_IsMessageAvailable(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsMessageAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Message(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails>
    {
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageManager> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageManager>
    {
        int32_t __stdcall add_MessageAvailableChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MessageAvailableChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageManager, winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MessageAvailableChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MessageAvailableChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics>
    {
        int32_t __stdcall GetEndUserMessageManager(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageManager>(this->shim().GetEndUserMessageManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTransportsAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::RcsTransport>>>(this->shim().GetTransportsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTransportAsync(void* transportId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::RcsTransport>>(this->shim().GetTransportAsync(*reinterpret_cast<hstring const*>(&transportId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LeaveConversationAsync(void* conversation, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().LeaveConversationAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::ChatConversation const*>(&conversation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics2> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics2>
    {
        int32_t __stdcall add_TransportListChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TransportListChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TransportListChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransportListChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs>
    {
        int32_t __stdcall get_ServiceKind(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::RcsServiceKind>(this->shim().ServiceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IRcsTransport> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IRcsTransport>
    {
        int32_t __stdcall get_ExtendedProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().ExtendedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsActive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransportFriendlyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TransportFriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransportId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TransportId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Configuration(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Chat::RcsTransportConfiguration>(this->shim().Configuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsStoreAndForwardEnabled(int32_t serviceKind, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsStoreAndForwardEnabled(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::RcsServiceKind const*>(&serviceKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsServiceKindSupported(int32_t serviceKind, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsServiceKindSupported(*reinterpret_cast<winrt::Windows::ApplicationModel::Chat::RcsServiceKind const*>(&serviceKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ServiceKindSupportedChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ServiceKindSupportedChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Chat::RcsTransport, winrt::Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ServiceKindSupportedChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ServiceKindSupportedChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IRcsTransportConfiguration> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IRcsTransportConfiguration>
    {
        int32_t __stdcall get_MaxAttachmentCount(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().MaxAttachmentCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxMessageSizeInKilobytes(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().MaxMessageSizeInKilobytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxGroupMessageSizeInKilobytes(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().MaxGroupMessageSizeInKilobytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxRecipientCount(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().MaxRecipientCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxFileSizeInKilobytes(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().MaxFileSizeInKilobytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WarningFileSizeInKilobytes(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().WarningFileSizeInKilobytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs>
    {
        int32_t __stdcall get_TransportId(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().TransportId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ParticipantAddress(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().ParticipantAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsComposing(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsComposing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Chat
{
    inline auto ChatCapabilitiesManager::GetCachedCapabilitiesAsync(param::hstring const& address)
    {
        return impl::call_factory<ChatCapabilitiesManager, IChatCapabilitiesManagerStatics>([&](IChatCapabilitiesManagerStatics const& f) { return f.GetCachedCapabilitiesAsync(address); });
    }
    inline auto ChatCapabilitiesManager::GetCapabilitiesFromNetworkAsync(param::hstring const& address)
    {
        return impl::call_factory<ChatCapabilitiesManager, IChatCapabilitiesManagerStatics>([&](IChatCapabilitiesManagerStatics const& f) { return f.GetCapabilitiesFromNetworkAsync(address); });
    }
    inline auto ChatCapabilitiesManager::GetCachedCapabilitiesAsync(param::hstring const& address, param::hstring const& transportId)
    {
        return impl::call_factory<ChatCapabilitiesManager, IChatCapabilitiesManagerStatics2>([&](IChatCapabilitiesManagerStatics2 const& f) { return f.GetCachedCapabilitiesAsync(address, transportId); });
    }
    inline auto ChatCapabilitiesManager::GetCapabilitiesFromNetworkAsync(param::hstring const& address, param::hstring const& transportId)
    {
        return impl::call_factory<ChatCapabilitiesManager, IChatCapabilitiesManagerStatics2>([&](IChatCapabilitiesManagerStatics2 const& f) { return f.GetCapabilitiesFromNetworkAsync(address, transportId); });
    }
    inline ChatConversationThreadingInfo::ChatConversationThreadingInfo() :
        ChatConversationThreadingInfo(impl::call_factory_cast<ChatConversationThreadingInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), ChatConversationThreadingInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ChatConversationThreadingInfo>(); }))
    {
    }
    inline ChatMessage::ChatMessage() :
        ChatMessage(impl::call_factory_cast<ChatMessage(*)(winrt::Windows::Foundation::IActivationFactory const&), ChatMessage>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ChatMessage>(); }))
    {
    }
    inline ChatMessageAttachment::ChatMessageAttachment(param::hstring const& mimeType, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& dataStreamReference) :
        ChatMessageAttachment(impl::call_factory<ChatMessageAttachment, IChatMessageAttachmentFactory>([&](IChatMessageAttachmentFactory const& f) { return f.CreateChatMessageAttachment(mimeType, dataStreamReference); }))
    {
    }
    inline auto ChatMessageBlocking::MarkMessageAsBlockedAsync(param::hstring const& localChatMessageId, bool blocked)
    {
        return impl::call_factory<ChatMessageBlocking, IChatMessageBlockingStatic>([&](IChatMessageBlockingStatic const& f) { return f.MarkMessageAsBlockedAsync(localChatMessageId, blocked); });
    }
    inline auto ChatMessageManager::RegisterTransportAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<hstring>(*)(IChatMessageManager2Statics const&), ChatMessageManager, IChatMessageManager2Statics>([](IChatMessageManager2Statics const& f) { return f.RegisterTransportAsync(); });
    }
    inline auto ChatMessageManager::GetTransportAsync(param::hstring const& transportId)
    {
        return impl::call_factory<ChatMessageManager, IChatMessageManager2Statics>([&](IChatMessageManager2Statics const& f) { return f.GetTransportAsync(transportId); });
    }
    inline auto ChatMessageManager::GetTransportsAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::ChatMessageTransport>>(*)(IChatMessageManagerStatic const&), ChatMessageManager, IChatMessageManagerStatic>([](IChatMessageManagerStatic const& f) { return f.GetTransportsAsync(); });
    }
    inline auto ChatMessageManager::RequestStoreAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatMessageStore>(*)(IChatMessageManagerStatic const&), ChatMessageManager, IChatMessageManagerStatic>([](IChatMessageManagerStatic const& f) { return f.RequestStoreAsync(); });
    }
    inline auto ChatMessageManager::ShowComposeSmsMessageAsync(winrt::Windows::ApplicationModel::Chat::ChatMessage const& message)
    {
        return impl::call_factory<ChatMessageManager, IChatMessageManagerStatic>([&](IChatMessageManagerStatic const& f) { return f.ShowComposeSmsMessageAsync(message); });
    }
    inline auto ChatMessageManager::ShowSmsSettings()
    {
        impl::call_factory_cast<void(*)(IChatMessageManagerStatic const&), ChatMessageManager, IChatMessageManagerStatic>([](IChatMessageManagerStatic const& f) { return f.ShowSmsSettings(); });
    }
    inline auto ChatMessageManager::RequestSyncManagerAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Chat::ChatSyncManager>(*)(IChatMessageManagerStatics3 const&), ChatMessageManager, IChatMessageManagerStatics3>([](IChatMessageManagerStatics3 const& f) { return f.RequestSyncManagerAsync(); });
    }
    inline ChatQueryOptions::ChatQueryOptions() :
        ChatQueryOptions(impl::call_factory_cast<ChatQueryOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), ChatQueryOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ChatQueryOptions>(); }))
    {
    }
    inline ChatRecipientDeliveryInfo::ChatRecipientDeliveryInfo() :
        ChatRecipientDeliveryInfo(impl::call_factory_cast<ChatRecipientDeliveryInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), ChatRecipientDeliveryInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ChatRecipientDeliveryInfo>(); }))
    {
    }
    inline auto RcsManager::GetEndUserMessageManager()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageManager(*)(IRcsManagerStatics const&), RcsManager, IRcsManagerStatics>([](IRcsManagerStatics const& f) { return f.GetEndUserMessageManager(); });
    }
    inline auto RcsManager::GetTransportsAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Chat::RcsTransport>>(*)(IRcsManagerStatics const&), RcsManager, IRcsManagerStatics>([](IRcsManagerStatics const& f) { return f.GetTransportsAsync(); });
    }
    inline auto RcsManager::GetTransportAsync(param::hstring const& transportId)
    {
        return impl::call_factory<RcsManager, IRcsManagerStatics>([&](IRcsManagerStatics const& f) { return f.GetTransportAsync(transportId); });
    }
    inline auto RcsManager::LeaveConversationAsync(winrt::Windows::ApplicationModel::Chat::ChatConversation const& conversation)
    {
        return impl::call_factory<RcsManager, IRcsManagerStatics>([&](IRcsManagerStatics const& f) { return f.LeaveConversationAsync(conversation); });
    }
    inline auto RcsManager::TransportListChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<RcsManager, IRcsManagerStatics2>([&](IRcsManagerStatics2 const& f) { return f.TransportListChanged(handler); });
    }
    inline RcsManager::TransportListChanged_revoker RcsManager::TransportListChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<RcsManager, winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics2>();
        return { f, f.TransportListChanged(handler) };
    }
    inline auto RcsManager::TransportListChanged(winrt::event_token const& token)
    {
        impl::call_factory<RcsManager, IRcsManagerStatics2>([&](IRcsManagerStatics2 const& f) { return f.TransportListChanged(token); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatConversation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatConversation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatConversationReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessage2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessage3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessage4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageBlockingStatic> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageChange> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageChangeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageChangeTracker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageChangedDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageManager2Statics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatic> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageReader2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageStore2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageStore3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageTransport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageTransport2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageValidationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatQueryOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatSearchReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatSyncConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatSyncManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsTransport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsTransportConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatCapabilitiesManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatConversation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatConversationReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageAttachment> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageBlocking> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageChange> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageChangeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageChangeTracker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageChangedDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageNotificationTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageTransport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageValidationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatQueryOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatSearchReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatSyncConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatSyncManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsTransport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsTransportConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
