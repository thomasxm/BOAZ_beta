// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Networking_Proximity_H
#define WINRT_Windows_Networking_Proximity_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Networking.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Networking.Proximity.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::PeerInformation) consume_Windows_Networking_Proximity_IConnectionRequestedEventArgs<D>::PeerInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IConnectionRequestedEventArgs)->get_PeerInformation(&value));
        return winrt::Windows::Networking::Proximity::PeerInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AllowBluetooth() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->get_AllowBluetooth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AllowBluetooth(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->put_AllowBluetooth(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AllowInfrastructure() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->get_AllowInfrastructure(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AllowInfrastructure(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->put_AllowInfrastructure(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AllowWiFiDirect() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->get_AllowWiFiDirect(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AllowWiFiDirect(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->put_AllowWiFiDirect(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::DisplayName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->put_DisplayName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::PeerDiscoveryTypes) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::SupportedDiscoveryTypes() const
    {
        winrt::Windows::Networking::Proximity::PeerDiscoveryTypes value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->get_SupportedDiscoveryTypes(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AlternateIdentities() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->get_AlternateIdentities(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::Start(param::hstring const& peerMessage) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->StartWithMessage(*(void**)(&peerMessage)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::TriggeredConnectionStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->add_TriggeredConnectionStateChanged(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::TriggeredConnectionStateChanged_revoker consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::TriggeredConnectionStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TriggeredConnectionStateChanged_revoker>(this, TriggeredConnectionStateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::TriggeredConnectionStateChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->remove_TriggeredConnectionStateChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::ConnectionRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::ConnectionRequestedEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->add_ConnectionRequested(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::ConnectionRequested_revoker consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::ConnectionRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::ConnectionRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ConnectionRequested_revoker>(this, ConnectionRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::ConnectionRequested(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->remove_ConnectionRequested(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::Proximity::PeerInformation>>) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::FindAllPeersAsync() const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->FindAllPeersAsync(&asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::Proximity::PeerInformation>>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::Sockets::StreamSocket>) consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::ConnectAsync(winrt::Windows::Networking::Proximity::PeerInformation const& peerInformation) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics)->ConnectAsync(*(void**)(&peerInformation), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::Sockets::StreamSocket>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::PeerRole) consume_Windows_Networking_Proximity_IPeerFinderStatics2<D>::Role() const
    {
        winrt::Windows::Networking::Proximity::PeerRole value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics2)->get_Role(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerFinderStatics2<D>::Role(winrt::Windows::Networking::Proximity::PeerRole const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics2)->put_Role(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Networking_Proximity_IPeerFinderStatics2<D>::DiscoveryData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics2)->get_DiscoveryData(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerFinderStatics2<D>::DiscoveryData(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics2)->put_DiscoveryData(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::PeerWatcher) consume_Windows_Networking_Proximity_IPeerFinderStatics2<D>::CreateWatcher() const
    {
        void* watcher{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerFinderStatics2)->CreateWatcher(&watcher));
        return winrt::Windows::Networking::Proximity::PeerWatcher{ watcher, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Proximity_IPeerInformation<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerInformation)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Proximity_IPeerInformation3<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerInformation3)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Networking_Proximity_IPeerInformation3<D>::DiscoveryData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerInformation3)->get_DiscoveryData(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_Proximity_IPeerInformationWithHostAndService<D>::HostName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerInformationWithHostAndService)->get_HostName(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Proximity_IPeerInformationWithHostAndService<D>::ServiceName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerInformationWithHostAndService)->get_ServiceName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Proximity_IPeerWatcher<D>::Added(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerWatcher)->add_Added(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Networking_Proximity_IPeerWatcher<D>::Added_revoker consume_Windows_Networking_Proximity_IPeerWatcher<D>::Added(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const& handler) const
    {
        return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerWatcher<D>::Added(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerWatcher)->remove_Added(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Proximity_IPeerWatcher<D>::Removed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerWatcher)->add_Removed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Networking_Proximity_IPeerWatcher<D>::Removed_revoker consume_Windows_Networking_Proximity_IPeerWatcher<D>::Removed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const& handler) const
    {
        return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerWatcher<D>::Removed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerWatcher)->remove_Removed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Proximity_IPeerWatcher<D>::Updated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerWatcher)->add_Updated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Networking_Proximity_IPeerWatcher<D>::Updated_revoker consume_Windows_Networking_Proximity_IPeerWatcher<D>::Updated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const& handler) const
    {
        return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerWatcher<D>::Updated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerWatcher)->remove_Updated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Proximity_IPeerWatcher<D>::EnumerationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerWatcher)->add_EnumerationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Networking_Proximity_IPeerWatcher<D>::EnumerationCompleted_revoker consume_Windows_Networking_Proximity_IPeerWatcher<D>::EnumerationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerWatcher)->remove_EnumerationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Proximity_IPeerWatcher<D>::Stopped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerWatcher)->add_Stopped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Networking_Proximity_IPeerWatcher<D>::Stopped_revoker consume_Windows_Networking_Proximity_IPeerWatcher<D>::Stopped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerWatcher)->remove_Stopped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::PeerWatcherStatus) consume_Windows_Networking_Proximity_IPeerWatcher<D>::Status() const
    {
        winrt::Windows::Networking::Proximity::PeerWatcherStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerWatcher)->get_Status(reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerWatcher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerWatcher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IPeerWatcher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IPeerWatcher)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_Networking_Proximity_IProximityDevice<D>::SubscribeForMessage(param::hstring const& messageType, winrt::Windows::Networking::Proximity::MessageReceivedHandler const& messageReceivedHandler) const
    {
        int64_t subscriptionId{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->SubscribeForMessage(*(void**)(&messageType), *(void**)(&messageReceivedHandler), &subscriptionId));
        return subscriptionId;
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_Networking_Proximity_IProximityDevice<D>::PublishMessage(param::hstring const& messageType, param::hstring const& message) const
    {
        int64_t messageId{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->PublishMessage(*(void**)(&messageType), *(void**)(&message), &messageId));
        return messageId;
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_Networking_Proximity_IProximityDevice<D>::PublishMessage(param::hstring const& messageType, param::hstring const& message, winrt::Windows::Networking::Proximity::MessageTransmittedHandler const& messageTransmittedHandler) const
    {
        int64_t messageId{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->PublishMessageWithCallback(*(void**)(&messageType), *(void**)(&message), *(void**)(&messageTransmittedHandler), &messageId));
        return messageId;
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_Networking_Proximity_IProximityDevice<D>::PublishBinaryMessage(param::hstring const& messageType, winrt::Windows::Storage::Streams::IBuffer const& message) const
    {
        int64_t messageId{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->PublishBinaryMessage(*(void**)(&messageType), *(void**)(&message), &messageId));
        return messageId;
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_Networking_Proximity_IProximityDevice<D>::PublishBinaryMessage(param::hstring const& messageType, winrt::Windows::Storage::Streams::IBuffer const& message, winrt::Windows::Networking::Proximity::MessageTransmittedHandler const& messageTransmittedHandler) const
    {
        int64_t messageId{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->PublishBinaryMessageWithCallback(*(void**)(&messageType), *(void**)(&message), *(void**)(&messageTransmittedHandler), &messageId));
        return messageId;
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_Networking_Proximity_IProximityDevice<D>::PublishUriMessage(winrt::Windows::Foundation::Uri const& message) const
    {
        int64_t messageId{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->PublishUriMessage(*(void**)(&message), &messageId));
        return messageId;
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_Networking_Proximity_IProximityDevice<D>::PublishUriMessage(winrt::Windows::Foundation::Uri const& message, winrt::Windows::Networking::Proximity::MessageTransmittedHandler const& messageTransmittedHandler) const
    {
        int64_t messageId{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->PublishUriMessageWithCallback(*(void**)(&message), *(void**)(&messageTransmittedHandler), &messageId));
        return messageId;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IProximityDevice<D>::StopSubscribingForMessage(int64_t subscriptionId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->StopSubscribingForMessage(subscriptionId));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IProximityDevice<D>::StopPublishingMessage(int64_t messageId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->StopPublishingMessage(messageId));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceArrived(winrt::Windows::Networking::Proximity::DeviceArrivedEventHandler const& arrivedHandler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->add_DeviceArrived(*(void**)(&arrivedHandler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceArrived_revoker consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceArrived(auto_revoke_t, winrt::Windows::Networking::Proximity::DeviceArrivedEventHandler const& arrivedHandler) const
    {
        return impl::make_event_revoker<D, DeviceArrived_revoker>(this, DeviceArrived(arrivedHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceArrived(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->remove_DeviceArrived(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceDeparted(winrt::Windows::Networking::Proximity::DeviceDepartedEventHandler const& departedHandler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->add_DeviceDeparted(*(void**)(&departedHandler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceDeparted_revoker consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceDeparted(auto_revoke_t, winrt::Windows::Networking::Proximity::DeviceDepartedEventHandler const& departedHandler) const
    {
        return impl::make_event_revoker<D, DeviceDeparted_revoker>(this, DeviceDeparted(departedHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceDeparted(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->remove_DeviceDeparted(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Networking_Proximity_IProximityDevice<D>::MaxMessageBytes() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->get_MaxMessageBytes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Networking_Proximity_IProximityDevice<D>::BitsPerSecond() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->get_BitsPerSecond(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDevice)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Proximity_IProximityDeviceStatics<D>::GetDeviceSelector() const
    {
        void* selector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDeviceStatics)->GetDeviceSelector(&selector));
        return hstring{ selector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::ProximityDevice) consume_Windows_Networking_Proximity_IProximityDeviceStatics<D>::GetDefault() const
    {
        void* proximityDevice{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDeviceStatics)->GetDefault(&proximityDevice));
        return winrt::Windows::Networking::Proximity::ProximityDevice{ proximityDevice, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::ProximityDevice) consume_Windows_Networking_Proximity_IProximityDeviceStatics<D>::FromId(param::hstring const& deviceId) const
    {
        void* proximityDevice{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityDeviceStatics)->FromId(*(void**)(&deviceId), &proximityDevice));
        return winrt::Windows::Networking::Proximity::ProximityDevice{ proximityDevice, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Proximity_IProximityMessage<D>::MessageType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityMessage)->get_MessageType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_Networking_Proximity_IProximityMessage<D>::SubscriptionId() const
    {
        int64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityMessage)->get_SubscriptionId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Networking_Proximity_IProximityMessage<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityMessage)->get_Data(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Proximity_IProximityMessage<D>::DataAsString() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::IProximityMessage)->get_DataAsString(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Proximity::TriggeredConnectState) consume_Windows_Networking_Proximity_ITriggeredConnectionStateChangedEventArgs<D>::State() const
    {
        winrt::Windows::Networking::Proximity::TriggeredConnectState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Networking_Proximity_ITriggeredConnectionStateChangedEventArgs<D>::Id() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs)->get_Id(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::StreamSocket) consume_Windows_Networking_Proximity_ITriggeredConnectionStateChangedEventArgs<D>::Socket() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs)->get_Socket(&value));
        return winrt::Windows::Networking::Sockets::StreamSocket{ value, take_ownership_from_abi };
    }
    template <typename H> struct delegate<winrt::Windows::Networking::Proximity::DeviceArrivedEventHandler, H> final : implements_delegate<winrt::Windows::Networking::Proximity::DeviceArrivedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Networking::Proximity::DeviceArrivedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Networking::Proximity::ProximityDevice const*>(&sender));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::Networking::Proximity::DeviceDepartedEventHandler, H> final : implements_delegate<winrt::Windows::Networking::Proximity::DeviceDepartedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Networking::Proximity::DeviceDepartedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Networking::Proximity::ProximityDevice const*>(&sender));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::Networking::Proximity::MessageReceivedHandler, H> final : implements_delegate<winrt::Windows::Networking::Proximity::MessageReceivedHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Networking::Proximity::MessageReceivedHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* message) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Networking::Proximity::ProximityDevice const*>(&sender), *reinterpret_cast<winrt::Windows::Networking::Proximity::ProximityMessage const*>(&message));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::Networking::Proximity::MessageTransmittedHandler, H> final : implements_delegate<winrt::Windows::Networking::Proximity::MessageTransmittedHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Networking::Proximity::MessageTransmittedHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, int64_t messageId) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Networking::Proximity::ProximityDevice const*>(&sender), messageId);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Proximity::IConnectionRequestedEventArgs> : produce_base<D, winrt::Windows::Networking::Proximity::IConnectionRequestedEventArgs>
    {
        int32_t __stdcall get_PeerInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Proximity::PeerInformation>(this->shim().PeerInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Proximity::IPeerFinderStatics> : produce_base<D, winrt::Windows::Networking::Proximity::IPeerFinderStatics>
    {
        int32_t __stdcall get_AllowBluetooth(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowBluetooth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowBluetooth(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowBluetooth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowInfrastructure(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowInfrastructure());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowInfrastructure(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowInfrastructure(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowWiFiDirect(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowWiFiDirect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowWiFiDirect(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowWiFiDirect(value);
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
        int32_t __stdcall get_SupportedDiscoveryTypes(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Proximity::PeerDiscoveryTypes>(this->shim().SupportedDiscoveryTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AlternateIdentities(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().AlternateIdentities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartWithMessage(void* peerMessage) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start(*reinterpret_cast<hstring const*>(&peerMessage));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_TriggeredConnectionStateChanged(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().TriggeredConnectionStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TriggeredConnectionStateChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TriggeredConnectionStateChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_ConnectionRequested(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().ConnectionRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::ConnectionRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ConnectionRequested(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConnectionRequested(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall FindAllPeersAsync(void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::Proximity::PeerInformation>>>(this->shim().FindAllPeersAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectAsync(void* peerInformation, void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::Sockets::StreamSocket>>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Networking::Proximity::PeerInformation const*>(&peerInformation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Proximity::IPeerFinderStatics2> : produce_base<D, winrt::Windows::Networking::Proximity::IPeerFinderStatics2>
    {
        int32_t __stdcall get_Role(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Proximity::PeerRole>(this->shim().Role());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Role(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Role(*reinterpret_cast<winrt::Windows::Networking::Proximity::PeerRole const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DiscoveryData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().DiscoveryData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DiscoveryData(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DiscoveryData(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWatcher(void** watcher) noexcept final try
        {
            clear_abi(watcher);
            typename D::abi_guard guard(this->shim());
            *watcher = detach_from<winrt::Windows::Networking::Proximity::PeerWatcher>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Proximity::IPeerInformation> : produce_base<D, winrt::Windows::Networking::Proximity::IPeerInformation>
    {
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Proximity::IPeerInformation3> : produce_base<D, winrt::Windows::Networking::Proximity::IPeerInformation3>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DiscoveryData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().DiscoveryData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Proximity::IPeerInformationWithHostAndService> : produce_base<D, winrt::Windows::Networking::Proximity::IPeerInformationWithHostAndService>
    {
        int32_t __stdcall get_HostName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().HostName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ServiceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Proximity::IPeerWatcher> : produce_base<D, winrt::Windows::Networking::Proximity::IPeerWatcher>
    {
        int32_t __stdcall add_Added(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Added(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Removed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Removed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Updated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Networking::Proximity::PeerInformation> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Updated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EnumerationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Stopped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Proximity::PeerWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Stopped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Status(int32_t* status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *status = detach_from<winrt::Windows::Networking::Proximity::PeerWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Proximity::IProximityDevice> : produce_base<D, winrt::Windows::Networking::Proximity::IProximityDevice>
    {
        int32_t __stdcall SubscribeForMessage(void* messageType, void* messageReceivedHandler, int64_t* subscriptionId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *subscriptionId = detach_from<int64_t>(this->shim().SubscribeForMessage(*reinterpret_cast<hstring const*>(&messageType), *reinterpret_cast<winrt::Windows::Networking::Proximity::MessageReceivedHandler const*>(&messageReceivedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PublishMessage(void* messageType, void* message, int64_t* messageId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *messageId = detach_from<int64_t>(this->shim().PublishMessage(*reinterpret_cast<hstring const*>(&messageType), *reinterpret_cast<hstring const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PublishMessageWithCallback(void* messageType, void* message, void* messageTransmittedHandler, int64_t* messageId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *messageId = detach_from<int64_t>(this->shim().PublishMessage(*reinterpret_cast<hstring const*>(&messageType), *reinterpret_cast<hstring const*>(&message), *reinterpret_cast<winrt::Windows::Networking::Proximity::MessageTransmittedHandler const*>(&messageTransmittedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PublishBinaryMessage(void* messageType, void* message, int64_t* messageId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *messageId = detach_from<int64_t>(this->shim().PublishBinaryMessage(*reinterpret_cast<hstring const*>(&messageType), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PublishBinaryMessageWithCallback(void* messageType, void* message, void* messageTransmittedHandler, int64_t* messageId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *messageId = detach_from<int64_t>(this->shim().PublishBinaryMessage(*reinterpret_cast<hstring const*>(&messageType), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&message), *reinterpret_cast<winrt::Windows::Networking::Proximity::MessageTransmittedHandler const*>(&messageTransmittedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PublishUriMessage(void* message, int64_t* messageId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *messageId = detach_from<int64_t>(this->shim().PublishUriMessage(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PublishUriMessageWithCallback(void* message, void* messageTransmittedHandler, int64_t* messageId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *messageId = detach_from<int64_t>(this->shim().PublishUriMessage(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&message), *reinterpret_cast<winrt::Windows::Networking::Proximity::MessageTransmittedHandler const*>(&messageTransmittedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopSubscribingForMessage(int64_t subscriptionId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopSubscribingForMessage(subscriptionId);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopPublishingMessage(int64_t messageId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopPublishingMessage(messageId);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_DeviceArrived(void* arrivedHandler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().DeviceArrived(*reinterpret_cast<winrt::Windows::Networking::Proximity::DeviceArrivedEventHandler const*>(&arrivedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DeviceArrived(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeviceArrived(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_DeviceDeparted(void* departedHandler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().DeviceDeparted(*reinterpret_cast<winrt::Windows::Networking::Proximity::DeviceDepartedEventHandler const*>(&departedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DeviceDeparted(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeviceDeparted(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall get_MaxMessageBytes(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxMessageBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BitsPerSecond(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().BitsPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Proximity::IProximityDeviceStatics> : produce_base<D, winrt::Windows::Networking::Proximity::IProximityDeviceStatics>
    {
        int32_t __stdcall GetDeviceSelector(void** selector) noexcept final try
        {
            clear_abi(selector);
            typename D::abi_guard guard(this->shim());
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefault(void** proximityDevice) noexcept final try
        {
            clear_abi(proximityDevice);
            typename D::abi_guard guard(this->shim());
            *proximityDevice = detach_from<winrt::Windows::Networking::Proximity::ProximityDevice>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromId(void* deviceId, void** proximityDevice) noexcept final try
        {
            clear_abi(proximityDevice);
            typename D::abi_guard guard(this->shim());
            *proximityDevice = detach_from<winrt::Windows::Networking::Proximity::ProximityDevice>(this->shim().FromId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Proximity::IProximityMessage> : produce_base<D, winrt::Windows::Networking::Proximity::IProximityMessage>
    {
        int32_t __stdcall get_MessageType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MessageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SubscriptionId(int64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int64_t>(this->shim().SubscriptionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DataAsString(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DataAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs> : produce_base<D, winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs>
    {
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Proximity::TriggeredConnectState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Socket(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::StreamSocket>(this->shim().Socket());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Networking::Proximity
{
    constexpr auto operator|(PeerDiscoveryTypes const left, PeerDiscoveryTypes const right) noexcept
    {
        return static_cast<PeerDiscoveryTypes>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(PeerDiscoveryTypes& left, PeerDiscoveryTypes const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(PeerDiscoveryTypes const left, PeerDiscoveryTypes const right) noexcept
    {
        return static_cast<PeerDiscoveryTypes>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(PeerDiscoveryTypes& left, PeerDiscoveryTypes const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(PeerDiscoveryTypes const value) noexcept
    {
        return static_cast<PeerDiscoveryTypes>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(PeerDiscoveryTypes const left, PeerDiscoveryTypes const right) noexcept
    {
        return static_cast<PeerDiscoveryTypes>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(PeerDiscoveryTypes& left, PeerDiscoveryTypes const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto PeerFinder::AllowBluetooth()
    {
        return impl::call_factory_cast<bool(*)(IPeerFinderStatics const&), PeerFinder, IPeerFinderStatics>([](IPeerFinderStatics const& f) { return f.AllowBluetooth(); });
    }
    inline auto PeerFinder::AllowBluetooth(bool value)
    {
        impl::call_factory<PeerFinder, IPeerFinderStatics>([&](IPeerFinderStatics const& f) { return f.AllowBluetooth(value); });
    }
    inline auto PeerFinder::AllowInfrastructure()
    {
        return impl::call_factory_cast<bool(*)(IPeerFinderStatics const&), PeerFinder, IPeerFinderStatics>([](IPeerFinderStatics const& f) { return f.AllowInfrastructure(); });
    }
    inline auto PeerFinder::AllowInfrastructure(bool value)
    {
        impl::call_factory<PeerFinder, IPeerFinderStatics>([&](IPeerFinderStatics const& f) { return f.AllowInfrastructure(value); });
    }
    inline auto PeerFinder::AllowWiFiDirect()
    {
        return impl::call_factory_cast<bool(*)(IPeerFinderStatics const&), PeerFinder, IPeerFinderStatics>([](IPeerFinderStatics const& f) { return f.AllowWiFiDirect(); });
    }
    inline auto PeerFinder::AllowWiFiDirect(bool value)
    {
        impl::call_factory<PeerFinder, IPeerFinderStatics>([&](IPeerFinderStatics const& f) { return f.AllowWiFiDirect(value); });
    }
    inline auto PeerFinder::DisplayName()
    {
        return impl::call_factory_cast<hstring(*)(IPeerFinderStatics const&), PeerFinder, IPeerFinderStatics>([](IPeerFinderStatics const& f) { return f.DisplayName(); });
    }
    inline auto PeerFinder::DisplayName(param::hstring const& value)
    {
        impl::call_factory<PeerFinder, IPeerFinderStatics>([&](IPeerFinderStatics const& f) { return f.DisplayName(value); });
    }
    inline auto PeerFinder::SupportedDiscoveryTypes()
    {
        return impl::call_factory_cast<winrt::Windows::Networking::Proximity::PeerDiscoveryTypes(*)(IPeerFinderStatics const&), PeerFinder, IPeerFinderStatics>([](IPeerFinderStatics const& f) { return f.SupportedDiscoveryTypes(); });
    }
    inline auto PeerFinder::AlternateIdentities()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>(*)(IPeerFinderStatics const&), PeerFinder, IPeerFinderStatics>([](IPeerFinderStatics const& f) { return f.AlternateIdentities(); });
    }
    inline auto PeerFinder::Start()
    {
        impl::call_factory_cast<void(*)(IPeerFinderStatics const&), PeerFinder, IPeerFinderStatics>([](IPeerFinderStatics const& f) { return f.Start(); });
    }
    inline auto PeerFinder::Start(param::hstring const& peerMessage)
    {
        impl::call_factory<PeerFinder, IPeerFinderStatics>([&](IPeerFinderStatics const& f) { return f.Start(peerMessage); });
    }
    inline auto PeerFinder::Stop()
    {
        impl::call_factory_cast<void(*)(IPeerFinderStatics const&), PeerFinder, IPeerFinderStatics>([](IPeerFinderStatics const& f) { return f.Stop(); });
    }
    inline auto PeerFinder::TriggeredConnectionStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const& handler)
    {
        return impl::call_factory<PeerFinder, IPeerFinderStatics>([&](IPeerFinderStatics const& f) { return f.TriggeredConnectionStateChanged(handler); });
    }
    inline PeerFinder::TriggeredConnectionStateChanged_revoker PeerFinder::TriggeredConnectionStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const& handler)
    {
        auto f = get_activation_factory<PeerFinder, winrt::Windows::Networking::Proximity::IPeerFinderStatics>();
        return { f, f.TriggeredConnectionStateChanged(handler) };
    }
    inline auto PeerFinder::TriggeredConnectionStateChanged(winrt::event_token const& cookie)
    {
        impl::call_factory<PeerFinder, IPeerFinderStatics>([&](IPeerFinderStatics const& f) { return f.TriggeredConnectionStateChanged(cookie); });
    }
    inline auto PeerFinder::ConnectionRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::ConnectionRequestedEventArgs> const& handler)
    {
        return impl::call_factory<PeerFinder, IPeerFinderStatics>([&](IPeerFinderStatics const& f) { return f.ConnectionRequested(handler); });
    }
    inline PeerFinder::ConnectionRequested_revoker PeerFinder::ConnectionRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Networking::Proximity::ConnectionRequestedEventArgs> const& handler)
    {
        auto f = get_activation_factory<PeerFinder, winrt::Windows::Networking::Proximity::IPeerFinderStatics>();
        return { f, f.ConnectionRequested(handler) };
    }
    inline auto PeerFinder::ConnectionRequested(winrt::event_token const& cookie)
    {
        impl::call_factory<PeerFinder, IPeerFinderStatics>([&](IPeerFinderStatics const& f) { return f.ConnectionRequested(cookie); });
    }
    inline auto PeerFinder::FindAllPeersAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::Proximity::PeerInformation>>(*)(IPeerFinderStatics const&), PeerFinder, IPeerFinderStatics>([](IPeerFinderStatics const& f) { return f.FindAllPeersAsync(); });
    }
    inline auto PeerFinder::ConnectAsync(winrt::Windows::Networking::Proximity::PeerInformation const& peerInformation)
    {
        return impl::call_factory<PeerFinder, IPeerFinderStatics>([&](IPeerFinderStatics const& f) { return f.ConnectAsync(peerInformation); });
    }
    inline auto PeerFinder::Role()
    {
        return impl::call_factory_cast<winrt::Windows::Networking::Proximity::PeerRole(*)(IPeerFinderStatics2 const&), PeerFinder, IPeerFinderStatics2>([](IPeerFinderStatics2 const& f) { return f.Role(); });
    }
    inline auto PeerFinder::Role(winrt::Windows::Networking::Proximity::PeerRole const& value)
    {
        impl::call_factory<PeerFinder, IPeerFinderStatics2>([&](IPeerFinderStatics2 const& f) { return f.Role(value); });
    }
    inline auto PeerFinder::DiscoveryData()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::Streams::IBuffer(*)(IPeerFinderStatics2 const&), PeerFinder, IPeerFinderStatics2>([](IPeerFinderStatics2 const& f) { return f.DiscoveryData(); });
    }
    inline auto PeerFinder::DiscoveryData(winrt::Windows::Storage::Streams::IBuffer const& value)
    {
        impl::call_factory<PeerFinder, IPeerFinderStatics2>([&](IPeerFinderStatics2 const& f) { return f.DiscoveryData(value); });
    }
    inline auto PeerFinder::CreateWatcher()
    {
        return impl::call_factory_cast<winrt::Windows::Networking::Proximity::PeerWatcher(*)(IPeerFinderStatics2 const&), PeerFinder, IPeerFinderStatics2>([](IPeerFinderStatics2 const& f) { return f.CreateWatcher(); });
    }
    inline auto ProximityDevice::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IProximityDeviceStatics const&), ProximityDevice, IProximityDeviceStatics>([](IProximityDeviceStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto ProximityDevice::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Networking::Proximity::ProximityDevice(*)(IProximityDeviceStatics const&), ProximityDevice, IProximityDeviceStatics>([](IProximityDeviceStatics const& f) { return f.GetDefault(); });
    }
    inline auto ProximityDevice::FromId(param::hstring const& deviceId)
    {
        return impl::call_factory<ProximityDevice, IProximityDeviceStatics>([&](IProximityDeviceStatics const& f) { return f.FromId(deviceId); });
    }
    template <typename L> DeviceArrivedEventHandler::DeviceArrivedEventHandler(L handler) :
        DeviceArrivedEventHandler(impl::make_delegate<DeviceArrivedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> DeviceArrivedEventHandler::DeviceArrivedEventHandler(F* handler) :
        DeviceArrivedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DeviceArrivedEventHandler::DeviceArrivedEventHandler(O* object, M method) :
        DeviceArrivedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DeviceArrivedEventHandler::DeviceArrivedEventHandler(com_ptr<O>&& object, M method) :
        DeviceArrivedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DeviceArrivedEventHandler::DeviceArrivedEventHandler(weak_ref<O>&& object, M method) :
        DeviceArrivedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DeviceArrivedEventHandler::operator()(winrt::Windows::Networking::Proximity::ProximityDevice const& sender) const
    {
        check_hresult((*(impl::abi_t<DeviceArrivedEventHandler>**)this)->Invoke(*(void**)(&sender)));
    }
    template <typename L> DeviceDepartedEventHandler::DeviceDepartedEventHandler(L handler) :
        DeviceDepartedEventHandler(impl::make_delegate<DeviceDepartedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> DeviceDepartedEventHandler::DeviceDepartedEventHandler(F* handler) :
        DeviceDepartedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DeviceDepartedEventHandler::DeviceDepartedEventHandler(O* object, M method) :
        DeviceDepartedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DeviceDepartedEventHandler::DeviceDepartedEventHandler(com_ptr<O>&& object, M method) :
        DeviceDepartedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DeviceDepartedEventHandler::DeviceDepartedEventHandler(weak_ref<O>&& object, M method) :
        DeviceDepartedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DeviceDepartedEventHandler::operator()(winrt::Windows::Networking::Proximity::ProximityDevice const& sender) const
    {
        check_hresult((*(impl::abi_t<DeviceDepartedEventHandler>**)this)->Invoke(*(void**)(&sender)));
    }
    template <typename L> MessageReceivedHandler::MessageReceivedHandler(L handler) :
        MessageReceivedHandler(impl::make_delegate<MessageReceivedHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> MessageReceivedHandler::MessageReceivedHandler(F* handler) :
        MessageReceivedHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> MessageReceivedHandler::MessageReceivedHandler(O* object, M method) :
        MessageReceivedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> MessageReceivedHandler::MessageReceivedHandler(com_ptr<O>&& object, M method) :
        MessageReceivedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> MessageReceivedHandler::MessageReceivedHandler(weak_ref<O>&& object, M method) :
        MessageReceivedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto MessageReceivedHandler::operator()(winrt::Windows::Networking::Proximity::ProximityDevice const& sender, winrt::Windows::Networking::Proximity::ProximityMessage const& message) const
    {
        check_hresult((*(impl::abi_t<MessageReceivedHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&message)));
    }
    template <typename L> MessageTransmittedHandler::MessageTransmittedHandler(L handler) :
        MessageTransmittedHandler(impl::make_delegate<MessageTransmittedHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> MessageTransmittedHandler::MessageTransmittedHandler(F* handler) :
        MessageTransmittedHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> MessageTransmittedHandler::MessageTransmittedHandler(O* object, M method) :
        MessageTransmittedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> MessageTransmittedHandler::MessageTransmittedHandler(com_ptr<O>&& object, M method) :
        MessageTransmittedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> MessageTransmittedHandler::MessageTransmittedHandler(weak_ref<O>&& object, M method) :
        MessageTransmittedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto MessageTransmittedHandler::operator()(winrt::Windows::Networking::Proximity::ProximityDevice const& sender, int64_t messageId) const
    {
        check_hresult((*(impl::abi_t<MessageTransmittedHandler>**)this)->Invoke(*(void**)(&sender), messageId));
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Networking::Proximity::IConnectionRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::IPeerFinderStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::IPeerFinderStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::IPeerInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::IPeerInformation3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::IPeerInformationWithHostAndService> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::IPeerWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::IProximityDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::IProximityDeviceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::IProximityMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::ConnectionRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::PeerFinder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::PeerInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::PeerWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::ProximityDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::ProximityMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
