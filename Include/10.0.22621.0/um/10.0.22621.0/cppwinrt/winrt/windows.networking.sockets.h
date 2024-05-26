// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Networking_Sockets_H
#define WINRT_Windows_Networking_Sockets_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Networking.h"
#include "winrt/impl/Windows.ApplicationModel.Background.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Networking.Connectivity.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Security.Cryptography.Certificates.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Web.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::ControlChannelTriggerId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTrigger)->get_ControlChannelTriggerId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::ServerKeepAliveIntervalInMinutes() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTrigger)->get_ServerKeepAliveIntervalInMinutes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::ServerKeepAliveIntervalInMinutes(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTrigger)->put_ServerKeepAliveIntervalInMinutes(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::CurrentKeepAliveIntervalInMinutes() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTrigger)->get_CurrentKeepAliveIntervalInMinutes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::TransportObject() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTrigger)->get_TransportObject(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Background::IBackgroundTrigger) consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::KeepAliveTrigger() const
    {
        void* trigger{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTrigger)->get_KeepAliveTrigger(&trigger));
        return winrt::Windows::ApplicationModel::Background::IBackgroundTrigger{ trigger, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Background::IBackgroundTrigger) consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::PushNotificationTrigger() const
    {
        void* trigger{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTrigger)->get_PushNotificationTrigger(&trigger));
        return winrt::Windows::ApplicationModel::Background::IBackgroundTrigger{ trigger, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::UsingTransport(winrt::Windows::Foundation::IInspectable const& transport) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTrigger)->UsingTransport(*(void**)(&transport)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::ControlChannelTriggerStatus) consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::WaitForPushEnabled() const
    {
        winrt::Windows::Networking::Sockets::ControlChannelTriggerStatus channelTriggerStatus{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTrigger)->WaitForPushEnabled(reinterpret_cast<int32_t*>(&channelTriggerStatus)));
        return channelTriggerStatus;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::DecreaseNetworkKeepAliveInterval() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTrigger)->DecreaseNetworkKeepAliveInterval());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::FlushTransport() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTrigger)->FlushTransport());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Sockets_IControlChannelTrigger2<D>::IsWakeFromLowPowerSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTrigger2)->get_IsWakeFromLowPowerSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::ControlChannelTrigger) consume_Windows_Networking_Sockets_IControlChannelTriggerEventDetails<D>::ControlChannelTrigger() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTriggerEventDetails)->get_ControlChannelTrigger(&value));
        return winrt::Windows::Networking::Sockets::ControlChannelTrigger{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::ControlChannelTrigger) consume_Windows_Networking_Sockets_IControlChannelTriggerFactory<D>::CreateControlChannelTrigger(param::hstring const& channelId, uint32_t serverKeepAliveIntervalInMinutes) const
    {
        void* notificationChannel{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTriggerFactory)->CreateControlChannelTrigger(*(void**)(&channelId), serverKeepAliveIntervalInMinutes, &notificationChannel));
        return winrt::Windows::Networking::Sockets::ControlChannelTrigger{ notificationChannel, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::ControlChannelTrigger) consume_Windows_Networking_Sockets_IControlChannelTriggerFactory<D>::CreateControlChannelTriggerEx(param::hstring const& channelId, uint32_t serverKeepAliveIntervalInMinutes, winrt::Windows::Networking::Sockets::ControlChannelTriggerResourceType const& resourceRequestType) const
    {
        void* notificationChannel{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTriggerFactory)->CreateControlChannelTriggerEx(*(void**)(&channelId), serverKeepAliveIntervalInMinutes, static_cast<int32_t>(resourceRequestType), &notificationChannel));
        return winrt::Windows::Networking::Sockets::ControlChannelTrigger{ notificationChannel, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::ControlChannelTriggerResetReason) consume_Windows_Networking_Sockets_IControlChannelTriggerResetEventDetails<D>::ResetReason() const
    {
        winrt::Windows::Networking::Sockets::ControlChannelTriggerResetReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTriggerResetEventDetails)->get_ResetReason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Sockets_IControlChannelTriggerResetEventDetails<D>::HardwareSlotReset() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTriggerResetEventDetails)->get_HardwareSlotReset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Sockets_IControlChannelTriggerResetEventDetails<D>::SoftwareSlotReset() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IControlChannelTriggerResetEventDetails)->get_SoftwareSlotReset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::DatagramSocketControl) consume_Windows_Networking_Sockets_IDatagramSocket<D>::Control() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket)->get_Control(&value));
        return winrt::Windows::Networking::Sockets::DatagramSocketControl{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::DatagramSocketInformation) consume_Windows_Networking_Sockets_IDatagramSocket<D>::Information() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket)->get_Information(&value));
        return winrt::Windows::Networking::Sockets::DatagramSocketInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) consume_Windows_Networking_Sockets_IDatagramSocket<D>::OutputStream() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket)->get_OutputStream(&value));
        return winrt::Windows::Storage::Streams::IOutputStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IDatagramSocket<D>::ConnectAsync(winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket)->ConnectAsync(*(void**)(&remoteHostName), *(void**)(&remoteServiceName), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IDatagramSocket<D>::ConnectAsync(winrt::Windows::Networking::EndpointPair const& endpointPair) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket)->ConnectWithEndpointPairAsync(*(void**)(&endpointPair), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IDatagramSocket<D>::BindServiceNameAsync(param::hstring const& localServiceName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket)->BindServiceNameAsync(*(void**)(&localServiceName), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IDatagramSocket<D>::BindEndpointAsync(winrt::Windows::Networking::HostName const& localHostName, param::hstring const& localServiceName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket)->BindEndpointAsync(*(void**)(&localHostName), *(void**)(&localServiceName), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IDatagramSocket<D>::JoinMulticastGroup(winrt::Windows::Networking::HostName const& host) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket)->JoinMulticastGroup(*(void**)(&host)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IOutputStream>) consume_Windows_Networking_Sockets_IDatagramSocket<D>::GetOutputStreamAsync(winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket)->GetOutputStreamAsync(*(void**)(&remoteHostName), *(void**)(&remoteServiceName), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IOutputStream>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IOutputStream>) consume_Windows_Networking_Sockets_IDatagramSocket<D>::GetOutputStreamAsync(winrt::Windows::Networking::EndpointPair const& endpointPair) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket)->GetOutputStreamWithEndpointPairAsync(*(void**)(&endpointPair), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IOutputStream>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Sockets_IDatagramSocket<D>::MessageReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::DatagramSocket, winrt::Windows::Networking::Sockets::DatagramSocketMessageReceivedEventArgs> const& eventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket)->add_MessageReceived(*(void**)(&eventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Networking_Sockets_IDatagramSocket<D>::MessageReceived_revoker consume_Windows_Networking_Sockets_IDatagramSocket<D>::MessageReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::DatagramSocket, winrt::Windows::Networking::Sockets::DatagramSocketMessageReceivedEventArgs> const& eventHandler) const
    {
        return impl::make_event_revoker<D, MessageReceived_revoker>(this, MessageReceived(eventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IDatagramSocket<D>::MessageReceived(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket)->remove_MessageReceived(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IDatagramSocket2<D>::BindServiceNameAsync(param::hstring const& localServiceName, winrt::Windows::Networking::Connectivity::NetworkAdapter const& adapter) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket2)->BindServiceNameAndAdapterAsync(*(void**)(&localServiceName), *(void**)(&adapter), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IDatagramSocket3<D>::CancelIOAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket3)->CancelIOAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IDatagramSocket3<D>::EnableTransferOwnership(winrt::guid const& taskId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket3)->EnableTransferOwnership(impl::bind_in(taskId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IDatagramSocket3<D>::EnableTransferOwnership(winrt::guid const& taskId, winrt::Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const& connectedStandbyAction) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket3)->EnableTransferOwnershipWithConnectedStandbyAction(impl::bind_in(taskId), static_cast<int32_t>(connectedStandbyAction)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IDatagramSocket3<D>::TransferOwnership(param::hstring const& socketId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket3)->TransferOwnership(*(void**)(&socketId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IDatagramSocket3<D>::TransferOwnership(param::hstring const& socketId, winrt::Windows::Networking::Sockets::SocketActivityContext const& data) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket3)->TransferOwnershipWithContext(*(void**)(&socketId), *(void**)(&data)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IDatagramSocket3<D>::TransferOwnership(param::hstring const& socketId, winrt::Windows::Networking::Sockets::SocketActivityContext const& data, winrt::Windows::Foundation::TimeSpan const& keepAliveTime) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocket3)->TransferOwnershipWithContextAndKeepAliveTime(*(void**)(&socketId), *(void**)(&data), impl::bind_in(keepAliveTime)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketQualityOfService) consume_Windows_Networking_Sockets_IDatagramSocketControl<D>::QualityOfService() const
    {
        winrt::Windows::Networking::Sockets::SocketQualityOfService value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketControl)->get_QualityOfService(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IDatagramSocketControl<D>::QualityOfService(winrt::Windows::Networking::Sockets::SocketQualityOfService const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketControl)->put_QualityOfService(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Networking_Sockets_IDatagramSocketControl<D>::OutboundUnicastHopLimit() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketControl)->get_OutboundUnicastHopLimit(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IDatagramSocketControl<D>::OutboundUnicastHopLimit(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketControl)->put_OutboundUnicastHopLimit(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Networking_Sockets_IDatagramSocketControl2<D>::InboundBufferSizeInBytes() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketControl2)->get_InboundBufferSizeInBytes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IDatagramSocketControl2<D>::InboundBufferSizeInBytes(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketControl2)->put_InboundBufferSizeInBytes(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Sockets_IDatagramSocketControl2<D>::DontFragment() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketControl2)->get_DontFragment(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IDatagramSocketControl2<D>::DontFragment(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketControl2)->put_DontFragment(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Sockets_IDatagramSocketControl3<D>::MulticastOnly() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketControl3)->get_MulticastOnly(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IDatagramSocketControl3<D>::MulticastOnly(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketControl3)->put_MulticastOnly(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_Sockets_IDatagramSocketInformation<D>::LocalAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketInformation)->get_LocalAddress(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Sockets_IDatagramSocketInformation<D>::LocalPort() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketInformation)->get_LocalPort(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_Sockets_IDatagramSocketInformation<D>::RemoteAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketInformation)->get_RemoteAddress(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Sockets_IDatagramSocketInformation<D>::RemotePort() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketInformation)->get_RemotePort(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_Sockets_IDatagramSocketMessageReceivedEventArgs<D>::RemoteAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs)->get_RemoteAddress(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Sockets_IDatagramSocketMessageReceivedEventArgs<D>::RemotePort() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs)->get_RemotePort(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_Sockets_IDatagramSocketMessageReceivedEventArgs<D>::LocalAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs)->get_LocalAddress(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::DataReader) consume_Windows_Networking_Sockets_IDatagramSocketMessageReceivedEventArgs<D>::GetDataReader() const
    {
        void* dataReader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs)->GetDataReader(&dataReader));
        return winrt::Windows::Storage::Streams::DataReader{ dataReader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) consume_Windows_Networking_Sockets_IDatagramSocketMessageReceivedEventArgs<D>::GetDataStream() const
    {
        void* inputStream{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs)->GetDataStream(&inputStream));
        return winrt::Windows::Storage::Streams::IInputStream{ inputStream, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>) consume_Windows_Networking_Sockets_IDatagramSocketStatics<D>::GetEndpointPairsAsync(winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketStatics)->GetEndpointPairsAsync(*(void**)(&remoteHostName), *(void**)(&remoteServiceName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>) consume_Windows_Networking_Sockets_IDatagramSocketStatics<D>::GetEndpointPairsAsync(winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, winrt::Windows::Networking::HostNameSortOptions const& sortOptions) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IDatagramSocketStatics)->GetEndpointPairsWithSortOptionsAsync(*(void**)(&remoteHostName), *(void**)(&remoteServiceName), static_cast<uint32_t>(sortOptions), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::MessageWebSocketControl) consume_Windows_Networking_Sockets_IMessageWebSocket<D>::Control() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocket)->get_Control(&value));
        return winrt::Windows::Networking::Sockets::MessageWebSocketControl{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::MessageWebSocketInformation) consume_Windows_Networking_Sockets_IMessageWebSocket<D>::Information() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocket)->get_Information(&value));
        return winrt::Windows::Networking::Sockets::MessageWebSocketInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Sockets_IMessageWebSocket<D>::MessageReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::MessageWebSocket, winrt::Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const& eventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocket)->add_MessageReceived(*(void**)(&eventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Networking_Sockets_IMessageWebSocket<D>::MessageReceived_revoker consume_Windows_Networking_Sockets_IMessageWebSocket<D>::MessageReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::MessageWebSocket, winrt::Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const& eventHandler) const
    {
        return impl::make_event_revoker<D, MessageReceived_revoker>(this, MessageReceived(eventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IMessageWebSocket<D>::MessageReceived(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocket)->remove_MessageReceived(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Sockets_IMessageWebSocket2<D>::ServerCustomValidationRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::MessageWebSocket, winrt::Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const& eventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocket2)->add_ServerCustomValidationRequested(*(void**)(&eventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Networking_Sockets_IMessageWebSocket2<D>::ServerCustomValidationRequested_revoker consume_Windows_Networking_Sockets_IMessageWebSocket2<D>::ServerCustomValidationRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::MessageWebSocket, winrt::Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const& eventHandler) const
    {
        return impl::make_event_revoker<D, ServerCustomValidationRequested_revoker>(this, ServerCustomValidationRequested(eventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IMessageWebSocket2<D>::ServerCustomValidationRequested(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocket2)->remove_ServerCustomValidationRequested(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>) consume_Windows_Networking_Sockets_IMessageWebSocket3<D>::SendNonfinalFrameAsync(winrt::Windows::Storage::Streams::IBuffer const& data) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocket3)->SendNonfinalFrameAsync(*(void**)(&data), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>) consume_Windows_Networking_Sockets_IMessageWebSocket3<D>::SendFinalFrameAsync(winrt::Windows::Storage::Streams::IBuffer const& data) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocket3)->SendFinalFrameAsync(*(void**)(&data), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Networking_Sockets_IMessageWebSocketControl<D>::MaxMessageSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketControl)->get_MaxMessageSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IMessageWebSocketControl<D>::MaxMessageSize(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketControl)->put_MaxMessageSize(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketMessageType) consume_Windows_Networking_Sockets_IMessageWebSocketControl<D>::MessageType() const
    {
        winrt::Windows::Networking::Sockets::SocketMessageType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketControl)->get_MessageType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IMessageWebSocketControl<D>::MessageType(winrt::Windows::Networking::Sockets::SocketMessageType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketControl)->put_MessageType(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::DesiredUnsolicitedPongInterval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketControl2)->get_DesiredUnsolicitedPongInterval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::DesiredUnsolicitedPongInterval(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketControl2)->put_DesiredUnsolicitedPongInterval(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::ActualUnsolicitedPongInterval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketControl2)->get_ActualUnsolicitedPongInterval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::MessageWebSocketReceiveMode) consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::ReceiveMode() const
    {
        winrt::Windows::Networking::Sockets::MessageWebSocketReceiveMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketControl2)->get_ReceiveMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::ReceiveMode(winrt::Windows::Networking::Sockets::MessageWebSocketReceiveMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketControl2)->put_ReceiveMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Cryptography::Certificates::Certificate) consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::ClientCertificate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketControl2)->get_ClientCertificate(&value));
        return winrt::Windows::Security::Cryptography::Certificates::Certificate{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::ClientCertificate(winrt::Windows::Security::Cryptography::Certificates::Certificate const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketControl2)->put_ClientCertificate(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketMessageType) consume_Windows_Networking_Sockets_IMessageWebSocketMessageReceivedEventArgs<D>::MessageType() const
    {
        winrt::Windows::Networking::Sockets::SocketMessageType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs)->get_MessageType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::DataReader) consume_Windows_Networking_Sockets_IMessageWebSocketMessageReceivedEventArgs<D>::GetDataReader() const
    {
        void* dataReader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs)->GetDataReader(&dataReader));
        return winrt::Windows::Storage::Streams::DataReader{ dataReader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) consume_Windows_Networking_Sockets_IMessageWebSocketMessageReceivedEventArgs<D>::GetDataStream() const
    {
        void* inputStream{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs)->GetDataStream(&inputStream));
        return winrt::Windows::Storage::Streams::IInputStream{ inputStream, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Sockets_IMessageWebSocketMessageReceivedEventArgs2<D>::IsMessageComplete() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs2)->get_IsMessageComplete(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::MessageReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::ServerMessageWebSocket, winrt::Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerMessageWebSocket)->add_MessageReceived(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::MessageReceived_revoker consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::MessageReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::ServerMessageWebSocket, winrt::Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, MessageReceived_revoker>(this, MessageReceived(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::MessageReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerMessageWebSocket)->remove_MessageReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::ServerMessageWebSocketControl) consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Control() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerMessageWebSocket)->get_Control(&value));
        return winrt::Windows::Networking::Sockets::ServerMessageWebSocketControl{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::ServerMessageWebSocketInformation) consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Information() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerMessageWebSocket)->get_Information(&value));
        return winrt::Windows::Networking::Sockets::ServerMessageWebSocketInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::OutputStream() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerMessageWebSocket)->get_OutputStream(&value));
        return winrt::Windows::Storage::Streams::IOutputStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::ServerMessageWebSocket, winrt::Windows::Networking::Sockets::WebSocketClosedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerMessageWebSocket)->add_Closed(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Closed_revoker consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::ServerMessageWebSocket, winrt::Windows::Networking::Sockets::WebSocketClosedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerMessageWebSocket)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Close(uint16_t code, param::hstring const& reason) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerMessageWebSocket)->CloseWithStatus(code, *(void**)(&reason)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketMessageType) consume_Windows_Networking_Sockets_IServerMessageWebSocketControl<D>::MessageType() const
    {
        winrt::Windows::Networking::Sockets::SocketMessageType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerMessageWebSocketControl)->get_MessageType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IServerMessageWebSocketControl<D>::MessageType(winrt::Windows::Networking::Sockets::SocketMessageType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerMessageWebSocketControl)->put_MessageType(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::BandwidthStatistics) consume_Windows_Networking_Sockets_IServerMessageWebSocketInformation<D>::BandwidthStatistics() const
    {
        winrt::Windows::Networking::Sockets::BandwidthStatistics value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerMessageWebSocketInformation)->get_BandwidthStatistics(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Sockets_IServerMessageWebSocketInformation<D>::Protocol() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerMessageWebSocketInformation)->get_Protocol(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_Sockets_IServerMessageWebSocketInformation<D>::LocalAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerMessageWebSocketInformation)->get_LocalAddress(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::ServerStreamWebSocketInformation) consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::Information() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerStreamWebSocket)->get_Information(&value));
        return winrt::Windows::Networking::Sockets::ServerStreamWebSocketInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::InputStream() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerStreamWebSocket)->get_InputStream(&value));
        return winrt::Windows::Storage::Streams::IInputStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::OutputStream() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerStreamWebSocket)->get_OutputStream(&value));
        return winrt::Windows::Storage::Streams::IOutputStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::ServerStreamWebSocket, winrt::Windows::Networking::Sockets::WebSocketClosedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerStreamWebSocket)->add_Closed(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::Closed_revoker consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::ServerStreamWebSocket, winrt::Windows::Networking::Sockets::WebSocketClosedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerStreamWebSocket)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::Close(uint16_t code, param::hstring const& reason) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerStreamWebSocket)->CloseWithStatus(code, *(void**)(&reason)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::BandwidthStatistics) consume_Windows_Networking_Sockets_IServerStreamWebSocketInformation<D>::BandwidthStatistics() const
    {
        winrt::Windows::Networking::Sockets::BandwidthStatistics value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerStreamWebSocketInformation)->get_BandwidthStatistics(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Sockets_IServerStreamWebSocketInformation<D>::Protocol() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerStreamWebSocketInformation)->get_Protocol(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_Sockets_IServerStreamWebSocketInformation<D>::LocalAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IServerStreamWebSocketInformation)->get_LocalAddress(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Networking_Sockets_ISocketActivityContext<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::ISocketActivityContext)->get_Data(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketActivityContext) consume_Windows_Networking_Sockets_ISocketActivityContextFactory<D>::Create(winrt::Windows::Storage::Streams::IBuffer const& data) const
    {
        void* context{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::ISocketActivityContextFactory)->Create(*(void**)(&data), &context));
        return winrt::Windows::Networking::Sockets::SocketActivityContext{ context, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::TaskId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::ISocketActivityInformation)->get_TaskId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::ISocketActivityInformation)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketActivityKind) consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::SocketKind() const
    {
        winrt::Windows::Networking::Sockets::SocketActivityKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::ISocketActivityInformation)->get_SocketKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketActivityContext) consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::Context() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::ISocketActivityInformation)->get_Context(&value));
        return winrt::Windows::Networking::Sockets::SocketActivityContext{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::DatagramSocket) consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::DatagramSocket() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::ISocketActivityInformation)->get_DatagramSocket(&value));
        return winrt::Windows::Networking::Sockets::DatagramSocket{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::StreamSocket) consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::StreamSocket() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::ISocketActivityInformation)->get_StreamSocket(&value));
        return winrt::Windows::Networking::Sockets::StreamSocket{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::StreamSocketListener) consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::StreamSocketListener() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::ISocketActivityInformation)->get_StreamSocketListener(&value));
        return winrt::Windows::Networking::Sockets::StreamSocketListener{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Networking::Sockets::SocketActivityInformation>) consume_Windows_Networking_Sockets_ISocketActivityInformationStatics<D>::AllSockets() const
    {
        void* sockets{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::ISocketActivityInformationStatics)->get_AllSockets(&sockets));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Networking::Sockets::SocketActivityInformation>{ sockets, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketActivityTriggerReason) consume_Windows_Networking_Sockets_ISocketActivityTriggerDetails<D>::Reason() const
    {
        winrt::Windows::Networking::Sockets::SocketActivityTriggerReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::ISocketActivityTriggerDetails)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketActivityInformation) consume_Windows_Networking_Sockets_ISocketActivityTriggerDetails<D>::SocketInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::ISocketActivityTriggerDetails)->get_SocketInformation(&value));
        return winrt::Windows::Networking::Sockets::SocketActivityInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketErrorStatus) consume_Windows_Networking_Sockets_ISocketErrorStatics<D>::GetStatus(int32_t hresult) const
    {
        winrt::Windows::Networking::Sockets::SocketErrorStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::ISocketErrorStatics)->GetStatus(hresult, reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::StreamSocketControl) consume_Windows_Networking_Sockets_IStreamSocket<D>::Control() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket)->get_Control(&value));
        return winrt::Windows::Networking::Sockets::StreamSocketControl{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::StreamSocketInformation) consume_Windows_Networking_Sockets_IStreamSocket<D>::Information() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket)->get_Information(&value));
        return winrt::Windows::Networking::Sockets::StreamSocketInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) consume_Windows_Networking_Sockets_IStreamSocket<D>::InputStream() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket)->get_InputStream(&value));
        return winrt::Windows::Storage::Streams::IInputStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) consume_Windows_Networking_Sockets_IStreamSocket<D>::OutputStream() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket)->get_OutputStream(&value));
        return winrt::Windows::Storage::Streams::IOutputStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IStreamSocket<D>::ConnectAsync(winrt::Windows::Networking::EndpointPair const& endpointPair) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket)->ConnectWithEndpointPairAsync(*(void**)(&endpointPair), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IStreamSocket<D>::ConnectAsync(winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket)->ConnectAsync(*(void**)(&remoteHostName), *(void**)(&remoteServiceName), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IStreamSocket<D>::ConnectAsync(winrt::Windows::Networking::EndpointPair const& endpointPair, winrt::Windows::Networking::Sockets::SocketProtectionLevel const& protectionLevel) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket)->ConnectWithEndpointPairAndProtectionLevelAsync(*(void**)(&endpointPair), static_cast<int32_t>(protectionLevel), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IStreamSocket<D>::ConnectAsync(winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, winrt::Windows::Networking::Sockets::SocketProtectionLevel const& protectionLevel) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket)->ConnectWithProtectionLevelAsync(*(void**)(&remoteHostName), *(void**)(&remoteServiceName), static_cast<int32_t>(protectionLevel), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IStreamSocket<D>::UpgradeToSslAsync(winrt::Windows::Networking::Sockets::SocketProtectionLevel const& protectionLevel, winrt::Windows::Networking::HostName const& validationHostName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket)->UpgradeToSslAsync(static_cast<int32_t>(protectionLevel), *(void**)(&validationHostName), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IStreamSocket2<D>::ConnectAsync(winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, winrt::Windows::Networking::Sockets::SocketProtectionLevel const& protectionLevel, winrt::Windows::Networking::Connectivity::NetworkAdapter const& adapter) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket2)->ConnectWithProtectionLevelAndAdapterAsync(*(void**)(&remoteHostName), *(void**)(&remoteServiceName), static_cast<int32_t>(protectionLevel), *(void**)(&adapter), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IStreamSocket3<D>::CancelIOAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket3)->CancelIOAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocket3<D>::EnableTransferOwnership(winrt::guid const& taskId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket3)->EnableTransferOwnership(impl::bind_in(taskId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocket3<D>::EnableTransferOwnership(winrt::guid const& taskId, winrt::Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const& connectedStandbyAction) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket3)->EnableTransferOwnershipWithConnectedStandbyAction(impl::bind_in(taskId), static_cast<int32_t>(connectedStandbyAction)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocket3<D>::TransferOwnership(param::hstring const& socketId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket3)->TransferOwnership(*(void**)(&socketId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocket3<D>::TransferOwnership(param::hstring const& socketId, winrt::Windows::Networking::Sockets::SocketActivityContext const& data) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket3)->TransferOwnershipWithContext(*(void**)(&socketId), *(void**)(&data)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocket3<D>::TransferOwnership(param::hstring const& socketId, winrt::Windows::Networking::Sockets::SocketActivityContext const& data, winrt::Windows::Foundation::TimeSpan const& keepAliveTime) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocket3)->TransferOwnershipWithContextAndKeepAliveTime(*(void**)(&socketId), *(void**)(&data), impl::bind_in(keepAliveTime)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Sockets_IStreamSocketControl<D>::NoDelay() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl)->get_NoDelay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketControl<D>::NoDelay(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl)->put_NoDelay(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Sockets_IStreamSocketControl<D>::KeepAlive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl)->get_KeepAlive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketControl<D>::KeepAlive(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl)->put_KeepAlive(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Networking_Sockets_IStreamSocketControl<D>::OutboundBufferSizeInBytes() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl)->get_OutboundBufferSizeInBytes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketControl<D>::OutboundBufferSizeInBytes(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl)->put_OutboundBufferSizeInBytes(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketQualityOfService) consume_Windows_Networking_Sockets_IStreamSocketControl<D>::QualityOfService() const
    {
        winrt::Windows::Networking::Sockets::SocketQualityOfService value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl)->get_QualityOfService(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketControl<D>::QualityOfService(winrt::Windows::Networking::Sockets::SocketQualityOfService const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl)->put_QualityOfService(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Networking_Sockets_IStreamSocketControl<D>::OutboundUnicastHopLimit() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl)->get_OutboundUnicastHopLimit(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketControl<D>::OutboundUnicastHopLimit(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl)->put_OutboundUnicastHopLimit(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>) consume_Windows_Networking_Sockets_IStreamSocketControl2<D>::IgnorableServerCertificateErrors() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl2)->get_IgnorableServerCertificateErrors(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Sockets_IStreamSocketControl3<D>::SerializeConnectionAttempts() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl3)->get_SerializeConnectionAttempts(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketControl3<D>::SerializeConnectionAttempts(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl3)->put_SerializeConnectionAttempts(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Cryptography::Certificates::Certificate) consume_Windows_Networking_Sockets_IStreamSocketControl3<D>::ClientCertificate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl3)->get_ClientCertificate(&value));
        return winrt::Windows::Security::Cryptography::Certificates::Certificate{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketControl3<D>::ClientCertificate(winrt::Windows::Security::Cryptography::Certificates::Certificate const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl3)->put_ClientCertificate(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketProtectionLevel) consume_Windows_Networking_Sockets_IStreamSocketControl4<D>::MinProtectionLevel() const
    {
        winrt::Windows::Networking::Sockets::SocketProtectionLevel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl4)->get_MinProtectionLevel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketControl4<D>::MinProtectionLevel(winrt::Windows::Networking::Sockets::SocketProtectionLevel const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketControl4)->put_MinProtectionLevel(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::LocalAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation)->get_LocalAddress(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::LocalPort() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation)->get_LocalPort(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::RemoteHostName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation)->get_RemoteHostName(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::RemoteAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation)->get_RemoteAddress(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::RemoteServiceName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation)->get_RemoteServiceName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::RemotePort() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation)->get_RemotePort(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::RoundTripTimeStatistics) consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::RoundTripTimeStatistics() const
    {
        winrt::Windows::Networking::Sockets::RoundTripTimeStatistics value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation)->get_RoundTripTimeStatistics(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::BandwidthStatistics) consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::BandwidthStatistics() const
    {
        winrt::Windows::Networking::Sockets::BandwidthStatistics value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation)->get_BandwidthStatistics(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketProtectionLevel) consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::ProtectionLevel() const
    {
        winrt::Windows::Networking::Sockets::SocketProtectionLevel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation)->get_ProtectionLevel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::SessionKey() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation)->get_SessionKey(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketSslErrorSeverity) consume_Windows_Networking_Sockets_IStreamSocketInformation2<D>::ServerCertificateErrorSeverity() const
    {
        winrt::Windows::Networking::Sockets::SocketSslErrorSeverity value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation2)->get_ServerCertificateErrorSeverity(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>) consume_Windows_Networking_Sockets_IStreamSocketInformation2<D>::ServerCertificateErrors() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation2)->get_ServerCertificateErrors(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Cryptography::Certificates::Certificate) consume_Windows_Networking_Sockets_IStreamSocketInformation2<D>::ServerCertificate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation2)->get_ServerCertificate(&value));
        return winrt::Windows::Security::Cryptography::Certificates::Certificate{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>) consume_Windows_Networking_Sockets_IStreamSocketInformation2<D>::ServerIntermediateCertificates() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketInformation2)->get_ServerIntermediateCertificates(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::StreamSocketListenerControl) consume_Windows_Networking_Sockets_IStreamSocketListener<D>::Control() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListener)->get_Control(&value));
        return winrt::Windows::Networking::Sockets::StreamSocketListenerControl{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::StreamSocketListenerInformation) consume_Windows_Networking_Sockets_IStreamSocketListener<D>::Information() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListener)->get_Information(&value));
        return winrt::Windows::Networking::Sockets::StreamSocketListenerInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IStreamSocketListener<D>::BindServiceNameAsync(param::hstring const& localServiceName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListener)->BindServiceNameAsync(*(void**)(&localServiceName), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IStreamSocketListener<D>::BindEndpointAsync(winrt::Windows::Networking::HostName const& localHostName, param::hstring const& localServiceName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListener)->BindEndpointAsync(*(void**)(&localHostName), *(void**)(&localServiceName), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Sockets_IStreamSocketListener<D>::ConnectionReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::StreamSocketListener, winrt::Windows::Networking::Sockets::StreamSocketListenerConnectionReceivedEventArgs> const& eventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListener)->add_ConnectionReceived(*(void**)(&eventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Networking_Sockets_IStreamSocketListener<D>::ConnectionReceived_revoker consume_Windows_Networking_Sockets_IStreamSocketListener<D>::ConnectionReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::StreamSocketListener, winrt::Windows::Networking::Sockets::StreamSocketListenerConnectionReceivedEventArgs> const& eventHandler) const
    {
        return impl::make_event_revoker<D, ConnectionReceived_revoker>(this, ConnectionReceived(eventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketListener<D>::ConnectionReceived(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListener)->remove_ConnectionReceived(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IStreamSocketListener2<D>::BindServiceNameAsync(param::hstring const& localServiceName, winrt::Windows::Networking::Sockets::SocketProtectionLevel const& protectionLevel) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListener2)->BindServiceNameWithProtectionLevelAsync(*(void**)(&localServiceName), static_cast<int32_t>(protectionLevel), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IStreamSocketListener2<D>::BindServiceNameAsync(param::hstring const& localServiceName, winrt::Windows::Networking::Sockets::SocketProtectionLevel const& protectionLevel, winrt::Windows::Networking::Connectivity::NetworkAdapter const& adapter) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListener2)->BindServiceNameWithProtectionLevelAndAdapterAsync(*(void**)(&localServiceName), static_cast<int32_t>(protectionLevel), *(void**)(&adapter), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IStreamSocketListener3<D>::CancelIOAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListener3)->CancelIOAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketListener3<D>::EnableTransferOwnership(winrt::guid const& taskId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListener3)->EnableTransferOwnership(impl::bind_in(taskId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketListener3<D>::EnableTransferOwnership(winrt::guid const& taskId, winrt::Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const& connectedStandbyAction) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListener3)->EnableTransferOwnershipWithConnectedStandbyAction(impl::bind_in(taskId), static_cast<int32_t>(connectedStandbyAction)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketListener3<D>::TransferOwnership(param::hstring const& socketId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListener3)->TransferOwnership(*(void**)(&socketId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketListener3<D>::TransferOwnership(param::hstring const& socketId, winrt::Windows::Networking::Sockets::SocketActivityContext const& data) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListener3)->TransferOwnershipWithContext(*(void**)(&socketId), *(void**)(&data)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::StreamSocket) consume_Windows_Networking_Sockets_IStreamSocketListenerConnectionReceivedEventArgs<D>::Socket() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListenerConnectionReceivedEventArgs)->get_Socket(&value));
        return winrt::Windows::Networking::Sockets::StreamSocket{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketQualityOfService) consume_Windows_Networking_Sockets_IStreamSocketListenerControl<D>::QualityOfService() const
    {
        winrt::Windows::Networking::Sockets::SocketQualityOfService value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListenerControl)->get_QualityOfService(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketListenerControl<D>::QualityOfService(winrt::Windows::Networking::Sockets::SocketQualityOfService const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListenerControl)->put_QualityOfService(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::NoDelay() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListenerControl2)->get_NoDelay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::NoDelay(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListenerControl2)->put_NoDelay(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::KeepAlive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListenerControl2)->get_KeepAlive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::KeepAlive(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListenerControl2)->put_KeepAlive(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::OutboundBufferSizeInBytes() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListenerControl2)->get_OutboundBufferSizeInBytes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::OutboundBufferSizeInBytes(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListenerControl2)->put_OutboundBufferSizeInBytes(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::OutboundUnicastHopLimit() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListenerControl2)->get_OutboundUnicastHopLimit(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::OutboundUnicastHopLimit(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListenerControl2)->put_OutboundUnicastHopLimit(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Sockets_IStreamSocketListenerInformation<D>::LocalPort() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketListenerInformation)->get_LocalPort(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>) consume_Windows_Networking_Sockets_IStreamSocketStatics<D>::GetEndpointPairsAsync(winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketStatics)->GetEndpointPairsAsync(*(void**)(&remoteHostName), *(void**)(&remoteServiceName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>) consume_Windows_Networking_Sockets_IStreamSocketStatics<D>::GetEndpointPairsAsync(winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, winrt::Windows::Networking::HostNameSortOptions const& sortOptions) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamSocketStatics)->GetEndpointPairsWithSortOptionsAsync(*(void**)(&remoteHostName), *(void**)(&remoteServiceName), static_cast<uint32_t>(sortOptions), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::StreamWebSocketControl) consume_Windows_Networking_Sockets_IStreamWebSocket<D>::Control() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamWebSocket)->get_Control(&value));
        return winrt::Windows::Networking::Sockets::StreamWebSocketControl{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::StreamWebSocketInformation) consume_Windows_Networking_Sockets_IStreamWebSocket<D>::Information() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamWebSocket)->get_Information(&value));
        return winrt::Windows::Networking::Sockets::StreamWebSocketInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) consume_Windows_Networking_Sockets_IStreamWebSocket<D>::InputStream() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamWebSocket)->get_InputStream(&value));
        return winrt::Windows::Storage::Streams::IInputStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Sockets_IStreamWebSocket2<D>::ServerCustomValidationRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::StreamWebSocket, winrt::Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const& eventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamWebSocket2)->add_ServerCustomValidationRequested(*(void**)(&eventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Networking_Sockets_IStreamWebSocket2<D>::ServerCustomValidationRequested_revoker consume_Windows_Networking_Sockets_IStreamWebSocket2<D>::ServerCustomValidationRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::StreamWebSocket, winrt::Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const& eventHandler) const
    {
        return impl::make_event_revoker<D, ServerCustomValidationRequested_revoker>(this, ServerCustomValidationRequested(eventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamWebSocket2<D>::ServerCustomValidationRequested(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamWebSocket2)->remove_ServerCustomValidationRequested(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_Sockets_IStreamWebSocketControl<D>::NoDelay() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamWebSocketControl)->get_NoDelay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamWebSocketControl<D>::NoDelay(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamWebSocketControl)->put_NoDelay(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Networking_Sockets_IStreamWebSocketControl2<D>::DesiredUnsolicitedPongInterval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamWebSocketControl2)->get_DesiredUnsolicitedPongInterval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamWebSocketControl2<D>::DesiredUnsolicitedPongInterval(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamWebSocketControl2)->put_DesiredUnsolicitedPongInterval(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Networking_Sockets_IStreamWebSocketControl2<D>::ActualUnsolicitedPongInterval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamWebSocketControl2)->get_ActualUnsolicitedPongInterval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Cryptography::Certificates::Certificate) consume_Windows_Networking_Sockets_IStreamWebSocketControl2<D>::ClientCertificate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamWebSocketControl2)->get_ClientCertificate(&value));
        return winrt::Windows::Security::Cryptography::Certificates::Certificate{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IStreamWebSocketControl2<D>::ClientCertificate(winrt::Windows::Security::Cryptography::Certificates::Certificate const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IStreamWebSocketControl2)->put_ClientCertificate(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) consume_Windows_Networking_Sockets_IWebSocket<D>::OutputStream() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocket)->get_OutputStream(&value));
        return winrt::Windows::Storage::Streams::IOutputStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Networking_Sockets_IWebSocket<D>::ConnectAsync(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocket)->ConnectAsync(*(void**)(&uri), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IWebSocket<D>::SetRequestHeader(param::hstring const& headerName, param::hstring const& headerValue) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocket)->SetRequestHeader(*(void**)(&headerName), *(void**)(&headerValue)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_Sockets_IWebSocket<D>::Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::IWebSocket, winrt::Windows::Networking::Sockets::WebSocketClosedEventArgs> const& eventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocket)->add_Closed(*(void**)(&eventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Networking_Sockets_IWebSocket<D>::Closed_revoker consume_Windows_Networking_Sockets_IWebSocket<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::IWebSocket, winrt::Windows::Networking::Sockets::WebSocketClosedEventArgs> const& eventHandler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(eventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IWebSocket<D>::Closed(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocket)->remove_Closed(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IWebSocket<D>::Close(uint16_t code, param::hstring const& reason) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocket)->CloseWithStatus(code, *(void**)(&reason)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Networking_Sockets_IWebSocketClosedEventArgs<D>::Code() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketClosedEventArgs)->get_Code(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Sockets_IWebSocketClosedEventArgs<D>::Reason() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketClosedEventArgs)->get_Reason(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Networking_Sockets_IWebSocketControl<D>::OutboundBufferSizeInBytes() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketControl)->get_OutboundBufferSizeInBytes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IWebSocketControl<D>::OutboundBufferSizeInBytes(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketControl)->put_OutboundBufferSizeInBytes(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) consume_Windows_Networking_Sockets_IWebSocketControl<D>::ServerCredential() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketControl)->get_ServerCredential(&value));
        return winrt::Windows::Security::Credentials::PasswordCredential{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IWebSocketControl<D>::ServerCredential(winrt::Windows::Security::Credentials::PasswordCredential const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketControl)->put_ServerCredential(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) consume_Windows_Networking_Sockets_IWebSocketControl<D>::ProxyCredential() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketControl)->get_ProxyCredential(&value));
        return winrt::Windows::Security::Credentials::PasswordCredential{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IWebSocketControl<D>::ProxyCredential(winrt::Windows::Security::Credentials::PasswordCredential const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketControl)->put_ProxyCredential(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Networking_Sockets_IWebSocketControl<D>::SupportedProtocols() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketControl)->get_SupportedProtocols(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>) consume_Windows_Networking_Sockets_IWebSocketControl2<D>::IgnorableServerCertificateErrors() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketControl2)->get_IgnorableServerCertificateErrors(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::WebErrorStatus) consume_Windows_Networking_Sockets_IWebSocketErrorStatics<D>::GetStatus(int32_t hresult) const
    {
        winrt::Windows::Web::WebErrorStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketErrorStatics)->GetStatus(hresult, reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_Sockets_IWebSocketInformation<D>::LocalAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketInformation)->get_LocalAddress(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::BandwidthStatistics) consume_Windows_Networking_Sockets_IWebSocketInformation<D>::BandwidthStatistics() const
    {
        winrt::Windows::Networking::Sockets::BandwidthStatistics value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketInformation)->get_BandwidthStatistics(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_Sockets_IWebSocketInformation<D>::Protocol() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketInformation)->get_Protocol(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Cryptography::Certificates::Certificate) consume_Windows_Networking_Sockets_IWebSocketInformation2<D>::ServerCertificate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketInformation2)->get_ServerCertificate(&value));
        return winrt::Windows::Security::Cryptography::Certificates::Certificate{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketSslErrorSeverity) consume_Windows_Networking_Sockets_IWebSocketInformation2<D>::ServerCertificateErrorSeverity() const
    {
        winrt::Windows::Networking::Sockets::SocketSslErrorSeverity value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketInformation2)->get_ServerCertificateErrorSeverity(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>) consume_Windows_Networking_Sockets_IWebSocketInformation2<D>::ServerCertificateErrors() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketInformation2)->get_ServerCertificateErrors(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>) consume_Windows_Networking_Sockets_IWebSocketInformation2<D>::ServerIntermediateCertificates() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketInformation2)->get_ServerIntermediateCertificates(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Cryptography::Certificates::Certificate) consume_Windows_Networking_Sockets_IWebSocketServerCustomValidationRequestedEventArgs<D>::ServerCertificate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs)->get_ServerCertificate(&value));
        return winrt::Windows::Security::Cryptography::Certificates::Certificate{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::SocketSslErrorSeverity) consume_Windows_Networking_Sockets_IWebSocketServerCustomValidationRequestedEventArgs<D>::ServerCertificateErrorSeverity() const
    {
        winrt::Windows::Networking::Sockets::SocketSslErrorSeverity value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs)->get_ServerCertificateErrorSeverity(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>) consume_Windows_Networking_Sockets_IWebSocketServerCustomValidationRequestedEventArgs<D>::ServerCertificateErrors() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs)->get_ServerCertificateErrors(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>) consume_Windows_Networking_Sockets_IWebSocketServerCustomValidationRequestedEventArgs<D>::ServerIntermediateCertificates() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs)->get_ServerIntermediateCertificates(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_Sockets_IWebSocketServerCustomValidationRequestedEventArgs<D>::Reject() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs)->Reject());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Networking_Sockets_IWebSocketServerCustomValidationRequestedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IControlChannelTrigger> : produce_base<D, winrt::Windows::Networking::Sockets::IControlChannelTrigger>
    {
        int32_t __stdcall get_ControlChannelTriggerId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ControlChannelTriggerId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServerKeepAliveIntervalInMinutes(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ServerKeepAliveIntervalInMinutes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ServerKeepAliveIntervalInMinutes(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ServerKeepAliveIntervalInMinutes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentKeepAliveIntervalInMinutes(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CurrentKeepAliveIntervalInMinutes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransportObject(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().TransportObject());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeepAliveTrigger(void** trigger) noexcept final try
        {
            clear_abi(trigger);
            typename D::abi_guard guard(this->shim());
            *trigger = detach_from<winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>(this->shim().KeepAliveTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PushNotificationTrigger(void** trigger) noexcept final try
        {
            clear_abi(trigger);
            typename D::abi_guard guard(this->shim());
            *trigger = detach_from<winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>(this->shim().PushNotificationTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UsingTransport(void* transport) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UsingTransport(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&transport));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WaitForPushEnabled(int32_t* channelTriggerStatus) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *channelTriggerStatus = detach_from<winrt::Windows::Networking::Sockets::ControlChannelTriggerStatus>(this->shim().WaitForPushEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DecreaseNetworkKeepAliveInterval() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DecreaseNetworkKeepAliveInterval();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FlushTransport() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FlushTransport();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IControlChannelTrigger2> : produce_base<D, winrt::Windows::Networking::Sockets::IControlChannelTrigger2>
    {
        int32_t __stdcall get_IsWakeFromLowPowerSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsWakeFromLowPowerSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IControlChannelTriggerEventDetails> : produce_base<D, winrt::Windows::Networking::Sockets::IControlChannelTriggerEventDetails>
    {
        int32_t __stdcall get_ControlChannelTrigger(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::ControlChannelTrigger>(this->shim().ControlChannelTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IControlChannelTriggerFactory> : produce_base<D, winrt::Windows::Networking::Sockets::IControlChannelTriggerFactory>
    {
        int32_t __stdcall CreateControlChannelTrigger(void* channelId, uint32_t serverKeepAliveIntervalInMinutes, void** notificationChannel) noexcept final try
        {
            clear_abi(notificationChannel);
            typename D::abi_guard guard(this->shim());
            *notificationChannel = detach_from<winrt::Windows::Networking::Sockets::ControlChannelTrigger>(this->shim().CreateControlChannelTrigger(*reinterpret_cast<hstring const*>(&channelId), serverKeepAliveIntervalInMinutes));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateControlChannelTriggerEx(void* channelId, uint32_t serverKeepAliveIntervalInMinutes, int32_t resourceRequestType, void** notificationChannel) noexcept final try
        {
            clear_abi(notificationChannel);
            typename D::abi_guard guard(this->shim());
            *notificationChannel = detach_from<winrt::Windows::Networking::Sockets::ControlChannelTrigger>(this->shim().CreateControlChannelTriggerEx(*reinterpret_cast<hstring const*>(&channelId), serverKeepAliveIntervalInMinutes, *reinterpret_cast<winrt::Windows::Networking::Sockets::ControlChannelTriggerResourceType const*>(&resourceRequestType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IControlChannelTriggerResetEventDetails> : produce_base<D, winrt::Windows::Networking::Sockets::IControlChannelTriggerResetEventDetails>
    {
        int32_t __stdcall get_ResetReason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::ControlChannelTriggerResetReason>(this->shim().ResetReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HardwareSlotReset(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HardwareSlotReset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SoftwareSlotReset(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SoftwareSlotReset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IDatagramSocket> : produce_base<D, winrt::Windows::Networking::Sockets::IDatagramSocket>
    {
        int32_t __stdcall get_Control(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::DatagramSocketControl>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Information(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::DatagramSocketInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutputStream(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IOutputStream>(this->shim().OutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectAsync(void* remoteHostName, void* remoteServiceName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectWithEndpointPairAsync(void* endpointPair, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Networking::EndpointPair const*>(&endpointPair)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall BindServiceNameAsync(void* localServiceName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().BindServiceNameAsync(*reinterpret_cast<hstring const*>(&localServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall BindEndpointAsync(void* localHostName, void* localServiceName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().BindEndpointAsync(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&localHostName), *reinterpret_cast<hstring const*>(&localServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall JoinMulticastGroup(void* host) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().JoinMulticastGroup(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&host));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetOutputStreamAsync(void* remoteHostName, void* remoteServiceName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IOutputStream>>(this->shim().GetOutputStreamAsync(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetOutputStreamWithEndpointPairAsync(void* endpointPair, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IOutputStream>>(this->shim().GetOutputStreamAsync(*reinterpret_cast<winrt::Windows::Networking::EndpointPair const*>(&endpointPair)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_MessageReceived(void* eventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().MessageReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::DatagramSocket, winrt::Windows::Networking::Sockets::DatagramSocketMessageReceivedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MessageReceived(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MessageReceived(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IDatagramSocket2> : produce_base<D, winrt::Windows::Networking::Sockets::IDatagramSocket2>
    {
        int32_t __stdcall BindServiceNameAndAdapterAsync(void* localServiceName, void* adapter, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().BindServiceNameAsync(*reinterpret_cast<hstring const*>(&localServiceName), *reinterpret_cast<winrt::Windows::Networking::Connectivity::NetworkAdapter const*>(&adapter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IDatagramSocket3> : produce_base<D, winrt::Windows::Networking::Sockets::IDatagramSocket3>
    {
        int32_t __stdcall CancelIOAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().CancelIOAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableTransferOwnership(winrt::guid taskId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableTransferOwnership(*reinterpret_cast<winrt::guid const*>(&taskId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableTransferOwnershipWithConnectedStandbyAction(winrt::guid taskId, int32_t connectedStandbyAction) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableTransferOwnership(*reinterpret_cast<winrt::guid const*>(&taskId), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const*>(&connectedStandbyAction));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TransferOwnership(void* socketId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TransferOwnershipWithContext(void* socketId, void* data) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketActivityContext const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TransferOwnershipWithContextAndKeepAliveTime(void* socketId, void* data, int64_t keepAliveTime) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketActivityContext const*>(&data), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&keepAliveTime));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IDatagramSocketControl> : produce_base<D, winrt::Windows::Networking::Sockets::IDatagramSocketControl>
    {
        int32_t __stdcall get_QualityOfService(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketQualityOfService>(this->shim().QualityOfService());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_QualityOfService(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().QualityOfService(*reinterpret_cast<winrt::Windows::Networking::Sockets::SocketQualityOfService const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutboundUnicastHopLimit(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().OutboundUnicastHopLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutboundUnicastHopLimit(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutboundUnicastHopLimit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IDatagramSocketControl2> : produce_base<D, winrt::Windows::Networking::Sockets::IDatagramSocketControl2>
    {
        int32_t __stdcall get_InboundBufferSizeInBytes(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().InboundBufferSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InboundBufferSizeInBytes(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InboundBufferSizeInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DontFragment(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DontFragment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DontFragment(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DontFragment(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IDatagramSocketControl3> : produce_base<D, winrt::Windows::Networking::Sockets::IDatagramSocketControl3>
    {
        int32_t __stdcall get_MulticastOnly(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().MulticastOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MulticastOnly(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MulticastOnly(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IDatagramSocketInformation> : produce_base<D, winrt::Windows::Networking::Sockets::IDatagramSocketInformation>
    {
        int32_t __stdcall get_LocalAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().LocalAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocalPort(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LocalPort());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().RemoteAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemotePort(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemotePort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs> : produce_base<D, winrt::Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs>
    {
        int32_t __stdcall get_RemoteAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().RemoteAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemotePort(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemotePort());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocalAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().LocalAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDataReader(void** dataReader) noexcept final try
        {
            clear_abi(dataReader);
            typename D::abi_guard guard(this->shim());
            *dataReader = detach_from<winrt::Windows::Storage::Streams::DataReader>(this->shim().GetDataReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDataStream(void** inputStream) noexcept final try
        {
            clear_abi(inputStream);
            typename D::abi_guard guard(this->shim());
            *inputStream = detach_from<winrt::Windows::Storage::Streams::IInputStream>(this->shim().GetDataStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IDatagramSocketStatics> : produce_base<D, winrt::Windows::Networking::Sockets::IDatagramSocketStatics>
    {
        int32_t __stdcall GetEndpointPairsAsync(void* remoteHostName, void* remoteServiceName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>>(this->shim().GetEndpointPairsAsync(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetEndpointPairsWithSortOptionsAsync(void* remoteHostName, void* remoteServiceName, uint32_t sortOptions, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>>(this->shim().GetEndpointPairsAsync(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName), *reinterpret_cast<winrt::Windows::Networking::HostNameSortOptions const*>(&sortOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IMessageWebSocket> : produce_base<D, winrt::Windows::Networking::Sockets::IMessageWebSocket>
    {
        int32_t __stdcall get_Control(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::MessageWebSocketControl>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Information(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::MessageWebSocketInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_MessageReceived(void* eventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().MessageReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::MessageWebSocket, winrt::Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MessageReceived(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MessageReceived(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IMessageWebSocket2> : produce_base<D, winrt::Windows::Networking::Sockets::IMessageWebSocket2>
    {
        int32_t __stdcall add_ServerCustomValidationRequested(void* eventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().ServerCustomValidationRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::MessageWebSocket, winrt::Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ServerCustomValidationRequested(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ServerCustomValidationRequested(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IMessageWebSocket3> : produce_base<D, winrt::Windows::Networking::Sockets::IMessageWebSocket3>
    {
        int32_t __stdcall SendNonfinalFrameAsync(void* data, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>>(this->shim().SendNonfinalFrameAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendFinalFrameAsync(void* data, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>>(this->shim().SendFinalFrameAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IMessageWebSocketControl> : produce_base<D, winrt::Windows::Networking::Sockets::IMessageWebSocketControl>
    {
        int32_t __stdcall get_MaxMessageSize(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxMessageSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxMessageSize(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxMessageSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MessageType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketMessageType>(this->shim().MessageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MessageType(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MessageType(*reinterpret_cast<winrt::Windows::Networking::Sockets::SocketMessageType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IMessageWebSocketControl2> : produce_base<D, winrt::Windows::Networking::Sockets::IMessageWebSocketControl2>
    {
        int32_t __stdcall get_DesiredUnsolicitedPongInterval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().DesiredUnsolicitedPongInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredUnsolicitedPongInterval(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredUnsolicitedPongInterval(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActualUnsolicitedPongInterval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().ActualUnsolicitedPongInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReceiveMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::MessageWebSocketReceiveMode>(this->shim().ReceiveMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReceiveMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReceiveMode(*reinterpret_cast<winrt::Windows::Networking::Sockets::MessageWebSocketReceiveMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClientCertificate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Cryptography::Certificates::Certificate>(this->shim().ClientCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClientCertificate(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClientCertificate(*reinterpret_cast<winrt::Windows::Security::Cryptography::Certificates::Certificate const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs> : produce_base<D, winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs>
    {
        int32_t __stdcall get_MessageType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketMessageType>(this->shim().MessageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDataReader(void** dataReader) noexcept final try
        {
            clear_abi(dataReader);
            typename D::abi_guard guard(this->shim());
            *dataReader = detach_from<winrt::Windows::Storage::Streams::DataReader>(this->shim().GetDataReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDataStream(void** inputStream) noexcept final try
        {
            clear_abi(inputStream);
            typename D::abi_guard guard(this->shim());
            *inputStream = detach_from<winrt::Windows::Storage::Streams::IInputStream>(this->shim().GetDataStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs2> : produce_base<D, winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs2>
    {
        int32_t __stdcall get_IsMessageComplete(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMessageComplete());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IServerMessageWebSocket> : produce_base<D, winrt::Windows::Networking::Sockets::IServerMessageWebSocket>
    {
        int32_t __stdcall add_MessageReceived(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MessageReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::ServerMessageWebSocket, winrt::Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MessageReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MessageReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Control(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::ServerMessageWebSocketControl>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Information(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::ServerMessageWebSocketInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutputStream(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IOutputStream>(this->shim().OutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Closed(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::ServerMessageWebSocket, winrt::Windows::Networking::Sockets::WebSocketClosedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall CloseWithStatus(uint16_t code, void* reason) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Close(code, *reinterpret_cast<hstring const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IServerMessageWebSocketControl> : produce_base<D, winrt::Windows::Networking::Sockets::IServerMessageWebSocketControl>
    {
        int32_t __stdcall get_MessageType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketMessageType>(this->shim().MessageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MessageType(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MessageType(*reinterpret_cast<winrt::Windows::Networking::Sockets::SocketMessageType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IServerMessageWebSocketInformation> : produce_base<D, winrt::Windows::Networking::Sockets::IServerMessageWebSocketInformation>
    {
        int32_t __stdcall get_BandwidthStatistics(struct struct_Windows_Networking_Sockets_BandwidthStatistics* value) noexcept final try
        {
            zero_abi<winrt::Windows::Networking::Sockets::BandwidthStatistics>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::BandwidthStatistics>(this->shim().BandwidthStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Protocol(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Protocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocalAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().LocalAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IServerStreamWebSocket> : produce_base<D, winrt::Windows::Networking::Sockets::IServerStreamWebSocket>
    {
        int32_t __stdcall get_Information(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::ServerStreamWebSocketInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InputStream(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IInputStream>(this->shim().InputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutputStream(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IOutputStream>(this->shim().OutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Closed(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::ServerStreamWebSocket, winrt::Windows::Networking::Sockets::WebSocketClosedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall CloseWithStatus(uint16_t code, void* reason) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Close(code, *reinterpret_cast<hstring const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IServerStreamWebSocketInformation> : produce_base<D, winrt::Windows::Networking::Sockets::IServerStreamWebSocketInformation>
    {
        int32_t __stdcall get_BandwidthStatistics(struct struct_Windows_Networking_Sockets_BandwidthStatistics* value) noexcept final try
        {
            zero_abi<winrt::Windows::Networking::Sockets::BandwidthStatistics>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::BandwidthStatistics>(this->shim().BandwidthStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Protocol(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Protocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocalAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().LocalAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::ISocketActivityContext> : produce_base<D, winrt::Windows::Networking::Sockets::ISocketActivityContext>
    {
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::ISocketActivityContextFactory> : produce_base<D, winrt::Windows::Networking::Sockets::ISocketActivityContextFactory>
    {
        int32_t __stdcall Create(void* data, void** context) noexcept final try
        {
            clear_abi(context);
            typename D::abi_guard guard(this->shim());
            *context = detach_from<winrt::Windows::Networking::Sockets::SocketActivityContext>(this->shim().Create(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::ISocketActivityInformation> : produce_base<D, winrt::Windows::Networking::Sockets::ISocketActivityInformation>
    {
        int32_t __stdcall get_TaskId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().TaskId());
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
        int32_t __stdcall get_SocketKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketActivityKind>(this->shim().SocketKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Context(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketActivityContext>(this->shim().Context());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DatagramSocket(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::DatagramSocket>(this->shim().DatagramSocket());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StreamSocket(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::StreamSocket>(this->shim().StreamSocket());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StreamSocketListener(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::StreamSocketListener>(this->shim().StreamSocketListener());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::ISocketActivityInformationStatics> : produce_base<D, winrt::Windows::Networking::Sockets::ISocketActivityInformationStatics>
    {
        int32_t __stdcall get_AllSockets(void** sockets) noexcept final try
        {
            clear_abi(sockets);
            typename D::abi_guard guard(this->shim());
            *sockets = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Networking::Sockets::SocketActivityInformation>>(this->shim().AllSockets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::ISocketActivityTriggerDetails> : produce_base<D, winrt::Windows::Networking::Sockets::ISocketActivityTriggerDetails>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketActivityTriggerReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SocketInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketActivityInformation>(this->shim().SocketInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::ISocketErrorStatics> : produce_base<D, winrt::Windows::Networking::Sockets::ISocketErrorStatics>
    {
        int32_t __stdcall GetStatus(int32_t hresult, int32_t* status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *status = detach_from<winrt::Windows::Networking::Sockets::SocketErrorStatus>(this->shim().GetStatus(hresult));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocket> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocket>
    {
        int32_t __stdcall get_Control(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::StreamSocketControl>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Information(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::StreamSocketInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InputStream(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IInputStream>(this->shim().InputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutputStream(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IOutputStream>(this->shim().OutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectWithEndpointPairAsync(void* endpointPair, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Networking::EndpointPair const*>(&endpointPair)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectAsync(void* remoteHostName, void* remoteServiceName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectWithEndpointPairAndProtectionLevelAsync(void* endpointPair, int32_t protectionLevel, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Networking::EndpointPair const*>(&endpointPair), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketProtectionLevel const*>(&protectionLevel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectWithProtectionLevelAsync(void* remoteHostName, void* remoteServiceName, int32_t protectionLevel, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketProtectionLevel const*>(&protectionLevel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpgradeToSslAsync(int32_t protectionLevel, void* validationHostName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().UpgradeToSslAsync(*reinterpret_cast<winrt::Windows::Networking::Sockets::SocketProtectionLevel const*>(&protectionLevel), *reinterpret_cast<winrt::Windows::Networking::HostName const*>(&validationHostName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocket2> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocket2>
    {
        int32_t __stdcall ConnectWithProtectionLevelAndAdapterAsync(void* remoteHostName, void* remoteServiceName, int32_t protectionLevel, void* adapter, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketProtectionLevel const*>(&protectionLevel), *reinterpret_cast<winrt::Windows::Networking::Connectivity::NetworkAdapter const*>(&adapter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocket3> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocket3>
    {
        int32_t __stdcall CancelIOAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().CancelIOAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableTransferOwnership(winrt::guid taskId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableTransferOwnership(*reinterpret_cast<winrt::guid const*>(&taskId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableTransferOwnershipWithConnectedStandbyAction(winrt::guid taskId, int32_t connectedStandbyAction) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableTransferOwnership(*reinterpret_cast<winrt::guid const*>(&taskId), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const*>(&connectedStandbyAction));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TransferOwnership(void* socketId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TransferOwnershipWithContext(void* socketId, void* data) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketActivityContext const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TransferOwnershipWithContextAndKeepAliveTime(void* socketId, void* data, int64_t keepAliveTime) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketActivityContext const*>(&data), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&keepAliveTime));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketControl> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketControl>
    {
        int32_t __stdcall get_NoDelay(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().NoDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NoDelay(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NoDelay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeepAlive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().KeepAlive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeepAlive(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeepAlive(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutboundBufferSizeInBytes(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().OutboundBufferSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutboundBufferSizeInBytes(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutboundBufferSizeInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_QualityOfService(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketQualityOfService>(this->shim().QualityOfService());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_QualityOfService(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().QualityOfService(*reinterpret_cast<winrt::Windows::Networking::Sockets::SocketQualityOfService const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutboundUnicastHopLimit(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().OutboundUnicastHopLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutboundUnicastHopLimit(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutboundUnicastHopLimit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketControl2> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketControl2>
    {
        int32_t __stdcall get_IgnorableServerCertificateErrors(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>>(this->shim().IgnorableServerCertificateErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketControl3> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketControl3>
    {
        int32_t __stdcall get_SerializeConnectionAttempts(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SerializeConnectionAttempts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SerializeConnectionAttempts(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SerializeConnectionAttempts(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClientCertificate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Cryptography::Certificates::Certificate>(this->shim().ClientCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClientCertificate(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClientCertificate(*reinterpret_cast<winrt::Windows::Security::Cryptography::Certificates::Certificate const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketControl4> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketControl4>
    {
        int32_t __stdcall get_MinProtectionLevel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketProtectionLevel>(this->shim().MinProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MinProtectionLevel(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MinProtectionLevel(*reinterpret_cast<winrt::Windows::Networking::Sockets::SocketProtectionLevel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketInformation> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketInformation>
    {
        int32_t __stdcall get_LocalAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().LocalAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocalPort(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LocalPort());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteHostName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().RemoteHostName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().RemoteAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteServiceName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemoteServiceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemotePort(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemotePort());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoundTripTimeStatistics(struct struct_Windows_Networking_Sockets_RoundTripTimeStatistics* value) noexcept final try
        {
            zero_abi<winrt::Windows::Networking::Sockets::RoundTripTimeStatistics>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::RoundTripTimeStatistics>(this->shim().RoundTripTimeStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BandwidthStatistics(struct struct_Windows_Networking_Sockets_BandwidthStatistics* value) noexcept final try
        {
            zero_abi<winrt::Windows::Networking::Sockets::BandwidthStatistics>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::BandwidthStatistics>(this->shim().BandwidthStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProtectionLevel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketProtectionLevel>(this->shim().ProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SessionKey(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().SessionKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketInformation2> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketInformation2>
    {
        int32_t __stdcall get_ServerCertificateErrorSeverity(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketSslErrorSeverity>(this->shim().ServerCertificateErrorSeverity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServerCertificateErrors(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>>(this->shim().ServerCertificateErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServerCertificate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Cryptography::Certificates::Certificate>(this->shim().ServerCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServerIntermediateCertificates(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>>(this->shim().ServerIntermediateCertificates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketListener> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketListener>
    {
        int32_t __stdcall get_Control(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::StreamSocketListenerControl>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Information(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::StreamSocketListenerInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall BindServiceNameAsync(void* localServiceName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().BindServiceNameAsync(*reinterpret_cast<hstring const*>(&localServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall BindEndpointAsync(void* localHostName, void* localServiceName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().BindEndpointAsync(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&localHostName), *reinterpret_cast<hstring const*>(&localServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ConnectionReceived(void* eventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().ConnectionReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::StreamSocketListener, winrt::Windows::Networking::Sockets::StreamSocketListenerConnectionReceivedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ConnectionReceived(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConnectionReceived(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketListener2> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketListener2>
    {
        int32_t __stdcall BindServiceNameWithProtectionLevelAsync(void* localServiceName, int32_t protectionLevel, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().BindServiceNameAsync(*reinterpret_cast<hstring const*>(&localServiceName), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketProtectionLevel const*>(&protectionLevel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall BindServiceNameWithProtectionLevelAndAdapterAsync(void* localServiceName, int32_t protectionLevel, void* adapter, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().BindServiceNameAsync(*reinterpret_cast<hstring const*>(&localServiceName), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketProtectionLevel const*>(&protectionLevel), *reinterpret_cast<winrt::Windows::Networking::Connectivity::NetworkAdapter const*>(&adapter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketListener3> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketListener3>
    {
        int32_t __stdcall CancelIOAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().CancelIOAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableTransferOwnership(winrt::guid taskId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableTransferOwnership(*reinterpret_cast<winrt::guid const*>(&taskId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableTransferOwnershipWithConnectedStandbyAction(winrt::guid taskId, int32_t connectedStandbyAction) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableTransferOwnership(*reinterpret_cast<winrt::guid const*>(&taskId), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const*>(&connectedStandbyAction));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TransferOwnership(void* socketId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TransferOwnershipWithContext(void* socketId, void* data) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketActivityContext const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketListenerConnectionReceivedEventArgs> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketListenerConnectionReceivedEventArgs>
    {
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
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketListenerControl> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketListenerControl>
    {
        int32_t __stdcall get_QualityOfService(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketQualityOfService>(this->shim().QualityOfService());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_QualityOfService(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().QualityOfService(*reinterpret_cast<winrt::Windows::Networking::Sockets::SocketQualityOfService const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketListenerControl2> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketListenerControl2>
    {
        int32_t __stdcall get_NoDelay(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().NoDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NoDelay(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NoDelay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeepAlive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().KeepAlive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeepAlive(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeepAlive(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutboundBufferSizeInBytes(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().OutboundBufferSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutboundBufferSizeInBytes(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutboundBufferSizeInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutboundUnicastHopLimit(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().OutboundUnicastHopLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutboundUnicastHopLimit(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutboundUnicastHopLimit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketListenerInformation> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketListenerInformation>
    {
        int32_t __stdcall get_LocalPort(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LocalPort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamSocketStatics> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamSocketStatics>
    {
        int32_t __stdcall GetEndpointPairsAsync(void* remoteHostName, void* remoteServiceName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>>(this->shim().GetEndpointPairsAsync(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetEndpointPairsWithSortOptionsAsync(void* remoteHostName, void* remoteServiceName, uint32_t sortOptions, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>>(this->shim().GetEndpointPairsAsync(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName), *reinterpret_cast<winrt::Windows::Networking::HostNameSortOptions const*>(&sortOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamWebSocket> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamWebSocket>
    {
        int32_t __stdcall get_Control(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::StreamWebSocketControl>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Information(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::StreamWebSocketInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InputStream(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IInputStream>(this->shim().InputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamWebSocket2> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamWebSocket2>
    {
        int32_t __stdcall add_ServerCustomValidationRequested(void* eventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().ServerCustomValidationRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::StreamWebSocket, winrt::Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ServerCustomValidationRequested(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ServerCustomValidationRequested(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamWebSocketControl> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamWebSocketControl>
    {
        int32_t __stdcall get_NoDelay(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().NoDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NoDelay(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NoDelay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IStreamWebSocketControl2> : produce_base<D, winrt::Windows::Networking::Sockets::IStreamWebSocketControl2>
    {
        int32_t __stdcall get_DesiredUnsolicitedPongInterval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().DesiredUnsolicitedPongInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredUnsolicitedPongInterval(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredUnsolicitedPongInterval(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActualUnsolicitedPongInterval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().ActualUnsolicitedPongInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClientCertificate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Cryptography::Certificates::Certificate>(this->shim().ClientCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClientCertificate(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClientCertificate(*reinterpret_cast<winrt::Windows::Security::Cryptography::Certificates::Certificate const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IWebSocket> : produce_base<D, winrt::Windows::Networking::Sockets::IWebSocket>
    {
        int32_t __stdcall get_OutputStream(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IOutputStream>(this->shim().OutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectAsync(void* uri, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetRequestHeader(void* headerName, void* headerValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetRequestHeader(*reinterpret_cast<hstring const*>(&headerName), *reinterpret_cast<hstring const*>(&headerValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Closed(void* eventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::Sockets::IWebSocket, winrt::Windows::Networking::Sockets::WebSocketClosedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
        int32_t __stdcall CloseWithStatus(uint16_t code, void* reason) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Close(code, *reinterpret_cast<hstring const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IWebSocketClosedEventArgs> : produce_base<D, winrt::Windows::Networking::Sockets::IWebSocketClosedEventArgs>
    {
        int32_t __stdcall get_Code(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Code());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Reason(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IWebSocketControl> : produce_base<D, winrt::Windows::Networking::Sockets::IWebSocketControl>
    {
        int32_t __stdcall get_OutboundBufferSizeInBytes(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().OutboundBufferSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutboundBufferSizeInBytes(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutboundBufferSizeInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServerCredential(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::PasswordCredential>(this->shim().ServerCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ServerCredential(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ServerCredential(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProxyCredential(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::PasswordCredential>(this->shim().ProxyCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProxyCredential(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProxyCredential(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedProtocols(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().SupportedProtocols());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IWebSocketControl2> : produce_base<D, winrt::Windows::Networking::Sockets::IWebSocketControl2>
    {
        int32_t __stdcall get_IgnorableServerCertificateErrors(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>>(this->shim().IgnorableServerCertificateErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IWebSocketErrorStatics> : produce_base<D, winrt::Windows::Networking::Sockets::IWebSocketErrorStatics>
    {
        int32_t __stdcall GetStatus(int32_t hresult, int32_t* status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *status = detach_from<winrt::Windows::Web::WebErrorStatus>(this->shim().GetStatus(hresult));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IWebSocketInformation> : produce_base<D, winrt::Windows::Networking::Sockets::IWebSocketInformation>
    {
        int32_t __stdcall get_LocalAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().LocalAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BandwidthStatistics(struct struct_Windows_Networking_Sockets_BandwidthStatistics* value) noexcept final try
        {
            zero_abi<winrt::Windows::Networking::Sockets::BandwidthStatistics>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::BandwidthStatistics>(this->shim().BandwidthStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Protocol(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Protocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IWebSocketInformation2> : produce_base<D, winrt::Windows::Networking::Sockets::IWebSocketInformation2>
    {
        int32_t __stdcall get_ServerCertificate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Cryptography::Certificates::Certificate>(this->shim().ServerCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServerCertificateErrorSeverity(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketSslErrorSeverity>(this->shim().ServerCertificateErrorSeverity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServerCertificateErrors(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>>(this->shim().ServerCertificateErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServerIntermediateCertificates(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>>(this->shim().ServerIntermediateCertificates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs> : produce_base<D, winrt::Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs>
    {
        int32_t __stdcall get_ServerCertificate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Cryptography::Certificates::Certificate>(this->shim().ServerCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServerCertificateErrorSeverity(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Sockets::SocketSslErrorSeverity>(this->shim().ServerCertificateErrorSeverity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServerCertificateErrors(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::ChainValidationResult>>(this->shim().ServerCertificateErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServerIntermediateCertificates(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Cryptography::Certificates::Certificate>>(this->shim().ServerIntermediateCertificates());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Reject() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Reject();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Networking::Sockets
{
    inline ControlChannelTrigger::ControlChannelTrigger(param::hstring const& channelId, uint32_t serverKeepAliveIntervalInMinutes) :
        ControlChannelTrigger(impl::call_factory<ControlChannelTrigger, IControlChannelTriggerFactory>([&](IControlChannelTriggerFactory const& f) { return f.CreateControlChannelTrigger(channelId, serverKeepAliveIntervalInMinutes); }))
    {
    }
    inline ControlChannelTrigger::ControlChannelTrigger(param::hstring const& channelId, uint32_t serverKeepAliveIntervalInMinutes, winrt::Windows::Networking::Sockets::ControlChannelTriggerResourceType const& resourceRequestType) :
        ControlChannelTrigger(impl::call_factory<ControlChannelTrigger, IControlChannelTriggerFactory>([&](IControlChannelTriggerFactory const& f) { return f.CreateControlChannelTriggerEx(channelId, serverKeepAliveIntervalInMinutes, resourceRequestType); }))
    {
    }
    inline DatagramSocket::DatagramSocket() :
        DatagramSocket(impl::call_factory_cast<DatagramSocket(*)(winrt::Windows::Foundation::IActivationFactory const&), DatagramSocket>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DatagramSocket>(); }))
    {
    }
    inline auto DatagramSocket::GetEndpointPairsAsync(winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName)
    {
        return impl::call_factory<DatagramSocket, IDatagramSocketStatics>([&](IDatagramSocketStatics const& f) { return f.GetEndpointPairsAsync(remoteHostName, remoteServiceName); });
    }
    inline auto DatagramSocket::GetEndpointPairsAsync(winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, winrt::Windows::Networking::HostNameSortOptions const& sortOptions)
    {
        return impl::call_factory<DatagramSocket, IDatagramSocketStatics>([&](IDatagramSocketStatics const& f) { return f.GetEndpointPairsAsync(remoteHostName, remoteServiceName, sortOptions); });
    }
    inline MessageWebSocket::MessageWebSocket() :
        MessageWebSocket(impl::call_factory_cast<MessageWebSocket(*)(winrt::Windows::Foundation::IActivationFactory const&), MessageWebSocket>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MessageWebSocket>(); }))
    {
    }
    inline SocketActivityContext::SocketActivityContext(winrt::Windows::Storage::Streams::IBuffer const& data) :
        SocketActivityContext(impl::call_factory<SocketActivityContext, ISocketActivityContextFactory>([&](ISocketActivityContextFactory const& f) { return f.Create(data); }))
    {
    }
    inline auto SocketActivityInformation::AllSockets()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Networking::Sockets::SocketActivityInformation>(*)(ISocketActivityInformationStatics const&), SocketActivityInformation, ISocketActivityInformationStatics>([](ISocketActivityInformationStatics const& f) { return f.AllSockets(); });
    }
    inline auto SocketError::GetStatus(int32_t hresult)
    {
        return impl::call_factory<SocketError, ISocketErrorStatics>([&](ISocketErrorStatics const& f) { return f.GetStatus(hresult); });
    }
    inline StreamSocket::StreamSocket() :
        StreamSocket(impl::call_factory_cast<StreamSocket(*)(winrt::Windows::Foundation::IActivationFactory const&), StreamSocket>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StreamSocket>(); }))
    {
    }
    inline auto StreamSocket::GetEndpointPairsAsync(winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName)
    {
        return impl::call_factory<StreamSocket, IStreamSocketStatics>([&](IStreamSocketStatics const& f) { return f.GetEndpointPairsAsync(remoteHostName, remoteServiceName); });
    }
    inline auto StreamSocket::GetEndpointPairsAsync(winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, winrt::Windows::Networking::HostNameSortOptions const& sortOptions)
    {
        return impl::call_factory<StreamSocket, IStreamSocketStatics>([&](IStreamSocketStatics const& f) { return f.GetEndpointPairsAsync(remoteHostName, remoteServiceName, sortOptions); });
    }
    inline StreamSocketListener::StreamSocketListener() :
        StreamSocketListener(impl::call_factory_cast<StreamSocketListener(*)(winrt::Windows::Foundation::IActivationFactory const&), StreamSocketListener>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StreamSocketListener>(); }))
    {
    }
    inline StreamWebSocket::StreamWebSocket() :
        StreamWebSocket(impl::call_factory_cast<StreamWebSocket(*)(winrt::Windows::Foundation::IActivationFactory const&), StreamWebSocket>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StreamWebSocket>(); }))
    {
    }
    inline auto WebSocketError::GetStatus(int32_t hresult)
    {
        return impl::call_factory<WebSocketError, IWebSocketErrorStatics>([&](IWebSocketErrorStatics const& f) { return f.GetStatus(hresult); });
    }
    inline WebSocketKeepAlive::WebSocketKeepAlive() :
        WebSocketKeepAlive(impl::call_factory_cast<WebSocketKeepAlive(*)(winrt::Windows::Foundation::IActivationFactory const&), WebSocketKeepAlive>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WebSocketKeepAlive>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Networking::Sockets::IControlChannelTrigger> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IControlChannelTrigger2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IControlChannelTriggerEventDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IControlChannelTriggerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IControlChannelTriggerResetEventDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocket2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocket3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocketControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocketControl2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocketControl3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocketInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocketStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocket2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocket3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocketControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocketControl2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IServerMessageWebSocket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IServerMessageWebSocketControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IServerMessageWebSocketInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IServerStreamWebSocket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IServerStreamWebSocketInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::ISocketActivityContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::ISocketActivityContextFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::ISocketActivityInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::ISocketActivityInformationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::ISocketActivityTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::ISocketErrorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocket2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocket3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketControl2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketControl3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketControl4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketInformation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListener> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListener2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListener3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListenerConnectionReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListenerControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListenerControl2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListenerInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamWebSocket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamWebSocket2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamWebSocketControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IStreamWebSocketControl2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketControl2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketErrorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketInformation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::ControlChannelTrigger> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::DatagramSocket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::DatagramSocketControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::DatagramSocketInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::DatagramSocketMessageReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::MessageWebSocket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::MessageWebSocketControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::MessageWebSocketInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::ServerMessageWebSocket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::ServerMessageWebSocketControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::ServerMessageWebSocketInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::ServerStreamWebSocket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::ServerStreamWebSocketInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::SocketActivityContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::SocketActivityInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::SocketActivityTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::SocketError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocketControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocketInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocketListener> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocketListenerConnectionReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocketListenerControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocketListenerInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::StreamWebSocket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::StreamWebSocketControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::StreamWebSocketInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::WebSocketClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::WebSocketError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::WebSocketKeepAlive> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
