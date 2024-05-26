// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_WiFiDirect_Services_H
#define WINRT_Windows_Devices_WiFiDirect_Services_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.WiFiDirect.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.WiFiDirect.Services.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::RemoteServiceInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->get_RemoteServiceInfo(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SupportedConfigurationMethods() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->get_SupportedConfigurationMethods(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::PreferGroupOwnerMode() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->get_PreferGroupOwnerMode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::PreferGroupOwnerMode(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->put_PreferGroupOwnerMode(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SessionInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->get_SessionInfo(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SessionInfo(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->put_SessionInfo(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::ServiceError() const
    {
        winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->get_ServiceError(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SessionDeferred(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->add_SessionDeferred(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SessionDeferred_revoker consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SessionDeferred(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SessionDeferred_revoker>(this, SessionDeferred(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SessionDeferred(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->remove_SessionDeferred(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo>) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::GetProvisioningInfoAsync(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod const& selectedConfigurationMethod) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->GetProvisioningInfoAsync(static_cast<int32_t>(selectedConfigurationMethod), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::ConnectAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->ConnectAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::ConnectAsync(param::hstring const& pin) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->ConnectAsyncWithPin(*(void**)(&pin), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_ServiceName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceNamePrefixes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_ServiceNamePrefixes(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_ServiceInfo(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceInfo(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->put_ServiceInfo(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AutoAcceptSession() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_AutoAcceptSession(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AutoAcceptSession(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->put_AutoAcceptSession(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::PreferGroupOwnerMode() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_PreferGroupOwnerMode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::PreferGroupOwnerMode(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->put_PreferGroupOwnerMode(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::PreferredConfigurationMethods() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_PreferredConfigurationMethods(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceStatus() const
    {
        winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_ServiceStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceStatus(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->put_ServiceStatus(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::CustomServiceStatusCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_CustomServiceStatusCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::CustomServiceStatusCode(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->put_CustomServiceStatusCode(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::DeferredSessionInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_DeferredSessionInfo(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::DeferredSessionInfo(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->put_DeferredSessionInfo(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertisementStatus) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AdvertisementStatus() const
    {
        winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertisementStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_AdvertisementStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceError() const
    {
        winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_ServiceError(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::SessionRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->add_SessionRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::SessionRequested_revoker consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::SessionRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SessionRequested_revoker>(this, SessionRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::SessionRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->remove_SessionRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AutoAcceptSessionConnected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->add_AutoAcceptSessionConnected(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AutoAcceptSessionConnected_revoker consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AutoAcceptSessionConnected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AutoAcceptSessionConnected_revoker>(this, AutoAcceptSessionConnected(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AutoAcceptSessionConnected(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->remove_AutoAcceptSessionConnected(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AdvertisementStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->add_AdvertisementStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AdvertisementStatusChanged_revoker consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AdvertisementStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, AdvertisementStatusChanged_revoker>(this, AdvertisementStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AdvertisementStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->remove_AdvertisementStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ConnectAsync(winrt::Windows::Devices::Enumeration::DeviceInformation const& deviceInfo) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->ConnectAsync(*(void**)(&deviceInfo), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ConnectAsync(winrt::Windows::Devices::Enumeration::DeviceInformation const& deviceInfo, param::hstring const& pin) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->ConnectAsyncWithPin(*(void**)(&deviceInfo), *(void**)(&pin), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiserFactory<D>::CreateWiFiDirectServiceAdvertiser(param::hstring const& serviceName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory)->CreateWiFiDirectServiceAdvertiser(*(void**)(&serviceName), &result));
        return winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs<D>::Session() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs)->get_Session(&value));
        return winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs<D>::SessionInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs)->get_SessionInfo(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceProvisioningInfo<D>::SelectedConfigurationMethod() const
    {
        winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo)->get_SelectedConfigurationMethod(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceProvisioningInfo<D>::IsGroupFormationNeeded() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo)->get_IsGroupFormationNeeded(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceRemotePortAddedEventArgs<D>::EndpointPairs() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs)->get_EndpointPairs(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceIPProtocol) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceRemotePortAddedEventArgs<D>::Protocol() const
    {
        winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceIPProtocol value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs)->get_Protocol(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::ServiceName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_ServiceName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionStatus) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::Status() const
    {
        winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionErrorStatus) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::ErrorStatus() const
    {
        winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionErrorStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_ErrorStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::SessionId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_SessionId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::AdvertisementId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_AdvertisementId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::ServiceAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_ServiceAddress(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::SessionAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_SessionAddress(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::GetConnectionEndpointPairs() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->GetConnectionEndpointPairs(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::SessionStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->add_SessionStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::SessionStatusChanged_revoker consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::SessionStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SessionStatusChanged_revoker>(this, SessionStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::SessionStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->remove_SessionStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::AddStreamSocketListenerAsync(winrt::Windows::Networking::Sockets::StreamSocketListener const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->AddStreamSocketListenerAsync(*(void**)(&value), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::AddDatagramSocketAsync(winrt::Windows::Networking::Sockets::DatagramSocket const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->AddDatagramSocketAsync(*(void**)(&value), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::RemotePortAdded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->add_RemotePortAdded(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::RemotePortAdded_revoker consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::RemotePortAdded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RemotePortAdded_revoker>(this, RemotePortAdded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::RemotePortAdded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->remove_RemotePortAdded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionDeferredEventArgs<D>::DeferredSessionInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs)->get_DeferredSessionInfo(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionRequest<D>::DeviceInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest)->get_DeviceInformation(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionRequest<D>::ProvisioningInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest)->get_ProvisioningInfo(&value));
        return winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionRequest<D>::SessionInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest)->get_SessionInfo(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionRequestedEventArgs<D>::GetSessionRequest() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs)->GetSessionRequest(&value));
        return winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceStatics<D>::GetSelector(param::hstring const& serviceName) const
    {
        void* serviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics)->GetSelector(*(void**)(&serviceName), &serviceSelector));
        return hstring{ serviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceStatics<D>::GetSelector(param::hstring const& serviceName, winrt::Windows::Storage::Streams::IBuffer const& serviceInfoFilter) const
    {
        void* serviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics)->GetSelectorWithFilter(*(void**)(&serviceName), *(void**)(&serviceInfoFilter), &serviceSelector));
        return hstring{ serviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService>) consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics)->FromIdAsync(*(void**)(&deviceId), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService>{ asyncOp, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService> : produce_base<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService>
    {
        int32_t __stdcall get_RemoteServiceInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().RemoteServiceInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedConfigurationMethods(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>>(this->shim().SupportedConfigurationMethods());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreferGroupOwnerMode(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().PreferGroupOwnerMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PreferGroupOwnerMode(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreferGroupOwnerMode(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SessionInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SessionInfo(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SessionInfo(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceError(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError>(this->shim().ServiceError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SessionDeferred(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SessionDeferred(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SessionDeferred(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SessionDeferred(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetProvisioningInfoAsync(int32_t selectedConfigurationMethod, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo>>(this->shim().GetProvisioningInfoAsync(*reinterpret_cast<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod const*>(&selectedConfigurationMethod)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>>(this->shim().ConnectAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectAsyncWithPin(void* pin, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>>(this->shim().ConnectAsync(*reinterpret_cast<hstring const*>(&pin)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser> : produce_base<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser>
    {
        int32_t __stdcall get_ServiceName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ServiceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceNamePrefixes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().ServiceNamePrefixes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().ServiceInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ServiceInfo(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ServiceInfo(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutoAcceptSession(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AutoAcceptSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoAcceptSession(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoAcceptSession(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreferGroupOwnerMode(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().PreferGroupOwnerMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PreferGroupOwnerMode(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreferGroupOwnerMode(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreferredConfigurationMethods(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>>(this->shim().PreferredConfigurationMethods());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus>(this->shim().ServiceStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ServiceStatus(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ServiceStatus(*reinterpret_cast<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomServiceStatusCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CustomServiceStatusCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CustomServiceStatusCode(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CustomServiceStatusCode(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeferredSessionInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().DeferredSessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DeferredSessionInfo(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeferredSessionInfo(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AdvertisementStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertisementStatus>(this->shim().AdvertisementStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceError(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError>(this->shim().ServiceError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SessionRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SessionRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SessionRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SessionRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AutoAcceptSessionConnected(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AutoAcceptSessionConnected(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AutoAcceptSessionConnected(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoAcceptSessionConnected(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AdvertisementStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AdvertisementStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AdvertisementStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AdvertisementStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall ConnectAsync(void* deviceInfo, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformation const*>(&deviceInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectAsyncWithPin(void* deviceInfo, void* pin, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformation const*>(&deviceInfo), *reinterpret_cast<hstring const*>(&pin)));
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
    struct produce<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory> : produce_base<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory>
    {
        int32_t __stdcall CreateWiFiDirectServiceAdvertiser(void* serviceName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser>(this->shim().CreateWiFiDirectServiceAdvertiser(*reinterpret_cast<hstring const*>(&serviceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs> : produce_base<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs>
    {
        int32_t __stdcall get_Session(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SessionInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo> : produce_base<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo>
    {
        int32_t __stdcall get_SelectedConfigurationMethod(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>(this->shim().SelectedConfigurationMethod());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsGroupFormationNeeded(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsGroupFormationNeeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs> : produce_base<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs>
    {
        int32_t __stdcall get_EndpointPairs(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>(this->shim().EndpointPairs());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Protocol(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceIPProtocol>(this->shim().Protocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession> : produce_base<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession>
    {
        int32_t __stdcall get_ServiceName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ServiceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionErrorStatus>(this->shim().ErrorStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SessionId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SessionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AdvertisementId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().AdvertisementId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ServiceAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SessionAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SessionAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConnectionEndpointPairs(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>(this->shim().GetConnectionEndpointPairs());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SessionStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SessionStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SessionStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SessionStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall AddStreamSocketListenerAsync(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AddStreamSocketListenerAsync(*reinterpret_cast<winrt::Windows::Networking::Sockets::StreamSocketListener const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDatagramSocketAsync(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AddDatagramSocketAsync(*reinterpret_cast<winrt::Windows::Networking::Sockets::DatagramSocket const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_RemotePortAdded(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RemotePortAdded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RemotePortAdded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemotePortAdded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs> : produce_base<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs>
    {
        int32_t __stdcall get_DeferredSessionInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().DeferredSessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest> : produce_base<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest>
    {
        int32_t __stdcall get_DeviceInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().DeviceInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProvisioningInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo>(this->shim().ProvisioningInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SessionInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs> : produce_base<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs>
    {
        int32_t __stdcall GetSessionRequest(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest>(this->shim().GetSessionRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics> : produce_base<D, winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics>
    {
        int32_t __stdcall GetSelector(void* serviceName, void** serviceSelector) noexcept final try
        {
            clear_abi(serviceSelector);
            typename D::abi_guard guard(this->shim());
            *serviceSelector = detach_from<hstring>(this->shim().GetSelector(*reinterpret_cast<hstring const*>(&serviceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSelectorWithFilter(void* serviceName, void* serviceInfoFilter, void** serviceSelector) noexcept final try
        {
            clear_abi(serviceSelector);
            typename D::abi_guard guard(this->shim());
            *serviceSelector = detach_from<hstring>(this->shim().GetSelector(*reinterpret_cast<hstring const*>(&serviceName), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&serviceInfoFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::WiFiDirect::Services
{
    inline auto WiFiDirectService::GetSelector(param::hstring const& serviceName)
    {
        return impl::call_factory<WiFiDirectService, IWiFiDirectServiceStatics>([&](IWiFiDirectServiceStatics const& f) { return f.GetSelector(serviceName); });
    }
    inline auto WiFiDirectService::GetSelector(param::hstring const& serviceName, winrt::Windows::Storage::Streams::IBuffer const& serviceInfoFilter)
    {
        return impl::call_factory<WiFiDirectService, IWiFiDirectServiceStatics>([&](IWiFiDirectServiceStatics const& f) { return f.GetSelector(serviceName, serviceInfoFilter); });
    }
    inline auto WiFiDirectService::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<WiFiDirectService, IWiFiDirectServiceStatics>([&](IWiFiDirectServiceStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline WiFiDirectServiceAdvertiser::WiFiDirectServiceAdvertiser(param::hstring const& serviceName) :
        WiFiDirectServiceAdvertiser(impl::call_factory<WiFiDirectServiceAdvertiser, IWiFiDirectServiceAdvertiserFactory>([&](IWiFiDirectServiceAdvertiserFactory const& f) { return f.CreateWiFiDirectServiceAdvertiser(serviceName); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
