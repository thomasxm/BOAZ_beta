// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_RemoteSystems_H
#define WINRT_Windows_System_RemoteSystems_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.h"
#include "winrt/impl/Windows.ApplicationModel.AppService.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.System.RemoteSystems.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IKnownRemoteSystemCapabilitiesStatics<D>::AppService() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics)->get_AppService(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IKnownRemoteSystemCapabilitiesStatics<D>::LaunchUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics)->get_LaunchUri(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IKnownRemoteSystemCapabilitiesStatics<D>::RemoteSession() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics)->get_RemoteSession(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IKnownRemoteSystemCapabilitiesStatics<D>::SpatialEntity() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics)->get_SpatialEntity(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystem<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystem)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystem<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystem)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystem<D>::Kind() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystem)->get_Kind(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemStatus) consume_Windows_System_RemoteSystems_IRemoteSystem<D>::Status() const
    {
        winrt::Windows::System::RemoteSystems::RemoteSystemStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystem)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_RemoteSystems_IRemoteSystem<D>::IsAvailableByProximity() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystem)->get_IsAvailableByProximity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_RemoteSystems_IRemoteSystem2<D>::IsAvailableBySpatialProximity() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystem2)->get_IsAvailableBySpatialProximity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_RemoteSystems_IRemoteSystem2<D>::GetCapabilitySupportedAsync(param::hstring const& capabilityName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystem2)->GetCapabilitySupportedAsync(*(void**)(&capabilityName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystem3<D>::ManufacturerDisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystem3)->get_ManufacturerDisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystem3<D>::ModelDisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystem3)->get_ModelDisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemPlatform) consume_Windows_System_RemoteSystems_IRemoteSystem4<D>::Platform() const
    {
        winrt::Windows::System::RemoteSystems::RemoteSystemPlatform value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystem4)->get_Platform(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::RemoteSystems::RemoteSystemApp>) consume_Windows_System_RemoteSystems_IRemoteSystem5<D>::Apps() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystem5)->get_Apps(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::RemoteSystems::RemoteSystemApp>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_RemoteSystems_IRemoteSystem6<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystem6)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystem) consume_Windows_System_RemoteSystems_IRemoteSystemAddedEventArgs<D>::RemoteSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemAddedEventArgs)->get_RemoteSystem(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemApp<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemApp)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemApp<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemApp)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_RemoteSystems_IRemoteSystemApp<D>::IsAvailableByProximity() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemApp)->get_IsAvailableByProximity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_RemoteSystems_IRemoteSystemApp<D>::IsAvailableBySpatialProximity() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemApp)->get_IsAvailableBySpatialProximity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>) consume_Windows_System_RemoteSystems_IRemoteSystemApp<D>::Attributes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemApp)->get_Attributes(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_RemoteSystems_IRemoteSystemApp2<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemApp2)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemApp2<D>::ConnectionToken() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemApp2)->get_ConnectionToken(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_RemoteSystems_IRemoteSystemAppRegistration<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistration)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) consume_Windows_System_RemoteSystems_IRemoteSystemAppRegistration<D>::Attributes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistration)->get_Attributes(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_RemoteSystems_IRemoteSystemAppRegistration<D>::SaveAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistration)->SaveAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemAppRegistration) consume_Windows_System_RemoteSystems_IRemoteSystemAppRegistrationStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistrationStatics)->GetDefault(&result));
        return winrt::Windows::System::RemoteSystems::RemoteSystemAppRegistration{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemAppRegistration) consume_Windows_System_RemoteSystems_IRemoteSystemAppRegistrationStatics<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistrationStatics)->GetForUser(*(void**)(&user), &result));
        return winrt::Windows::System::RemoteSystems::RemoteSystemAppRegistration{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKind) consume_Windows_System_RemoteSystems_IRemoteSystemAuthorizationKindFilter<D>::RemoteSystemAuthorizationKind() const
    {
        winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilter)->get_RemoteSystemAuthorizationKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKindFilter) consume_Windows_System_RemoteSystems_IRemoteSystemAuthorizationKindFilterFactory<D>::Create(winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const& remoteSystemAuthorizationKind) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilterFactory)->Create(static_cast<int32_t>(remoteSystemAuthorizationKind), &value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKindFilter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_RemoteSystems_IRemoteSystemConnectionInfo<D>::IsProximal() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionInfo)->get_IsProximal(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemConnectionInfo) consume_Windows_System_RemoteSystems_IRemoteSystemConnectionInfoStatics<D>::TryCreateFromAppServiceConnection(winrt::Windows::ApplicationModel::AppService::AppServiceConnection const& connection) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionInfoStatics)->TryCreateFromAppServiceConnection(*(void**)(&connection), &result));
        return winrt::Windows::System::RemoteSystems::RemoteSystemConnectionInfo{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystem) consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequest<D>::RemoteSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest)->get_RemoteSystem(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemApp) consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequest2<D>::RemoteSystemApp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest2)->get_RemoteSystemApp(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemApp{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequest3<D>::ConnectionToken() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest3)->get_ConnectionToken(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest) consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequestFactory<D>::Create(winrt::Windows::System::RemoteSystems::RemoteSystem const& remoteSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestFactory)->Create(*(void**)(&remoteSystem), &value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest) consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequestStatics<D>::CreateForApp(winrt::Windows::System::RemoteSystems::RemoteSystemApp const& remoteSystemApp) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics)->CreateForApp(*(void**)(&remoteSystemApp), &result));
        return winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest) consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequestStatics2<D>::CreateFromConnectionToken(param::hstring const& connectionToken) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics2)->CreateFromConnectionToken(*(void**)(&connectionToken), &result));
        return winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest) consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequestStatics2<D>::CreateFromConnectionTokenForUser(winrt::Windows::System::User const& user, param::hstring const& connectionToken) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics2)->CreateFromConnectionTokenForUser(*(void**)(&user), *(void**)(&connectionToken), &result));
        return winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemDiscoveryType) consume_Windows_System_RemoteSystems_IRemoteSystemDiscoveryTypeFilter<D>::RemoteSystemDiscoveryType() const
    {
        winrt::Windows::System::RemoteSystems::RemoteSystemDiscoveryType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilter)->get_RemoteSystemDiscoveryType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemDiscoveryTypeFilter) consume_Windows_System_RemoteSystems_IRemoteSystemDiscoveryTypeFilterFactory<D>::Create(winrt::Windows::System::RemoteSystems::RemoteSystemDiscoveryType const& discoveryType) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilterFactory)->Create(static_cast<int32_t>(discoveryType), &value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemDiscoveryTypeFilter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_System_RemoteSystems_IRemoteSystemKindFilter<D>::RemoteSystemKinds() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemKindFilter)->get_RemoteSystemKinds(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemKindFilter) consume_Windows_System_RemoteSystems_IRemoteSystemKindFilterFactory<D>::Create(param::iterable<hstring> const& remoteSystemKinds) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemKindFilterFactory)->Create(*(void**)(&remoteSystemKinds), &value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemKindFilter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics<D>::Phone() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics)->get_Phone(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics<D>::Hub() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics)->get_Hub(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics<D>::Holographic() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics)->get_Holographic(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics<D>::Desktop() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics)->get_Desktop(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics<D>::Xbox() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics)->get_Xbox(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics2<D>::Iot() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics2)->get_Iot(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics2<D>::Tablet() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics2)->get_Tablet(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics2<D>::Laptop() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics2)->get_Laptop(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemRemovedEventArgs<D>::RemoteSystemId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemRemovedEventArgs)->get_RemoteSystemId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSession)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSession)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::ControllerDisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSession)->get_ControllerDisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::Disconnected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSession, winrt::Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSession)->add_Disconnected(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::Disconnected_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::Disconnected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSession, winrt::Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Disconnected_revoker>(this, Disconnected(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::Disconnected(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSession)->remove_Disconnected(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher) consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::CreateParticipantWatcher() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSession)->CreateParticipantWatcher(&result));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::SendInvitationAsync(winrt::Windows::System::RemoteSystems::RemoteSystem const& invitee) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSession)->SendInvitationAsync(*(void**)(&invitee), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo) consume_Windows_System_RemoteSystems_IRemoteSystemSessionAddedEventArgs<D>::SessionInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionAddedEventArgs)->get_SessionInfo(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemSessionController<D>::JoinRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionController, winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionController)->add_JoinRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionController<D>::JoinRequested_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionController<D>::JoinRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionController, winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, JoinRequested_revoker>(this, JoinRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionController<D>::JoinRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionController)->remove_JoinRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_RemoteSystems_IRemoteSystemSessionController<D>::RemoveParticipantAsync(winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant const& pParticipant) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionController)->RemoveParticipantAsync(*(void**)(&pParticipant), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteSystems::RemoteSystemSessionCreationResult>) consume_Windows_System_RemoteSystems_IRemoteSystemSessionController<D>::CreateSessionAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionController)->CreateSessionAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteSystems::RemoteSystemSessionCreationResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionController) consume_Windows_System_RemoteSystems_IRemoteSystemSessionControllerFactory<D>::CreateController(param::hstring const& displayName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionControllerFactory)->CreateController(*(void**)(&displayName), &value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionController) consume_Windows_System_RemoteSystems_IRemoteSystemSessionControllerFactory<D>::CreateController(param::hstring const& displayName, winrt::Windows::System::RemoteSystems::RemoteSystemSessionOptions const& options) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionControllerFactory)->CreateControllerWithSessionOptions(*(void**)(&displayName), *(void**)(&options), &value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionCreationStatus) consume_Windows_System_RemoteSystems_IRemoteSystemSessionCreationResult<D>::Status() const
    {
        winrt::Windows::System::RemoteSystems::RemoteSystemSessionCreationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionCreationResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSession) consume_Windows_System_RemoteSystems_IRemoteSystemSessionCreationResult<D>::Session() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionCreationResult)->get_Session(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSession{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedReason) consume_Windows_System_RemoteSystems_IRemoteSystemSessionDisconnectedEventArgs<D>::Reason() const
    {
        winrt::Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionDisconnectedEventArgs)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemSessionInfo<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInfo)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteSystems_IRemoteSystemSessionInfo<D>::ControllerDisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInfo)->get_ControllerDisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinResult>) consume_Windows_System_RemoteSystems_IRemoteSystemSessionInfo<D>::JoinAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInfo)->JoinAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystem) consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitation<D>::Sender() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitation)->get_Sender(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo) consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitation<D>::SessionInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitation)->get_SessionInfo(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitationListener<D>::InvitationReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitationListener, winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitationReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitationListener)->add_InvitationReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitationListener<D>::InvitationReceived_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitationListener<D>::InvitationReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitationListener, winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitationReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, InvitationReceived_revoker>(this, InvitationReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitationListener<D>::InvitationReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitationListener)->remove_InvitationReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitation) consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitationReceivedEventArgs<D>::Invitation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitationReceivedEventArgs)->get_Invitation(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant) consume_Windows_System_RemoteSystems_IRemoteSystemSessionJoinRequest<D>::Participant() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequest)->get_Participant(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionJoinRequest<D>::Accept() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequest)->Accept());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinRequest) consume_Windows_System_RemoteSystems_IRemoteSystemSessionJoinRequestedEventArgs<D>::JoinRequest() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequestedEventArgs)->get_JoinRequest(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_System_RemoteSystems_IRemoteSystemSessionJoinRequestedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequestedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinStatus) consume_Windows_System_RemoteSystems_IRemoteSystemSessionJoinResult<D>::Status() const
    {
        winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSession) consume_Windows_System_RemoteSystems_IRemoteSystemSessionJoinResult<D>::Session() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinResult)->get_Session(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSession{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSession) consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::Session() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel)->get_Session(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSession{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::BroadcastValueSetAsync(winrt::Windows::Foundation::Collections::ValueSet const& messageData) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel)->BroadcastValueSetAsync(*(void**)(&messageData), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::SendValueSetAsync(winrt::Windows::Foundation::Collections::ValueSet const& messageData, winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant const& participant) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel)->SendValueSetAsync(*(void**)(&messageData), *(void**)(&participant), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::SendValueSetToParticipantsAsync(winrt::Windows::Foundation::Collections::ValueSet const& messageData, param::async_iterable<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant> const& participants) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel)->SendValueSetToParticipantsAsync(*(void**)(&messageData), *(void**)(&participants), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::ValueSetReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel, winrt::Windows::System::RemoteSystems::RemoteSystemSessionValueSetReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel)->add_ValueSetReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::ValueSetReceived_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::ValueSetReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel, winrt::Windows::System::RemoteSystems::RemoteSystemSessionValueSetReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ValueSetReceived_revoker>(this, ValueSetReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::ValueSetReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel)->remove_ValueSetReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel) consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannelFactory<D>::Create(winrt::Windows::System::RemoteSystems::RemoteSystemSession const& session, param::hstring const& channelName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannelFactory)->Create(*(void**)(&session), *(void**)(&channelName), &value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel) consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannelFactory<D>::Create(winrt::Windows::System::RemoteSystems::RemoteSystemSession const& session, param::hstring const& channelName, winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannelReliability const& reliability) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannelFactory)->CreateWithReliability(*(void**)(&session), *(void**)(&channelName), static_cast<int32_t>(reliability), &value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_RemoteSystems_IRemoteSystemSessionOptions<D>::IsInviteOnly() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionOptions)->get_IsInviteOnly(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionOptions<D>::IsInviteOnly(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionOptions)->put_IsInviteOnly(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystem) consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipant<D>::RemoteSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipant)->get_RemoteSystem(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::HostName>) consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipant<D>::GetHostNames() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipant)->GetHostNames(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::HostName>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant) consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantAddedEventArgs<D>::Participant() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantAddedEventArgs)->get_Participant(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant) consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantRemovedEventArgs<D>::Participant() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantRemovedEventArgs)->get_Participant(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcherStatus) consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Status() const
    {
        winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcherStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Added(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantAddedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->add_Added(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Added_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Added(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantAddedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Added(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->remove_Added(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Removed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantRemovedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->add_Removed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Removed_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Removed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantRemovedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Removed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->remove_Removed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::EnumerationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->add_EnumerationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::EnumerationCompleted_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::EnumerationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->remove_EnumerationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo) consume_Windows_System_RemoteSystems_IRemoteSystemSessionRemovedEventArgs<D>::SessionInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionRemovedEventArgs)->get_SessionInfo(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher) consume_Windows_System_RemoteSystems_IRemoteSystemSessionStatics<D>::CreateWatcher() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionStatics)->CreateWatcher(&result));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo) consume_Windows_System_RemoteSystems_IRemoteSystemSessionUpdatedEventArgs<D>::SessionInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionUpdatedEventArgs)->get_SessionInfo(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant) consume_Windows_System_RemoteSystems_IRemoteSystemSessionValueSetReceivedEventArgs<D>::Sender() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionValueSetReceivedEventArgs)->get_Sender(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_System_RemoteSystems_IRemoteSystemSessionValueSetReceivedEventArgs<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionValueSetReceivedEventArgs)->get_Message(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcherStatus) consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Status() const
    {
        winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcherStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Added(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionAddedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->add_Added(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Added_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Added(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionAddedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Added(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->remove_Added(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Updated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionUpdatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->add_Updated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Updated_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Updated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionUpdatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Updated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->remove_Updated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Removed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionRemovedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->add_Removed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Removed_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Removed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionRemovedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Removed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->remove_Removed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteSystems::RemoteSystem>) consume_Windows_System_RemoteSystems_IRemoteSystemStatics<D>::FindByHostNameAsync(winrt::Windows::Networking::HostName const& hostName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemStatics)->FindByHostNameAsync(*(void**)(&hostName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteSystems::RemoteSystem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemWatcher) consume_Windows_System_RemoteSystems_IRemoteSystemStatics<D>::CreateWatcher() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemStatics)->CreateWatcher(&result));
        return winrt::Windows::System::RemoteSystems::RemoteSystemWatcher{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemWatcher) consume_Windows_System_RemoteSystems_IRemoteSystemStatics<D>::CreateWatcher(param::iterable<winrt::Windows::System::RemoteSystems::IRemoteSystemFilter> const& filters) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemStatics)->CreateWatcherWithFilters(*(void**)(&filters), &result));
        return winrt::Windows::System::RemoteSystems::RemoteSystemWatcher{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteSystems::RemoteSystemAccessStatus>) consume_Windows_System_RemoteSystems_IRemoteSystemStatics<D>::RequestAccessAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemStatics)->RequestAccessAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteSystems::RemoteSystemAccessStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_RemoteSystems_IRemoteSystemStatics2<D>::IsAuthorizationKindEnabled(winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const& kind) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemStatics2)->IsAuthorizationKindEnabled(static_cast<int32_t>(kind), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemWatcher) consume_Windows_System_RemoteSystems_IRemoteSystemStatics3<D>::CreateWatcherForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemStatics3)->CreateWatcherForUser(*(void**)(&user), &result));
        return winrt::Windows::System::RemoteSystems::RemoteSystemWatcher{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemWatcher) consume_Windows_System_RemoteSystems_IRemoteSystemStatics3<D>::CreateWatcherForUser(winrt::Windows::System::User const& user, param::iterable<winrt::Windows::System::RemoteSystems::IRemoteSystemFilter> const& filters) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemStatics3)->CreateWatcherWithFiltersForUser(*(void**)(&user), *(void**)(&filters), &result));
        return winrt::Windows::System::RemoteSystems::RemoteSystemWatcher{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemStatusType) consume_Windows_System_RemoteSystems_IRemoteSystemStatusTypeFilter<D>::RemoteSystemStatusType() const
    {
        winrt::Windows::System::RemoteSystems::RemoteSystemStatusType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilter)->get_RemoteSystemStatusType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemStatusTypeFilter) consume_Windows_System_RemoteSystems_IRemoteSystemStatusTypeFilterFactory<D>::Create(winrt::Windows::System::RemoteSystems::RemoteSystemStatusType const& remoteSystemStatusType) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilterFactory)->Create(static_cast<int32_t>(remoteSystemStatusType), &value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemStatusTypeFilter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystem) consume_Windows_System_RemoteSystems_IRemoteSystemUpdatedEventArgs<D>::RemoteSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemUpdatedEventArgs)->get_RemoteSystem(&value));
        return winrt::Windows::System::RemoteSystems::RemoteSystem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemAdded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemAddedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher)->add_RemoteSystemAdded(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemAdded_revoker consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemAdded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemAddedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RemoteSystemAdded_revoker>(this, RemoteSystemAdded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemAdded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher)->remove_RemoteSystemAdded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemUpdatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher)->add_RemoteSystemUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemUpdated_revoker consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemUpdatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RemoteSystemUpdated_revoker>(this, RemoteSystemUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher)->remove_RemoteSystemUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemRemoved(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemRemovedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher)->add_RemoteSystemRemoved(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemRemoved_revoker consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemRemoved(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemRemovedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RemoteSystemRemoved_revoker>(this, RemoteSystemRemoved(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemRemoved(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher)->remove_RemoteSystemRemoved(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::EnumerationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemEnumerationCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher2)->add_EnumerationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::EnumerationCompleted_revoker consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::EnumerationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemEnumerationCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher2)->remove_EnumerationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::ErrorOccurred(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemWatcherErrorOccurredEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher2)->add_ErrorOccurred(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::ErrorOccurred_revoker consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::ErrorOccurred(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemWatcherErrorOccurredEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ErrorOccurred_revoker>(this, ErrorOccurred(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::ErrorOccurred(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher2)->remove_ErrorOccurred(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_System_RemoteSystems_IRemoteSystemWatcher3<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher3)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemWatcherError) consume_Windows_System_RemoteSystems_IRemoteSystemWatcherErrorOccurredEventArgs<D>::Error() const
    {
        winrt::Windows::System::RemoteSystems::RemoteSystemWatcherError value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWatcherErrorOccurredEventArgs)->get_Error(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::WebAccount) consume_Windows_System_RemoteSystems_IRemoteSystemWebAccountFilter<D>::Account() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWebAccountFilter)->get_Account(&value));
        return winrt::Windows::Security::Credentials::WebAccount{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteSystems::RemoteSystemWebAccountFilter) consume_Windows_System_RemoteSystems_IRemoteSystemWebAccountFilterFactory<D>::Create(winrt::Windows::Security::Credentials::WebAccount const& account) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteSystems::IRemoteSystemWebAccountFilterFactory)->Create(*(void**)(&account), &value));
        return winrt::Windows::System::RemoteSystems::RemoteSystemWebAccountFilter{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics> : produce_base<D, winrt::Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics>
    {
        int32_t __stdcall get_AppService(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppService());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LaunchUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LaunchUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteSession(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemoteSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpatialEntity(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SpatialEntity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystem> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystem>
    {
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
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
        int32_t __stdcall get_Kind(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAvailableByProximity(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAvailableByProximity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystem2> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystem2>
    {
        int32_t __stdcall get_IsAvailableBySpatialProximity(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAvailableBySpatialProximity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCapabilitySupportedAsync(void* capabilityName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetCapabilitySupportedAsync(*reinterpret_cast<hstring const*>(&capabilityName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystem3> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystem3>
    {
        int32_t __stdcall get_ManufacturerDisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ManufacturerDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ModelDisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ModelDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystem4> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystem4>
    {
        int32_t __stdcall get_Platform(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemPlatform>(this->shim().Platform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystem5> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystem5>
    {
        int32_t __stdcall get_Apps(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::RemoteSystems::RemoteSystemApp>>(this->shim().Apps());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystem6> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystem6>
    {
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
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemAddedEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemAddedEventArgs>
    {
        int32_t __stdcall get_RemoteSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystem>(this->shim().RemoteSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemApp> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemApp>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
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
        int32_t __stdcall get_IsAvailableByProximity(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAvailableByProximity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAvailableBySpatialProximity(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAvailableBySpatialProximity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Attributes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>>(this->shim().Attributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemApp2> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemApp2>
    {
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConnectionToken(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ConnectionToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistration> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistration>
    {
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Attributes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Attributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SaveAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().SaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistrationStatics> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistrationStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemAppRegistration>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemAppRegistration>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilter> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilter>
    {
        int32_t __stdcall get_RemoteSystemAuthorizationKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKind>(this->shim().RemoteSystemAuthorizationKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilterFactory> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilterFactory>
    {
        int32_t __stdcall Create(int32_t remoteSystemAuthorizationKind, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKindFilter>(this->shim().Create(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const*>(&remoteSystemAuthorizationKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionInfo> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionInfo>
    {
        int32_t __stdcall get_IsProximal(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsProximal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionInfoStatics> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionInfoStatics>
    {
        int32_t __stdcall TryCreateFromAppServiceConnection(void* connection, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionInfo>(this->shim().TryCreateFromAppServiceConnection(*reinterpret_cast<winrt::Windows::ApplicationModel::AppService::AppServiceConnection const*>(&connection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest>
    {
        int32_t __stdcall get_RemoteSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystem>(this->shim().RemoteSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest2> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest2>
    {
        int32_t __stdcall get_RemoteSystemApp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemApp>(this->shim().RemoteSystemApp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest3> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest3>
    {
        int32_t __stdcall get_ConnectionToken(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ConnectionToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestFactory> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestFactory>
    {
        int32_t __stdcall Create(void* remoteSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest>(this->shim().Create(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystem const*>(&remoteSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics>
    {
        int32_t __stdcall CreateForApp(void* remoteSystemApp, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest>(this->shim().CreateForApp(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemApp const*>(&remoteSystemApp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics2> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics2>
    {
        int32_t __stdcall CreateFromConnectionToken(void* connectionToken, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest>(this->shim().CreateFromConnectionToken(*reinterpret_cast<hstring const*>(&connectionToken)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromConnectionTokenForUser(void* user, void* connectionToken, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest>(this->shim().CreateFromConnectionTokenForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&connectionToken)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilter> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilter>
    {
        int32_t __stdcall get_RemoteSystemDiscoveryType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemDiscoveryType>(this->shim().RemoteSystemDiscoveryType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilterFactory> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilterFactory>
    {
        int32_t __stdcall Create(int32_t discoveryType, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemDiscoveryTypeFilter>(this->shim().Create(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemDiscoveryType const*>(&discoveryType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemEnumerationCompletedEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemEnumerationCompletedEventArgs>
    {
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemFilter> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemFilter>
    {
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemKindFilter> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemKindFilter>
    {
        int32_t __stdcall get_RemoteSystemKinds(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().RemoteSystemKinds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemKindFilterFactory> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemKindFilterFactory>
    {
        int32_t __stdcall Create(void* remoteSystemKinds, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemKindFilter>(this->shim().Create(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&remoteSystemKinds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics>
    {
        int32_t __stdcall get_Phone(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Phone());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Hub(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Hub());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Holographic(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Holographic());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Desktop(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Desktop());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Xbox(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Xbox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics2> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics2>
    {
        int32_t __stdcall get_Iot(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Iot());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tablet(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Tablet());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Laptop(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Laptop());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemRemovedEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemRemovedEventArgs>
    {
        int32_t __stdcall get_RemoteSystemId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemoteSystemId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSession> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSession>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
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
        int32_t __stdcall get_ControllerDisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ControllerDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Disconnected(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Disconnected(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSession, winrt::Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Disconnected(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Disconnected(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall CreateParticipantWatcher(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher>(this->shim().CreateParticipantWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendInvitationAsync(void* invitee, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().SendInvitationAsync(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystem const*>(&invitee)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionAddedEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionAddedEventArgs>
    {
        int32_t __stdcall get_SessionInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionController> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionController>
    {
        int32_t __stdcall add_JoinRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().JoinRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionController, winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_JoinRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().JoinRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall RemoveParticipantAsync(void* pParticipant, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RemoveParticipantAsync(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant const*>(&pParticipant)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateSessionAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteSystems::RemoteSystemSessionCreationResult>>(this->shim().CreateSessionAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionControllerFactory> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionControllerFactory>
    {
        int32_t __stdcall CreateController(void* displayName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionController>(this->shim().CreateController(*reinterpret_cast<hstring const*>(&displayName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateControllerWithSessionOptions(void* displayName, void* options, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionController>(this->shim().CreateController(*reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemSessionOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionCreationResult> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionCreationResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionCreationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Session(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionDisconnectedEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionDisconnectedEventArgs>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInfo> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInfo>
    {
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ControllerDisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ControllerDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall JoinAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinResult>>(this->shim().JoinAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitation> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitation>
    {
        int32_t __stdcall get_Sender(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystem>(this->shim().Sender());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SessionInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitationListener> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitationListener>
    {
        int32_t __stdcall add_InvitationReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().InvitationReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitationListener, winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitationReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_InvitationReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InvitationReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitationReceivedEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitationReceivedEventArgs>
    {
        int32_t __stdcall get_Invitation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitation>(this->shim().Invitation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequest> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequest>
    {
        int32_t __stdcall get_Participant(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant>(this->shim().Participant());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Accept() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Accept();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequestedEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequestedEventArgs>
    {
        int32_t __stdcall get_JoinRequest(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinRequest>(this->shim().JoinRequest());
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
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinResult> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Session(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel>
    {
        int32_t __stdcall get_Session(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall BroadcastValueSetAsync(void* messageData, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().BroadcastValueSetAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&messageData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendValueSetAsync(void* messageData, void* participant, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().SendValueSetAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&messageData), *reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant const*>(&participant)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendValueSetToParticipantsAsync(void* messageData, void* participants, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().SendValueSetToParticipantsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&messageData), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant> const*>(&participants)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ValueSetReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ValueSetReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel, winrt::Windows::System::RemoteSystems::RemoteSystemSessionValueSetReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ValueSetReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ValueSetReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannelFactory> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannelFactory>
    {
        int32_t __stdcall Create(void* session, void* channelName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel>(this->shim().Create(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemSession const*>(&session), *reinterpret_cast<hstring const*>(&channelName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithReliability(void* session, void* channelName, int32_t reliability, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel>(this->shim().Create(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemSession const*>(&session), *reinterpret_cast<hstring const*>(&channelName), *reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannelReliability const*>(&reliability)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionOptions> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionOptions>
    {
        int32_t __stdcall get_IsInviteOnly(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInviteOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsInviteOnly(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsInviteOnly(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipant> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipant>
    {
        int32_t __stdcall get_RemoteSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystem>(this->shim().RemoteSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetHostNames(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::HostName>>(this->shim().GetHostNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantAddedEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantAddedEventArgs>
    {
        int32_t __stdcall get_Participant(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant>(this->shim().Participant());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantRemovedEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantRemovedEventArgs>
    {
        int32_t __stdcall get_Participant(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant>(this->shim().Participant());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher>
    {
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
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Added(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantAddedEventArgs> const*>(&handler)));
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
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Removed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EnumerationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionRemovedEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionRemovedEventArgs>
    {
        int32_t __stdcall get_SessionInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionStatics> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionStatics>
    {
        int32_t __stdcall CreateWatcher(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionUpdatedEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionUpdatedEventArgs>
    {
        int32_t __stdcall get_SessionInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionValueSetReceivedEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionValueSetReceivedEventArgs>
    {
        int32_t __stdcall get_Sender(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant>(this->shim().Sender());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher>
    {
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
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Added(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionAddedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Added(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Updated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Updated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Removed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemSessionRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Removed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemStatics> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemStatics>
    {
        int32_t __stdcall FindByHostNameAsync(void* hostName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteSystems::RemoteSystem>>(this->shim().FindByHostNameAsync(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&hostName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWatcher(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWatcherWithFilters(void* filters, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher>(this->shim().CreateWatcher(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::System::RemoteSystems::IRemoteSystemFilter> const*>(&filters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAccessAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteSystems::RemoteSystemAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemStatics2> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemStatics2>
    {
        int32_t __stdcall IsAuthorizationKindEnabled(int32_t kind, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsAuthorizationKindEnabled(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemStatics3> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemStatics3>
    {
        int32_t __stdcall CreateWatcherForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher>(this->shim().CreateWatcherForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWatcherWithFiltersForUser(void* user, void* filters, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher>(this->shim().CreateWatcherForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::System::RemoteSystems::IRemoteSystemFilter> const*>(&filters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilter> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilter>
    {
        int32_t __stdcall get_RemoteSystemStatusType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemStatusType>(this->shim().RemoteSystemStatusType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilterFactory> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilterFactory>
    {
        int32_t __stdcall Create(int32_t remoteSystemStatusType, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemStatusTypeFilter>(this->shim().Create(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemStatusType const*>(&remoteSystemStatusType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemUpdatedEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemUpdatedEventArgs>
    {
        int32_t __stdcall get_RemoteSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystem>(this->shim().RemoteSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher>
    {
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
        int32_t __stdcall add_RemoteSystemAdded(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RemoteSystemAdded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemAddedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RemoteSystemAdded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoteSystemAdded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RemoteSystemUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RemoteSystemUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RemoteSystemUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoteSystemUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RemoteSystemRemoved(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RemoteSystemRemoved(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RemoteSystemRemoved(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoteSystemRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher2> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher2>
    {
        int32_t __stdcall add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemEnumerationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EnumerationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ErrorOccurred(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ErrorOccurred(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher, winrt::Windows::System::RemoteSystems::RemoteSystemWatcherErrorOccurredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ErrorOccurred(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ErrorOccurred(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher3> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher3>
    {
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
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemWatcherErrorOccurredEventArgs> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemWatcherErrorOccurredEventArgs>
    {
        int32_t __stdcall get_Error(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemWatcherError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemWebAccountFilter> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemWebAccountFilter>
    {
        int32_t __stdcall get_Account(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::WebAccount>(this->shim().Account());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteSystems::IRemoteSystemWebAccountFilterFactory> : produce_base<D, winrt::Windows::System::RemoteSystems::IRemoteSystemWebAccountFilterFactory>
    {
        int32_t __stdcall Create(void* account, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteSystems::RemoteSystemWebAccountFilter>(this->shim().Create(*reinterpret_cast<winrt::Windows::Security::Credentials::WebAccount const*>(&account)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::RemoteSystems
{
    inline auto KnownRemoteSystemCapabilities::AppService()
    {
        return impl::call_factory_cast<hstring(*)(IKnownRemoteSystemCapabilitiesStatics const&), KnownRemoteSystemCapabilities, IKnownRemoteSystemCapabilitiesStatics>([](IKnownRemoteSystemCapabilitiesStatics const& f) { return f.AppService(); });
    }
    inline auto KnownRemoteSystemCapabilities::LaunchUri()
    {
        return impl::call_factory_cast<hstring(*)(IKnownRemoteSystemCapabilitiesStatics const&), KnownRemoteSystemCapabilities, IKnownRemoteSystemCapabilitiesStatics>([](IKnownRemoteSystemCapabilitiesStatics const& f) { return f.LaunchUri(); });
    }
    inline auto KnownRemoteSystemCapabilities::RemoteSession()
    {
        return impl::call_factory_cast<hstring(*)(IKnownRemoteSystemCapabilitiesStatics const&), KnownRemoteSystemCapabilities, IKnownRemoteSystemCapabilitiesStatics>([](IKnownRemoteSystemCapabilitiesStatics const& f) { return f.RemoteSession(); });
    }
    inline auto KnownRemoteSystemCapabilities::SpatialEntity()
    {
        return impl::call_factory_cast<hstring(*)(IKnownRemoteSystemCapabilitiesStatics const&), KnownRemoteSystemCapabilities, IKnownRemoteSystemCapabilitiesStatics>([](IKnownRemoteSystemCapabilitiesStatics const& f) { return f.SpatialEntity(); });
    }
    inline auto RemoteSystem::FindByHostNameAsync(winrt::Windows::Networking::HostName const& hostName)
    {
        return impl::call_factory<RemoteSystem, IRemoteSystemStatics>([&](IRemoteSystemStatics const& f) { return f.FindByHostNameAsync(hostName); });
    }
    inline auto RemoteSystem::CreateWatcher()
    {
        return impl::call_factory_cast<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher(*)(IRemoteSystemStatics const&), RemoteSystem, IRemoteSystemStatics>([](IRemoteSystemStatics const& f) { return f.CreateWatcher(); });
    }
    inline auto RemoteSystem::CreateWatcher(param::iterable<winrt::Windows::System::RemoteSystems::IRemoteSystemFilter> const& filters)
    {
        return impl::call_factory<RemoteSystem, IRemoteSystemStatics>([&](IRemoteSystemStatics const& f) { return f.CreateWatcher(filters); });
    }
    inline auto RemoteSystem::RequestAccessAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::RemoteSystems::RemoteSystemAccessStatus>(*)(IRemoteSystemStatics const&), RemoteSystem, IRemoteSystemStatics>([](IRemoteSystemStatics const& f) { return f.RequestAccessAsync(); });
    }
    inline auto RemoteSystem::IsAuthorizationKindEnabled(winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const& kind)
    {
        return impl::call_factory<RemoteSystem, IRemoteSystemStatics2>([&](IRemoteSystemStatics2 const& f) { return f.IsAuthorizationKindEnabled(kind); });
    }
    inline auto RemoteSystem::CreateWatcherForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<RemoteSystem, IRemoteSystemStatics3>([&](IRemoteSystemStatics3 const& f) { return f.CreateWatcherForUser(user); });
    }
    inline auto RemoteSystem::CreateWatcherForUser(winrt::Windows::System::User const& user, param::iterable<winrt::Windows::System::RemoteSystems::IRemoteSystemFilter> const& filters)
    {
        return impl::call_factory<RemoteSystem, IRemoteSystemStatics3>([&](IRemoteSystemStatics3 const& f) { return f.CreateWatcherForUser(user, filters); });
    }
    inline auto RemoteSystemAppRegistration::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::System::RemoteSystems::RemoteSystemAppRegistration(*)(IRemoteSystemAppRegistrationStatics const&), RemoteSystemAppRegistration, IRemoteSystemAppRegistrationStatics>([](IRemoteSystemAppRegistrationStatics const& f) { return f.GetDefault(); });
    }
    inline auto RemoteSystemAppRegistration::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<RemoteSystemAppRegistration, IRemoteSystemAppRegistrationStatics>([&](IRemoteSystemAppRegistrationStatics const& f) { return f.GetForUser(user); });
    }
    inline RemoteSystemAuthorizationKindFilter::RemoteSystemAuthorizationKindFilter(winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const& remoteSystemAuthorizationKind) :
        RemoteSystemAuthorizationKindFilter(impl::call_factory<RemoteSystemAuthorizationKindFilter, IRemoteSystemAuthorizationKindFilterFactory>([&](IRemoteSystemAuthorizationKindFilterFactory const& f) { return f.Create(remoteSystemAuthorizationKind); }))
    {
    }
    inline auto RemoteSystemConnectionInfo::TryCreateFromAppServiceConnection(winrt::Windows::ApplicationModel::AppService::AppServiceConnection const& connection)
    {
        return impl::call_factory<RemoteSystemConnectionInfo, IRemoteSystemConnectionInfoStatics>([&](IRemoteSystemConnectionInfoStatics const& f) { return f.TryCreateFromAppServiceConnection(connection); });
    }
    inline RemoteSystemConnectionRequest::RemoteSystemConnectionRequest(winrt::Windows::System::RemoteSystems::RemoteSystem const& remoteSystem) :
        RemoteSystemConnectionRequest(impl::call_factory<RemoteSystemConnectionRequest, IRemoteSystemConnectionRequestFactory>([&](IRemoteSystemConnectionRequestFactory const& f) { return f.Create(remoteSystem); }))
    {
    }
    inline auto RemoteSystemConnectionRequest::CreateForApp(winrt::Windows::System::RemoteSystems::RemoteSystemApp const& remoteSystemApp)
    {
        return impl::call_factory<RemoteSystemConnectionRequest, IRemoteSystemConnectionRequestStatics>([&](IRemoteSystemConnectionRequestStatics const& f) { return f.CreateForApp(remoteSystemApp); });
    }
    inline auto RemoteSystemConnectionRequest::CreateFromConnectionToken(param::hstring const& connectionToken)
    {
        return impl::call_factory<RemoteSystemConnectionRequest, IRemoteSystemConnectionRequestStatics2>([&](IRemoteSystemConnectionRequestStatics2 const& f) { return f.CreateFromConnectionToken(connectionToken); });
    }
    inline auto RemoteSystemConnectionRequest::CreateFromConnectionTokenForUser(winrt::Windows::System::User const& user, param::hstring const& connectionToken)
    {
        return impl::call_factory<RemoteSystemConnectionRequest, IRemoteSystemConnectionRequestStatics2>([&](IRemoteSystemConnectionRequestStatics2 const& f) { return f.CreateFromConnectionTokenForUser(user, connectionToken); });
    }
    inline RemoteSystemDiscoveryTypeFilter::RemoteSystemDiscoveryTypeFilter(winrt::Windows::System::RemoteSystems::RemoteSystemDiscoveryType const& discoveryType) :
        RemoteSystemDiscoveryTypeFilter(impl::call_factory<RemoteSystemDiscoveryTypeFilter, IRemoteSystemDiscoveryTypeFilterFactory>([&](IRemoteSystemDiscoveryTypeFilterFactory const& f) { return f.Create(discoveryType); }))
    {
    }
    inline RemoteSystemKindFilter::RemoteSystemKindFilter(param::iterable<hstring> const& remoteSystemKinds) :
        RemoteSystemKindFilter(impl::call_factory<RemoteSystemKindFilter, IRemoteSystemKindFilterFactory>([&](IRemoteSystemKindFilterFactory const& f) { return f.Create(remoteSystemKinds); }))
    {
    }
    inline auto RemoteSystemKinds::Phone()
    {
        return impl::call_factory_cast<hstring(*)(IRemoteSystemKindStatics const&), RemoteSystemKinds, IRemoteSystemKindStatics>([](IRemoteSystemKindStatics const& f) { return f.Phone(); });
    }
    inline auto RemoteSystemKinds::Hub()
    {
        return impl::call_factory_cast<hstring(*)(IRemoteSystemKindStatics const&), RemoteSystemKinds, IRemoteSystemKindStatics>([](IRemoteSystemKindStatics const& f) { return f.Hub(); });
    }
    inline auto RemoteSystemKinds::Holographic()
    {
        return impl::call_factory_cast<hstring(*)(IRemoteSystemKindStatics const&), RemoteSystemKinds, IRemoteSystemKindStatics>([](IRemoteSystemKindStatics const& f) { return f.Holographic(); });
    }
    inline auto RemoteSystemKinds::Desktop()
    {
        return impl::call_factory_cast<hstring(*)(IRemoteSystemKindStatics const&), RemoteSystemKinds, IRemoteSystemKindStatics>([](IRemoteSystemKindStatics const& f) { return f.Desktop(); });
    }
    inline auto RemoteSystemKinds::Xbox()
    {
        return impl::call_factory_cast<hstring(*)(IRemoteSystemKindStatics const&), RemoteSystemKinds, IRemoteSystemKindStatics>([](IRemoteSystemKindStatics const& f) { return f.Xbox(); });
    }
    inline auto RemoteSystemKinds::Iot()
    {
        return impl::call_factory_cast<hstring(*)(IRemoteSystemKindStatics2 const&), RemoteSystemKinds, IRemoteSystemKindStatics2>([](IRemoteSystemKindStatics2 const& f) { return f.Iot(); });
    }
    inline auto RemoteSystemKinds::Tablet()
    {
        return impl::call_factory_cast<hstring(*)(IRemoteSystemKindStatics2 const&), RemoteSystemKinds, IRemoteSystemKindStatics2>([](IRemoteSystemKindStatics2 const& f) { return f.Tablet(); });
    }
    inline auto RemoteSystemKinds::Laptop()
    {
        return impl::call_factory_cast<hstring(*)(IRemoteSystemKindStatics2 const&), RemoteSystemKinds, IRemoteSystemKindStatics2>([](IRemoteSystemKindStatics2 const& f) { return f.Laptop(); });
    }
    inline auto RemoteSystemSession::CreateWatcher()
    {
        return impl::call_factory_cast<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher(*)(IRemoteSystemSessionStatics const&), RemoteSystemSession, IRemoteSystemSessionStatics>([](IRemoteSystemSessionStatics const& f) { return f.CreateWatcher(); });
    }
    inline RemoteSystemSessionController::RemoteSystemSessionController(param::hstring const& displayName) :
        RemoteSystemSessionController(impl::call_factory<RemoteSystemSessionController, IRemoteSystemSessionControllerFactory>([&](IRemoteSystemSessionControllerFactory const& f) { return f.CreateController(displayName); }))
    {
    }
    inline RemoteSystemSessionController::RemoteSystemSessionController(param::hstring const& displayName, winrt::Windows::System::RemoteSystems::RemoteSystemSessionOptions const& options) :
        RemoteSystemSessionController(impl::call_factory<RemoteSystemSessionController, IRemoteSystemSessionControllerFactory>([&](IRemoteSystemSessionControllerFactory const& f) { return f.CreateController(displayName, options); }))
    {
    }
    inline RemoteSystemSessionInvitationListener::RemoteSystemSessionInvitationListener() :
        RemoteSystemSessionInvitationListener(impl::call_factory_cast<RemoteSystemSessionInvitationListener(*)(winrt::Windows::Foundation::IActivationFactory const&), RemoteSystemSessionInvitationListener>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<RemoteSystemSessionInvitationListener>(); }))
    {
    }
    inline RemoteSystemSessionMessageChannel::RemoteSystemSessionMessageChannel(winrt::Windows::System::RemoteSystems::RemoteSystemSession const& session, param::hstring const& channelName) :
        RemoteSystemSessionMessageChannel(impl::call_factory<RemoteSystemSessionMessageChannel, IRemoteSystemSessionMessageChannelFactory>([&](IRemoteSystemSessionMessageChannelFactory const& f) { return f.Create(session, channelName); }))
    {
    }
    inline RemoteSystemSessionMessageChannel::RemoteSystemSessionMessageChannel(winrt::Windows::System::RemoteSystems::RemoteSystemSession const& session, param::hstring const& channelName, winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannelReliability const& reliability) :
        RemoteSystemSessionMessageChannel(impl::call_factory<RemoteSystemSessionMessageChannel, IRemoteSystemSessionMessageChannelFactory>([&](IRemoteSystemSessionMessageChannelFactory const& f) { return f.Create(session, channelName, reliability); }))
    {
    }
    inline RemoteSystemSessionOptions::RemoteSystemSessionOptions() :
        RemoteSystemSessionOptions(impl::call_factory_cast<RemoteSystemSessionOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), RemoteSystemSessionOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<RemoteSystemSessionOptions>(); }))
    {
    }
    inline RemoteSystemStatusTypeFilter::RemoteSystemStatusTypeFilter(winrt::Windows::System::RemoteSystems::RemoteSystemStatusType const& remoteSystemStatusType) :
        RemoteSystemStatusTypeFilter(impl::call_factory<RemoteSystemStatusTypeFilter, IRemoteSystemStatusTypeFilterFactory>([&](IRemoteSystemStatusTypeFilterFactory const& f) { return f.Create(remoteSystemStatusType); }))
    {
    }
    inline RemoteSystemWebAccountFilter::RemoteSystemWebAccountFilter(winrt::Windows::Security::Credentials::WebAccount const& account) :
        RemoteSystemWebAccountFilter(impl::call_factory<RemoteSystemWebAccountFilter, IRemoteSystemWebAccountFilterFactory>([&](IRemoteSystemWebAccountFilterFactory const& f) { return f.Create(account); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystem2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystem3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystem4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystem5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystem6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemApp> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemApp2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistrationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionInfoStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemEnumerationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemKindFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemKindFilterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionControllerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionCreationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionDisconnectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitationListener> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitationReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannelFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipant> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionValueSetReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemWatcherErrorOccurredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemWebAccountFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemWebAccountFilterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::KnownRemoteSystemCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemApp> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemAppRegistration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKindFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemDiscoveryTypeFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemEnumerationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemKindFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemKinds> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionCreationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitationListener> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitationReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionValueSetReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemStatusTypeFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemWatcherErrorOccurredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemWebAccountFilter> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
