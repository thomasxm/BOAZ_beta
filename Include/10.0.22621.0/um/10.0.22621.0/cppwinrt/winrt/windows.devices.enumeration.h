// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Enumeration_H
#define WINRT_Windows_Devices_Enumeration_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.ApplicationModel.Background.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceAccessStatus) consume_Windows_Devices_Enumeration_IDeviceAccessChangedEventArgs<D>::Status() const
    {
        winrt::Windows::Devices::Enumeration::DeviceAccessStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Enumeration_IDeviceAccessChangedEventArgs2<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_IDeviceAccessInformation<D>::AccessChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceAccessInformation, winrt::Windows::Devices::Enumeration::DeviceAccessChangedEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceAccessInformation)->add_AccessChanged(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceAccessInformation<D>::AccessChanged_revoker consume_Windows_Devices_Enumeration_IDeviceAccessInformation<D>::AccessChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceAccessInformation, winrt::Windows::Devices::Enumeration::DeviceAccessChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AccessChanged_revoker>(this, AccessChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDeviceAccessInformation<D>::AccessChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceAccessInformation)->remove_AccessChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceAccessStatus) consume_Windows_Devices_Enumeration_IDeviceAccessInformation<D>::CurrentStatus() const
    {
        winrt::Windows::Devices::Enumeration::DeviceAccessStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceAccessInformation)->get_CurrentStatus(reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceAccessInformation) consume_Windows_Devices_Enumeration_IDeviceAccessInformationStatics<D>::CreateFromId(param::hstring const& deviceId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceAccessInformationStatics)->CreateFromId(*(void**)(&deviceId), &value));
        return winrt::Windows::Devices::Enumeration::DeviceAccessInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceAccessInformation) consume_Windows_Devices_Enumeration_IDeviceAccessInformationStatics<D>::CreateFromDeviceClassId(winrt::guid const& deviceClassId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceAccessInformationStatics)->CreateFromDeviceClassId(impl::bind_in(deviceClassId), &value));
        return winrt::Windows::Devices::Enumeration::DeviceAccessInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceAccessInformation) consume_Windows_Devices_Enumeration_IDeviceAccessInformationStatics<D>::CreateFromDeviceClass(winrt::Windows::Devices::Enumeration::DeviceClass const& deviceClass) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceAccessInformationStatics)->CreateFromDeviceClass(static_cast<int32_t>(deviceClass), &value));
        return winrt::Windows::Devices::Enumeration::DeviceAccessInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Enumeration_IDeviceConnectionChangeTriggerDetails<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Devices_Enumeration_IDeviceDisconnectButtonClickedEventArgs<D>::Device() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs)->get_Device(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Enumeration_IDeviceInformation<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformation)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Enumeration_IDeviceInformation<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformation)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Enumeration_IDeviceInformation<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformation)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Enumeration_IDeviceInformation<D>::IsDefault() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformation)->get_IsDefault(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::EnclosureLocation) consume_Windows_Devices_Enumeration_IDeviceInformation<D>::EnclosureLocation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformation)->get_EnclosureLocation(&value));
        return winrt::Windows::Devices::Enumeration::EnclosureLocation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Enumeration_IDeviceInformation<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformation)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDeviceInformation<D>::Update(winrt::Windows::Devices::Enumeration::DeviceInformationUpdate const& updateInfo) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformation)->Update(*(void**)(&updateInfo)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceThumbnail>) consume_Windows_Devices_Enumeration_IDeviceInformation<D>::GetThumbnailAsync() const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformation)->GetThumbnailAsync(&asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceThumbnail>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceThumbnail>) consume_Windows_Devices_Enumeration_IDeviceInformation<D>::GetGlyphThumbnailAsync() const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformation)->GetGlyphThumbnailAsync(&asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceThumbnail>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformationKind) consume_Windows_Devices_Enumeration_IDeviceInformation2<D>::Kind() const
    {
        winrt::Windows::Devices::Enumeration::DeviceInformationKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformation2)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformationPairing) consume_Windows_Devices_Enumeration_IDeviceInformation2<D>::Pairing() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformation2)->get_Pairing(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformationPairing{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>) consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairAsync(winrt::Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationCustomPairing)->PairAsync(static_cast<uint32_t>(pairingKindsSupported), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>) consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairAsync(winrt::Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported, winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationCustomPairing)->PairWithProtectionLevelAsync(static_cast<uint32_t>(pairingKindsSupported), static_cast<int32_t>(minProtectionLevel), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>) consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairAsync(winrt::Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported, winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel, winrt::Windows::Devices::Enumeration::IDevicePairingSettings const& devicePairingSettings) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationCustomPairing)->PairWithProtectionLevelAndSettingsAsync(static_cast<uint32_t>(pairingKindsSupported), static_cast<int32_t>(minProtectionLevel), *(void**)(&devicePairingSettings), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairingRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceInformationCustomPairing, winrt::Windows::Devices::Enumeration::DevicePairingRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationCustomPairing)->add_PairingRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairingRequested_revoker consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairingRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceInformationCustomPairing, winrt::Windows::Devices::Enumeration::DevicePairingRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PairingRequested_revoker>(this, PairingRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairingRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationCustomPairing)->remove_PairingRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Enumeration_IDeviceInformationPairing<D>::IsPaired() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationPairing)->get_IsPaired(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Enumeration_IDeviceInformationPairing<D>::CanPair() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationPairing)->get_CanPair(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>) consume_Windows_Devices_Enumeration_IDeviceInformationPairing<D>::PairAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationPairing)->PairAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>) consume_Windows_Devices_Enumeration_IDeviceInformationPairing<D>::PairAsync(winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationPairing)->PairWithProtectionLevelAsync(static_cast<int32_t>(minProtectionLevel), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel) consume_Windows_Devices_Enumeration_IDeviceInformationPairing2<D>::ProtectionLevel() const
    {
        winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationPairing2)->get_ProtectionLevel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformationCustomPairing) consume_Windows_Devices_Enumeration_IDeviceInformationPairing2<D>::Custom() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationPairing2)->get_Custom(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformationCustomPairing{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>) consume_Windows_Devices_Enumeration_IDeviceInformationPairing2<D>::PairAsync(winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel, winrt::Windows::Devices::Enumeration::IDevicePairingSettings const& devicePairingSettings) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationPairing2)->PairWithProtectionLevelAndSettingsAsync(static_cast<int32_t>(minProtectionLevel), *(void**)(&devicePairingSettings), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceUnpairingResult>) consume_Windows_Devices_Enumeration_IDeviceInformationPairing2<D>::UnpairAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationPairing2)->UnpairAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceUnpairingResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Enumeration_IDeviceInformationPairingStatics<D>::TryRegisterForAllInboundPairingRequests(winrt::Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationPairingStatics)->TryRegisterForAllInboundPairingRequests(static_cast<uint32_t>(pairingKindsSupported), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Enumeration_IDeviceInformationPairingStatics2<D>::TryRegisterForAllInboundPairingRequestsWithProtectionLevel(winrt::Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported, winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationPairingStatics2)->TryRegisterForAllInboundPairingRequestsWithProtectionLevel(static_cast<uint32_t>(pairingKindsSupported), static_cast<int32_t>(minProtectionLevel), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>) consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::CreateFromIdAsync(param::hstring const& deviceId) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics)->CreateFromIdAsync(*(void**)(&deviceId), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>) consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::CreateFromIdAsync(param::hstring const& deviceId, param::async_iterable<hstring> const& additionalProperties) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics)->CreateFromIdAsyncAdditionalProperties(*(void**)(&deviceId), *(void**)(&additionalProperties), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>) consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::FindAllAsync() const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics)->FindAllAsync(&asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>) consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::FindAllAsync(winrt::Windows::Devices::Enumeration::DeviceClass const& deviceClass) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics)->FindAllAsyncDeviceClass(static_cast<int32_t>(deviceClass), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>) consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::FindAllAsync(param::hstring const& aqsFilter) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics)->FindAllAsyncAqsFilter(*(void**)(&aqsFilter), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>) consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::FindAllAsync(param::hstring const& aqsFilter, param::async_iterable<hstring> const& additionalProperties) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics)->FindAllAsyncAqsFilterAndAdditionalProperties(*(void**)(&aqsFilter), *(void**)(&additionalProperties), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceWatcher) consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::CreateWatcher() const
    {
        void* watcher{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics)->CreateWatcher(&watcher));
        return winrt::Windows::Devices::Enumeration::DeviceWatcher{ watcher, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceWatcher) consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::CreateWatcher(winrt::Windows::Devices::Enumeration::DeviceClass const& deviceClass) const
    {
        void* watcher{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics)->CreateWatcherDeviceClass(static_cast<int32_t>(deviceClass), &watcher));
        return winrt::Windows::Devices::Enumeration::DeviceWatcher{ watcher, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceWatcher) consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::CreateWatcher(param::hstring const& aqsFilter) const
    {
        void* watcher{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics)->CreateWatcherAqsFilter(*(void**)(&aqsFilter), &watcher));
        return winrt::Windows::Devices::Enumeration::DeviceWatcher{ watcher, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceWatcher) consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::CreateWatcher(param::hstring const& aqsFilter, param::iterable<hstring> const& additionalProperties) const
    {
        void* watcher{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics)->CreateWatcherAqsFilterAndAdditionalProperties(*(void**)(&aqsFilter), *(void**)(&additionalProperties), &watcher));
        return winrt::Windows::Devices::Enumeration::DeviceWatcher{ watcher, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Enumeration_IDeviceInformationStatics2<D>::GetAqsFilterFromDeviceClass(winrt::Windows::Devices::Enumeration::DeviceClass const& deviceClass) const
    {
        void* aqsFilter{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics2)->GetAqsFilterFromDeviceClass(static_cast<int32_t>(deviceClass), &aqsFilter));
        return hstring{ aqsFilter, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>) consume_Windows_Devices_Enumeration_IDeviceInformationStatics2<D>::CreateFromIdAsync(param::hstring const& deviceId, param::async_iterable<hstring> const& additionalProperties, winrt::Windows::Devices::Enumeration::DeviceInformationKind const& kind) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics2)->CreateFromIdAsyncWithKindAndAdditionalProperties(*(void**)(&deviceId), *(void**)(&additionalProperties), static_cast<int32_t>(kind), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>) consume_Windows_Devices_Enumeration_IDeviceInformationStatics2<D>::FindAllAsync(param::hstring const& aqsFilter, param::async_iterable<hstring> const& additionalProperties, winrt::Windows::Devices::Enumeration::DeviceInformationKind const& kind) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics2)->FindAllAsyncWithKindAqsFilterAndAdditionalProperties(*(void**)(&aqsFilter), *(void**)(&additionalProperties), static_cast<int32_t>(kind), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceWatcher) consume_Windows_Devices_Enumeration_IDeviceInformationStatics2<D>::CreateWatcher(param::hstring const& aqsFilter, param::iterable<hstring> const& additionalProperties, winrt::Windows::Devices::Enumeration::DeviceInformationKind const& kind) const
    {
        void* watcher{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationStatics2)->CreateWatcherWithKindAqsFilterAndAdditionalProperties(*(void**)(&aqsFilter), *(void**)(&additionalProperties), static_cast<int32_t>(kind), &watcher));
        return winrt::Windows::Devices::Enumeration::DeviceWatcher{ watcher, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Enumeration_IDeviceInformationUpdate<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationUpdate)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Enumeration_IDeviceInformationUpdate<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationUpdate)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformationKind) consume_Windows_Devices_Enumeration_IDeviceInformationUpdate2<D>::Kind() const
    {
        winrt::Windows::Devices::Enumeration::DeviceInformationKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceInformationUpdate2)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs<D>::DeviceInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs)->get_DeviceInformation(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DevicePairingKinds) consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs<D>::PairingKind() const
    {
        winrt::Windows::Devices::Enumeration::DevicePairingKinds value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs)->get_PairingKind(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs<D>::Pin() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs)->get_Pin(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs<D>::Accept() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs)->Accept());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs<D>::Accept(param::hstring const& pin) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs)->AcceptWithPin(*(void**)(&pin)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs2<D>::AcceptWithPasswordCredential(winrt::Windows::Security::Credentials::PasswordCredential const& passwordCredential) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2)->AcceptWithPasswordCredential(*(void**)(&passwordCredential)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DevicePairingResultStatus) consume_Windows_Devices_Enumeration_IDevicePairingResult<D>::Status() const
    {
        winrt::Windows::Devices::Enumeration::DevicePairingResultStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePairingResult)->get_Status(reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel) consume_Windows_Devices_Enumeration_IDevicePairingResult<D>::ProtectionLevelUsed() const
    {
        winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePairingResult)->get_ProtectionLevelUsed(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DevicePickerFilter) consume_Windows_Devices_Enumeration_IDevicePicker<D>::Filter() const
    {
        void* filter{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->get_Filter(&filter));
        return winrt::Windows::Devices::Enumeration::DevicePickerFilter{ filter, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DevicePickerAppearance) consume_Windows_Devices_Enumeration_IDevicePicker<D>::Appearance() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->get_Appearance(&value));
        return winrt::Windows::Devices::Enumeration::DevicePickerAppearance{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Devices_Enumeration_IDevicePicker<D>::RequestedProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->get_RequestedProperties(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_IDevicePicker<D>::DeviceSelected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DevicePicker, winrt::Windows::Devices::Enumeration::DeviceSelectedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->add_DeviceSelected(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_IDevicePicker<D>::DeviceSelected_revoker consume_Windows_Devices_Enumeration_IDevicePicker<D>::DeviceSelected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DevicePicker, winrt::Windows::Devices::Enumeration::DeviceSelectedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DeviceSelected_revoker>(this, DeviceSelected(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePicker<D>::DeviceSelected(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->remove_DeviceSelected(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_IDevicePicker<D>::DisconnectButtonClicked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DevicePicker, winrt::Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->add_DisconnectButtonClicked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_IDevicePicker<D>::DisconnectButtonClicked_revoker consume_Windows_Devices_Enumeration_IDevicePicker<D>::DisconnectButtonClicked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DevicePicker, winrt::Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DisconnectButtonClicked_revoker>(this, DisconnectButtonClicked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePicker<D>::DisconnectButtonClicked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->remove_DisconnectButtonClicked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_IDevicePicker<D>::DevicePickerDismissed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DevicePicker, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->add_DevicePickerDismissed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_IDevicePicker<D>::DevicePickerDismissed_revoker consume_Windows_Devices_Enumeration_IDevicePicker<D>::DevicePickerDismissed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DevicePicker, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, DevicePickerDismissed_revoker>(this, DevicePickerDismissed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePicker<D>::DevicePickerDismissed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->remove_DevicePickerDismissed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePicker<D>::Show(winrt::Windows::Foundation::Rect const& selection) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->Show(impl::bind_in(selection)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePicker<D>::Show(winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& placement) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->ShowWithPlacement(impl::bind_in(selection), static_cast<int32_t>(placement)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>) consume_Windows_Devices_Enumeration_IDevicePicker<D>::PickSingleDeviceAsync(winrt::Windows::Foundation::Rect const& selection) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->PickSingleDeviceAsync(impl::bind_in(selection), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>) consume_Windows_Devices_Enumeration_IDevicePicker<D>::PickSingleDeviceAsync(winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& placement) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->PickSingleDeviceAsyncWithPlacement(impl::bind_in(selection), static_cast<int32_t>(placement), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePicker<D>::Hide() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->Hide());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePicker<D>::SetDisplayStatus(winrt::Windows::Devices::Enumeration::DeviceInformation const& device, param::hstring const& status, winrt::Windows::Devices::Enumeration::DevicePickerDisplayStatusOptions const& options) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePicker)->SetDisplayStatus(*(void**)(&device), *(void**)(&status), static_cast<uint32_t>(options)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::ForegroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->get_ForegroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::ForegroundColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->put_ForegroundColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::BackgroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->get_BackgroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::BackgroundColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->put_BackgroundColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::AccentColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->get_AccentColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::AccentColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->put_AccentColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::SelectedForegroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->get_SelectedForegroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::SelectedForegroundColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->put_SelectedForegroundColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::SelectedBackgroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->get_SelectedBackgroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::SelectedBackgroundColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->put_SelectedBackgroundColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::SelectedAccentColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->get_SelectedAccentColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::SelectedAccentColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerAppearance)->put_SelectedAccentColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Enumeration::DeviceClass>) consume_Windows_Devices_Enumeration_IDevicePickerFilter<D>::SupportedDeviceClasses() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerFilter)->get_SupportedDeviceClasses(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Enumeration::DeviceClass>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Devices_Enumeration_IDevicePickerFilter<D>::SupportedDeviceSelectors() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDevicePickerFilter)->get_SupportedDeviceSelectors(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Devices_Enumeration_IDeviceSelectedEventArgs<D>::SelectedDevice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceSelectedEventArgs)->get_SelectedDevice(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceUnpairingResultStatus) consume_Windows_Devices_Enumeration_IDeviceUnpairingResult<D>::Status() const
    {
        winrt::Windows::Devices::Enumeration::DeviceUnpairingResultStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceUnpairingResult)->get_Status(reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Added(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Devices::Enumeration::DeviceInformation> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher)->add_Added(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Added_revoker consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Added(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Devices::Enumeration::DeviceInformation> const& handler) const
    {
        return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Added(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher)->remove_Added(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Updated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Devices::Enumeration::DeviceInformationUpdate> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher)->add_Updated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Updated_revoker consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Updated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Devices::Enumeration::DeviceInformationUpdate> const& handler) const
    {
        return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Updated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher)->remove_Updated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Removed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Devices::Enumeration::DeviceInformationUpdate> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher)->add_Removed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Removed_revoker consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Removed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Devices::Enumeration::DeviceInformationUpdate> const& handler) const
    {
        return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Removed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher)->remove_Removed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::EnumerationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher)->add_EnumerationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::EnumerationCompleted_revoker consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::EnumerationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher)->remove_EnumerationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Stopped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher)->add_Stopped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Stopped_revoker consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Stopped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher)->remove_Stopped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceWatcherStatus) consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Status() const
    {
        winrt::Windows::Devices::Enumeration::DeviceWatcherStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher)->get_Status(reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Background::DeviceWatcherTrigger) consume_Windows_Devices_Enumeration_IDeviceWatcher2<D>::GetBackgroundTrigger(param::iterable<winrt::Windows::Devices::Enumeration::DeviceWatcherEventKind> const& requestedEventKinds) const
    {
        void* trigger{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcher2)->GetBackgroundTrigger(*(void**)(&requestedEventKinds), &trigger));
        return winrt::Windows::ApplicationModel::Background::DeviceWatcherTrigger{ trigger, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceWatcherEventKind) consume_Windows_Devices_Enumeration_IDeviceWatcherEvent<D>::Kind() const
    {
        winrt::Windows::Devices::Enumeration::DeviceWatcherEventKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcherEvent)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Devices_Enumeration_IDeviceWatcherEvent<D>::DeviceInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcherEvent)->get_DeviceInformation(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformationUpdate) consume_Windows_Devices_Enumeration_IDeviceWatcherEvent<D>::DeviceInformationUpdate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcherEvent)->get_DeviceInformationUpdate(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformationUpdate{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Enumeration::DeviceWatcherEvent>) consume_Windows_Devices_Enumeration_IDeviceWatcherTriggerDetails<D>::DeviceWatcherEvents() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails)->get_DeviceWatcherEvents(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Enumeration::DeviceWatcherEvent>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Enumeration_IEnclosureLocation<D>::InDock() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IEnclosureLocation)->get_InDock(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Enumeration_IEnclosureLocation<D>::InLid() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IEnclosureLocation)->get_InLid(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::Panel) consume_Windows_Devices_Enumeration_IEnclosureLocation<D>::Panel() const
    {
        winrt::Windows::Devices::Enumeration::Panel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IEnclosureLocation)->get_Panel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Enumeration_IEnclosureLocation2<D>::RotationAngleInDegreesClockwise() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::IEnclosureLocation2)->get_RotationAngleInDegreesClockwise(&value));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceAccessStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceAccessInformation> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceAccessInformation>
    {
        int32_t __stdcall add_AccessChanged(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().AccessChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceAccessInformation, winrt::Windows::Devices::Enumeration::DeviceAccessChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AccessChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccessChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall get_CurrentStatus(int32_t* status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *status = detach_from<winrt::Windows::Devices::Enumeration::DeviceAccessStatus>(this->shim().CurrentStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceAccessInformationStatics> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceAccessInformationStatics>
    {
        int32_t __stdcall CreateFromId(void* deviceId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceAccessInformation>(this->shim().CreateFromId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromDeviceClassId(winrt::guid deviceClassId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceAccessInformation>(this->shim().CreateFromDeviceClassId(*reinterpret_cast<winrt::guid const*>(&deviceClassId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromDeviceClass(int32_t deviceClass, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceAccessInformation>(this->shim().CreateFromDeviceClass(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceClass const*>(&deviceClass)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails>
    {
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
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs>
    {
        int32_t __stdcall get_Device(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceInformation> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceInformation>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
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
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDefault(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnclosureLocation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::EnclosureLocation>(this->shim().EnclosureLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Update(void* updateInfo) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Update(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformationUpdate const*>(&updateInfo));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetThumbnailAsync(void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceThumbnail>>(this->shim().GetThumbnailAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetGlyphThumbnailAsync(void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceThumbnail>>(this->shim().GetGlyphThumbnailAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceInformation2> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceInformation2>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformationKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pairing(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformationPairing>(this->shim().Pairing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceInformationCustomPairing> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceInformationCustomPairing>
    {
        int32_t __stdcall PairAsync(uint32_t pairingKindsSupported, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>>(this->shim().PairAsync(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DevicePairingKinds const*>(&pairingKindsSupported)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PairWithProtectionLevelAsync(uint32_t pairingKindsSupported, int32_t minProtectionLevel, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>>(this->shim().PairAsync(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DevicePairingKinds const*>(&pairingKindsSupported), *reinterpret_cast<winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel const*>(&minProtectionLevel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PairWithProtectionLevelAndSettingsAsync(uint32_t pairingKindsSupported, int32_t minProtectionLevel, void* devicePairingSettings, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>>(this->shim().PairAsync(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DevicePairingKinds const*>(&pairingKindsSupported), *reinterpret_cast<winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel const*>(&minProtectionLevel), *reinterpret_cast<winrt::Windows::Devices::Enumeration::IDevicePairingSettings const*>(&devicePairingSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_PairingRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PairingRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceInformationCustomPairing, winrt::Windows::Devices::Enumeration::DevicePairingRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PairingRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PairingRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceInformationPairing> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceInformationPairing>
    {
        int32_t __stdcall get_IsPaired(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPaired());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanPair(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanPair());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PairAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>>(this->shim().PairAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PairWithProtectionLevelAsync(int32_t minProtectionLevel, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>>(this->shim().PairAsync(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel const*>(&minProtectionLevel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceInformationPairing2> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceInformationPairing2>
    {
        int32_t __stdcall get_ProtectionLevel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel>(this->shim().ProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Custom(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformationCustomPairing>(this->shim().Custom());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PairWithProtectionLevelAndSettingsAsync(int32_t minProtectionLevel, void* devicePairingSettings, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DevicePairingResult>>(this->shim().PairAsync(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel const*>(&minProtectionLevel), *reinterpret_cast<winrt::Windows::Devices::Enumeration::IDevicePairingSettings const*>(&devicePairingSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnpairAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceUnpairingResult>>(this->shim().UnpairAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceInformationPairingStatics> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceInformationPairingStatics>
    {
        int32_t __stdcall TryRegisterForAllInboundPairingRequests(uint32_t pairingKindsSupported, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryRegisterForAllInboundPairingRequests(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DevicePairingKinds const*>(&pairingKindsSupported)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceInformationPairingStatics2> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceInformationPairingStatics2>
    {
        int32_t __stdcall TryRegisterForAllInboundPairingRequestsWithProtectionLevel(uint32_t pairingKindsSupported, int32_t minProtectionLevel, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryRegisterForAllInboundPairingRequestsWithProtectionLevel(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DevicePairingKinds const*>(&pairingKindsSupported), *reinterpret_cast<winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel const*>(&minProtectionLevel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceInformationStatics> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceInformationStatics>
    {
        int32_t __stdcall CreateFromIdAsync(void* deviceId, void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>>(this->shim().CreateFromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromIdAsyncAdditionalProperties(void* deviceId, void* additionalProperties, void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>>(this->shim().CreateFromIdAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&additionalProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllAsync(void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>>(this->shim().FindAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllAsyncDeviceClass(int32_t deviceClass, void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>>(this->shim().FindAllAsync(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceClass const*>(&deviceClass)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllAsyncAqsFilter(void* aqsFilter, void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>>(this->shim().FindAllAsync(*reinterpret_cast<hstring const*>(&aqsFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllAsyncAqsFilterAndAdditionalProperties(void* aqsFilter, void* additionalProperties, void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>>(this->shim().FindAllAsync(*reinterpret_cast<hstring const*>(&aqsFilter), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&additionalProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWatcher(void** watcher) noexcept final try
        {
            clear_abi(watcher);
            typename D::abi_guard guard(this->shim());
            *watcher = detach_from<winrt::Windows::Devices::Enumeration::DeviceWatcher>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWatcherDeviceClass(int32_t deviceClass, void** watcher) noexcept final try
        {
            clear_abi(watcher);
            typename D::abi_guard guard(this->shim());
            *watcher = detach_from<winrt::Windows::Devices::Enumeration::DeviceWatcher>(this->shim().CreateWatcher(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceClass const*>(&deviceClass)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWatcherAqsFilter(void* aqsFilter, void** watcher) noexcept final try
        {
            clear_abi(watcher);
            typename D::abi_guard guard(this->shim());
            *watcher = detach_from<winrt::Windows::Devices::Enumeration::DeviceWatcher>(this->shim().CreateWatcher(*reinterpret_cast<hstring const*>(&aqsFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWatcherAqsFilterAndAdditionalProperties(void* aqsFilter, void* additionalProperties, void** watcher) noexcept final try
        {
            clear_abi(watcher);
            typename D::abi_guard guard(this->shim());
            *watcher = detach_from<winrt::Windows::Devices::Enumeration::DeviceWatcher>(this->shim().CreateWatcher(*reinterpret_cast<hstring const*>(&aqsFilter), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&additionalProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceInformationStatics2> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceInformationStatics2>
    {
        int32_t __stdcall GetAqsFilterFromDeviceClass(int32_t deviceClass, void** aqsFilter) noexcept final try
        {
            clear_abi(aqsFilter);
            typename D::abi_guard guard(this->shim());
            *aqsFilter = detach_from<hstring>(this->shim().GetAqsFilterFromDeviceClass(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceClass const*>(&deviceClass)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromIdAsyncWithKindAndAdditionalProperties(void* deviceId, void* additionalProperties, int32_t kind, void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>>(this->shim().CreateFromIdAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&additionalProperties), *reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformationKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllAsyncWithKindAqsFilterAndAdditionalProperties(void* aqsFilter, void* additionalProperties, int32_t kind, void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>>(this->shim().FindAllAsync(*reinterpret_cast<hstring const*>(&aqsFilter), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&additionalProperties), *reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformationKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWatcherWithKindAqsFilterAndAdditionalProperties(void* aqsFilter, void* additionalProperties, int32_t kind, void** watcher) noexcept final try
        {
            clear_abi(watcher);
            typename D::abi_guard guard(this->shim());
            *watcher = detach_from<winrt::Windows::Devices::Enumeration::DeviceWatcher>(this->shim().CreateWatcher(*reinterpret_cast<hstring const*>(&aqsFilter), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&additionalProperties), *reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformationKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceInformationUpdate> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceInformationUpdate>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceInformationUpdate2> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceInformationUpdate2>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformationKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs> : produce_base<D, winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs>
    {
        int32_t __stdcall get_DeviceInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().DeviceInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PairingKind(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DevicePairingKinds>(this->shim().PairingKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pin(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Pin());
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
        int32_t __stdcall AcceptWithPin(void* pin) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Accept(*reinterpret_cast<hstring const*>(&pin));
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
    struct produce<D, winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2> : produce_base<D, winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2>
    {
        int32_t __stdcall AcceptWithPasswordCredential(void* passwordCredential) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AcceptWithPasswordCredential(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&passwordCredential));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDevicePairingResult> : produce_base<D, winrt::Windows::Devices::Enumeration::IDevicePairingResult>
    {
        int32_t __stdcall get_Status(int32_t* status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *status = detach_from<winrt::Windows::Devices::Enumeration::DevicePairingResultStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProtectionLevelUsed(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel>(this->shim().ProtectionLevelUsed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDevicePairingSettings> : produce_base<D, winrt::Windows::Devices::Enumeration::IDevicePairingSettings>
    {
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDevicePicker> : produce_base<D, winrt::Windows::Devices::Enumeration::IDevicePicker>
    {
        int32_t __stdcall get_Filter(void** filter) noexcept final try
        {
            clear_abi(filter);
            typename D::abi_guard guard(this->shim());
            *filter = detach_from<winrt::Windows::Devices::Enumeration::DevicePickerFilter>(this->shim().Filter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Appearance(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DevicePickerAppearance>(this->shim().Appearance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequestedProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().RequestedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_DeviceSelected(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DeviceSelected(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DevicePicker, winrt::Windows::Devices::Enumeration::DeviceSelectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DeviceSelected(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeviceSelected(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DisconnectButtonClicked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DisconnectButtonClicked(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DevicePicker, winrt::Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DisconnectButtonClicked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisconnectButtonClicked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DevicePickerDismissed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DevicePickerDismissed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DevicePicker, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DevicePickerDismissed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DevicePickerDismissed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall Show(winrt::Windows::Foundation::Rect selection) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Show(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&selection));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowWithPlacement(winrt::Windows::Foundation::Rect selection, int32_t placement) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Show(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<winrt::Windows::UI::Popups::Placement const*>(&placement));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickSingleDeviceAsync(winrt::Windows::Foundation::Rect selection, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>>(this->shim().PickSingleDeviceAsync(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&selection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickSingleDeviceAsyncWithPlacement(winrt::Windows::Foundation::Rect selection, int32_t placement, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformation>>(this->shim().PickSingleDeviceAsync(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<winrt::Windows::UI::Popups::Placement const*>(&placement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Hide() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Hide();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDisplayStatus(void* device, void* status, uint32_t options) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDisplayStatus(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformation const*>(&device), *reinterpret_cast<hstring const*>(&status), *reinterpret_cast<winrt::Windows::Devices::Enumeration::DevicePickerDisplayStatusOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDevicePickerAppearance> : produce_base<D, winrt::Windows::Devices::Enumeration::IDevicePickerAppearance>
    {
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ForegroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().ForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ForegroundColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ForegroundColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BackgroundColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccentColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().AccentColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AccentColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccentColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedForegroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().SelectedForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedForegroundColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedForegroundColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedBackgroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().SelectedBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedBackgroundColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedBackgroundColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedAccentColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().SelectedAccentColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedAccentColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedAccentColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDevicePickerFilter> : produce_base<D, winrt::Windows::Devices::Enumeration::IDevicePickerFilter>
    {
        int32_t __stdcall get_SupportedDeviceClasses(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Enumeration::DeviceClass>>(this->shim().SupportedDeviceClasses());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedDeviceSelectors(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().SupportedDeviceSelectors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceSelectedEventArgs> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceSelectedEventArgs>
    {
        int32_t __stdcall get_SelectedDevice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().SelectedDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceUnpairingResult> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceUnpairingResult>
    {
        int32_t __stdcall get_Status(int32_t* status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *status = detach_from<winrt::Windows::Devices::Enumeration::DeviceUnpairingResultStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceWatcher> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceWatcher>
    {
        int32_t __stdcall add_Added(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Devices::Enumeration::DeviceInformation> const*>(&handler)));
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
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Devices::Enumeration::DeviceInformationUpdate> const*>(&handler)));
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
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Devices::Enumeration::DeviceInformationUpdate> const*>(&handler)));
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
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
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
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::DeviceWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
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
            *status = detach_from<winrt::Windows::Devices::Enumeration::DeviceWatcherStatus>(this->shim().Status());
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
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceWatcher2> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceWatcher2>
    {
        int32_t __stdcall GetBackgroundTrigger(void* requestedEventKinds, void** trigger) noexcept final try
        {
            clear_abi(trigger);
            typename D::abi_guard guard(this->shim());
            *trigger = detach_from<winrt::Windows::ApplicationModel::Background::DeviceWatcherTrigger>(this->shim().GetBackgroundTrigger(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::Enumeration::DeviceWatcherEventKind> const*>(&requestedEventKinds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceWatcherEvent> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceWatcherEvent>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceWatcherEventKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().DeviceInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceInformationUpdate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformationUpdate>(this->shim().DeviceInformationUpdate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails> : produce_base<D, winrt::Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails>
    {
        int32_t __stdcall get_DeviceWatcherEvents(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Enumeration::DeviceWatcherEvent>>(this->shim().DeviceWatcherEvents());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IEnclosureLocation> : produce_base<D, winrt::Windows::Devices::Enumeration::IEnclosureLocation>
    {
        int32_t __stdcall get_InDock(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().InDock());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InLid(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().InLid());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Panel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::Panel>(this->shim().Panel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::IEnclosureLocation2> : produce_base<D, winrt::Windows::Devices::Enumeration::IEnclosureLocation2>
    {
        int32_t __stdcall get_RotationAngleInDegreesClockwise(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().RotationAngleInDegreesClockwise());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration
{
    constexpr auto operator|(DevicePairingKinds const left, DevicePairingKinds const right) noexcept
    {
        return static_cast<DevicePairingKinds>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(DevicePairingKinds& left, DevicePairingKinds const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(DevicePairingKinds const left, DevicePairingKinds const right) noexcept
    {
        return static_cast<DevicePairingKinds>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(DevicePairingKinds& left, DevicePairingKinds const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(DevicePairingKinds const value) noexcept
    {
        return static_cast<DevicePairingKinds>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(DevicePairingKinds const left, DevicePairingKinds const right) noexcept
    {
        return static_cast<DevicePairingKinds>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(DevicePairingKinds& left, DevicePairingKinds const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(DevicePickerDisplayStatusOptions const left, DevicePickerDisplayStatusOptions const right) noexcept
    {
        return static_cast<DevicePickerDisplayStatusOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(DevicePickerDisplayStatusOptions& left, DevicePickerDisplayStatusOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(DevicePickerDisplayStatusOptions const left, DevicePickerDisplayStatusOptions const right) noexcept
    {
        return static_cast<DevicePickerDisplayStatusOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(DevicePickerDisplayStatusOptions& left, DevicePickerDisplayStatusOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(DevicePickerDisplayStatusOptions const value) noexcept
    {
        return static_cast<DevicePickerDisplayStatusOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(DevicePickerDisplayStatusOptions const left, DevicePickerDisplayStatusOptions const right) noexcept
    {
        return static_cast<DevicePickerDisplayStatusOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(DevicePickerDisplayStatusOptions& left, DevicePickerDisplayStatusOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto DeviceAccessInformation::CreateFromId(param::hstring const& deviceId)
    {
        return impl::call_factory<DeviceAccessInformation, IDeviceAccessInformationStatics>([&](IDeviceAccessInformationStatics const& f) { return f.CreateFromId(deviceId); });
    }
    inline auto DeviceAccessInformation::CreateFromDeviceClassId(winrt::guid const& deviceClassId)
    {
        return impl::call_factory<DeviceAccessInformation, IDeviceAccessInformationStatics>([&](IDeviceAccessInformationStatics const& f) { return f.CreateFromDeviceClassId(deviceClassId); });
    }
    inline auto DeviceAccessInformation::CreateFromDeviceClass(winrt::Windows::Devices::Enumeration::DeviceClass const& deviceClass)
    {
        return impl::call_factory<DeviceAccessInformation, IDeviceAccessInformationStatics>([&](IDeviceAccessInformationStatics const& f) { return f.CreateFromDeviceClass(deviceClass); });
    }
    inline auto DeviceInformation::CreateFromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<DeviceInformation, IDeviceInformationStatics>([&](IDeviceInformationStatics const& f) { return f.CreateFromIdAsync(deviceId); });
    }
    inline auto DeviceInformation::CreateFromIdAsync(param::hstring const& deviceId, param::async_iterable<hstring> const& additionalProperties)
    {
        return impl::call_factory<DeviceInformation, IDeviceInformationStatics>([&](IDeviceInformationStatics const& f) { return f.CreateFromIdAsync(deviceId, additionalProperties); });
    }
    inline auto DeviceInformation::FindAllAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceInformationCollection>(*)(IDeviceInformationStatics const&), DeviceInformation, IDeviceInformationStatics>([](IDeviceInformationStatics const& f) { return f.FindAllAsync(); });
    }
    inline auto DeviceInformation::FindAllAsync(winrt::Windows::Devices::Enumeration::DeviceClass const& deviceClass)
    {
        return impl::call_factory<DeviceInformation, IDeviceInformationStatics>([&](IDeviceInformationStatics const& f) { return f.FindAllAsync(deviceClass); });
    }
    inline auto DeviceInformation::FindAllAsync(param::hstring const& aqsFilter)
    {
        return impl::call_factory<DeviceInformation, IDeviceInformationStatics>([&](IDeviceInformationStatics const& f) { return f.FindAllAsync(aqsFilter); });
    }
    inline auto DeviceInformation::FindAllAsync(param::hstring const& aqsFilter, param::async_iterable<hstring> const& additionalProperties)
    {
        return impl::call_factory<DeviceInformation, IDeviceInformationStatics>([&](IDeviceInformationStatics const& f) { return f.FindAllAsync(aqsFilter, additionalProperties); });
    }
    inline auto DeviceInformation::CreateWatcher()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Enumeration::DeviceWatcher(*)(IDeviceInformationStatics const&), DeviceInformation, IDeviceInformationStatics>([](IDeviceInformationStatics const& f) { return f.CreateWatcher(); });
    }
    inline auto DeviceInformation::CreateWatcher(winrt::Windows::Devices::Enumeration::DeviceClass const& deviceClass)
    {
        return impl::call_factory<DeviceInformation, IDeviceInformationStatics>([&](IDeviceInformationStatics const& f) { return f.CreateWatcher(deviceClass); });
    }
    inline auto DeviceInformation::CreateWatcher(param::hstring const& aqsFilter)
    {
        return impl::call_factory<DeviceInformation, IDeviceInformationStatics>([&](IDeviceInformationStatics const& f) { return f.CreateWatcher(aqsFilter); });
    }
    inline auto DeviceInformation::CreateWatcher(param::hstring const& aqsFilter, param::iterable<hstring> const& additionalProperties)
    {
        return impl::call_factory<DeviceInformation, IDeviceInformationStatics>([&](IDeviceInformationStatics const& f) { return f.CreateWatcher(aqsFilter, additionalProperties); });
    }
    inline auto DeviceInformation::GetAqsFilterFromDeviceClass(winrt::Windows::Devices::Enumeration::DeviceClass const& deviceClass)
    {
        return impl::call_factory<DeviceInformation, IDeviceInformationStatics2>([&](IDeviceInformationStatics2 const& f) { return f.GetAqsFilterFromDeviceClass(deviceClass); });
    }
    inline auto DeviceInformation::CreateFromIdAsync(param::hstring const& deviceId, param::async_iterable<hstring> const& additionalProperties, winrt::Windows::Devices::Enumeration::DeviceInformationKind const& kind)
    {
        return impl::call_factory<DeviceInformation, IDeviceInformationStatics2>([&](IDeviceInformationStatics2 const& f) { return f.CreateFromIdAsync(deviceId, additionalProperties, kind); });
    }
    inline auto DeviceInformation::FindAllAsync(param::hstring const& aqsFilter, param::async_iterable<hstring> const& additionalProperties, winrt::Windows::Devices::Enumeration::DeviceInformationKind const& kind)
    {
        return impl::call_factory<DeviceInformation, IDeviceInformationStatics2>([&](IDeviceInformationStatics2 const& f) { return f.FindAllAsync(aqsFilter, additionalProperties, kind); });
    }
    inline auto DeviceInformation::CreateWatcher(param::hstring const& aqsFilter, param::iterable<hstring> const& additionalProperties, winrt::Windows::Devices::Enumeration::DeviceInformationKind const& kind)
    {
        return impl::call_factory<DeviceInformation, IDeviceInformationStatics2>([&](IDeviceInformationStatics2 const& f) { return f.CreateWatcher(aqsFilter, additionalProperties, kind); });
    }
    inline auto DeviceInformationPairing::TryRegisterForAllInboundPairingRequests(winrt::Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported)
    {
        return impl::call_factory<DeviceInformationPairing, IDeviceInformationPairingStatics>([&](IDeviceInformationPairingStatics const& f) { return f.TryRegisterForAllInboundPairingRequests(pairingKindsSupported); });
    }
    inline auto DeviceInformationPairing::TryRegisterForAllInboundPairingRequestsWithProtectionLevel(winrt::Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported, winrt::Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel)
    {
        return impl::call_factory<DeviceInformationPairing, IDeviceInformationPairingStatics2>([&](IDeviceInformationPairingStatics2 const& f) { return f.TryRegisterForAllInboundPairingRequestsWithProtectionLevel(pairingKindsSupported, minProtectionLevel); });
    }
    inline DevicePicker::DevicePicker() :
        DevicePicker(impl::call_factory_cast<DevicePicker(*)(winrt::Windows::Foundation::IActivationFactory const&), DevicePicker>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DevicePicker>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceAccessInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceAccessInformationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationCustomPairing> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationPairing> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationPairing2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationPairingStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationPairingStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationUpdate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationUpdate2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePairingResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePairingSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePickerAppearance> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePickerFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceSelectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceUnpairingResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceWatcher2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceWatcherEvent> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IEnclosureLocation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::IEnclosureLocation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceAccessChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceAccessInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceConnectionChangeTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceInformationCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceInformationCustomPairing> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceInformationPairing> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceInformationUpdate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DevicePairingRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DevicePairingResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DevicePicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DevicePickerAppearance> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DevicePickerFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceSelectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceThumbnail> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceUnpairingResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceWatcherEvent> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceWatcherTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::EnclosureLocation> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
