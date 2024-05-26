// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Enumeration_Pnp_2_H
#define WINRT_Windows_Devices_Enumeration_Pnp_2_H
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Devices.Enumeration.Pnp.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration::Pnp
{
    struct __declspec(empty_bases) PnpObject : winrt::Windows::Devices::Enumeration::Pnp::IPnpObject
    {
        PnpObject(std::nullptr_t) noexcept {}
        PnpObject(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Enumeration::Pnp::IPnpObject(ptr, take_ownership_from_abi) {}
        static auto CreateFromIdAsync(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::hstring const& id, param::async_iterable<hstring> const& requestedProperties);
        static auto FindAllAsync(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::async_iterable<hstring> const& requestedProperties);
        static auto FindAllAsync(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::async_iterable<hstring> const& requestedProperties, param::hstring const& aqsFilter);
        static auto CreateWatcher(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::iterable<hstring> const& requestedProperties);
        static auto CreateWatcher(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::iterable<hstring> const& requestedProperties, param::hstring const& aqsFilter);
    };
    struct __declspec(empty_bases) PnpObjectCollection : winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Enumeration::Pnp::PnpObject>
    {
        PnpObjectCollection(std::nullptr_t) noexcept {}
        PnpObjectCollection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Enumeration::Pnp::PnpObject>(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PnpObjectUpdate : winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate
    {
        PnpObjectUpdate(std::nullptr_t) noexcept {}
        PnpObjectUpdate(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PnpObjectWatcher : winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher
    {
        PnpObjectWatcher(std::nullptr_t) noexcept {}
        PnpObjectWatcher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher(ptr, take_ownership_from_abi) {}
    };
}
#endif
