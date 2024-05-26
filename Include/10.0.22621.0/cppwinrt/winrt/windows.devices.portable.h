// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Portable_H
#define WINRT_Windows_Devices_Portable_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Devices.Portable.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Portable_IServiceDeviceStatics<D>::GetDeviceSelector(winrt::Windows::Devices::Portable::ServiceDeviceType const& serviceType) const
    {
        void* selector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Portable::IServiceDeviceStatics)->GetDeviceSelector(static_cast<int32_t>(serviceType), &selector));
        return hstring{ selector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Portable_IServiceDeviceStatics<D>::GetDeviceSelectorFromServiceId(winrt::guid const& serviceId) const
    {
        void* selector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Portable::IServiceDeviceStatics)->GetDeviceSelectorFromServiceId(impl::bind_in(serviceId), &selector));
        return hstring{ selector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Devices_Portable_IStorageDeviceStatics<D>::FromId(param::hstring const& deviceId) const
    {
        void* deviceRoot{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Portable::IStorageDeviceStatics)->FromId(*(void**)(&deviceId), &deviceRoot));
        return winrt::Windows::Storage::StorageFolder{ deviceRoot, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Portable_IStorageDeviceStatics<D>::GetDeviceSelector() const
    {
        void* selector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Portable::IStorageDeviceStatics)->GetDeviceSelector(&selector));
        return hstring{ selector, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Portable::IServiceDeviceStatics> : produce_base<D, winrt::Windows::Devices::Portable::IServiceDeviceStatics>
    {
        int32_t __stdcall GetDeviceSelector(int32_t serviceType, void** selector) noexcept final try
        {
            clear_abi(selector);
            typename D::abi_guard guard(this->shim());
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::Windows::Devices::Portable::ServiceDeviceType const*>(&serviceType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorFromServiceId(winrt::guid serviceId, void** selector) noexcept final try
        {
            clear_abi(selector);
            typename D::abi_guard guard(this->shim());
            *selector = detach_from<hstring>(this->shim().GetDeviceSelectorFromServiceId(*reinterpret_cast<winrt::guid const*>(&serviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Portable::IStorageDeviceStatics> : produce_base<D, winrt::Windows::Devices::Portable::IStorageDeviceStatics>
    {
        int32_t __stdcall FromId(void* deviceId, void** deviceRoot) noexcept final try
        {
            clear_abi(deviceRoot);
            typename D::abi_guard guard(this->shim());
            *deviceRoot = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().FromId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** selector) noexcept final try
        {
            clear_abi(selector);
            typename D::abi_guard guard(this->shim());
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Portable
{
    inline auto ServiceDevice::GetDeviceSelector(winrt::Windows::Devices::Portable::ServiceDeviceType const& serviceType)
    {
        return impl::call_factory<ServiceDevice, IServiceDeviceStatics>([&](IServiceDeviceStatics const& f) { return f.GetDeviceSelector(serviceType); });
    }
    inline auto ServiceDevice::GetDeviceSelectorFromServiceId(winrt::guid const& serviceId)
    {
        return impl::call_factory<ServiceDevice, IServiceDeviceStatics>([&](IServiceDeviceStatics const& f) { return f.GetDeviceSelectorFromServiceId(serviceId); });
    }
    inline auto StorageDevice::FromId(param::hstring const& deviceId)
    {
        return impl::call_factory<StorageDevice, IStorageDeviceStatics>([&](IStorageDeviceStatics const& f) { return f.FromId(deviceId); });
    }
    inline auto StorageDevice::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IStorageDeviceStatics const&), StorageDevice, IStorageDeviceStatics>([](IStorageDeviceStatics const& f) { return f.GetDeviceSelector(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Portable::IServiceDeviceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Portable::IStorageDeviceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Portable::ServiceDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Portable::StorageDevice> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
