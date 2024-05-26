// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Inventory_H
#define WINRT_Windows_System_Inventory_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.Inventory.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Inventory_IInstalledDesktopApp<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Inventory::IInstalledDesktopApp)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Inventory_IInstalledDesktopApp<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Inventory::IInstalledDesktopApp)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Inventory_IInstalledDesktopApp<D>::Publisher() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Inventory::IInstalledDesktopApp)->get_Publisher(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Inventory_IInstalledDesktopApp<D>::DisplayVersion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Inventory::IInstalledDesktopApp)->get_DisplayVersion(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::Inventory::InstalledDesktopApp>>) consume_Windows_System_Inventory_IInstalledDesktopAppStatics<D>::GetInventoryAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Inventory::IInstalledDesktopAppStatics)->GetInventoryAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::Inventory::InstalledDesktopApp>>{ operation, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Inventory::IInstalledDesktopApp> : produce_base<D, winrt::Windows::System::Inventory::IInstalledDesktopApp>
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
        int32_t __stdcall get_Publisher(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Publisher());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayVersion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Inventory::IInstalledDesktopAppStatics> : produce_base<D, winrt::Windows::System::Inventory::IInstalledDesktopAppStatics>
    {
        int32_t __stdcall GetInventoryAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::Inventory::InstalledDesktopApp>>>(this->shim().GetInventoryAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::Inventory
{
    inline auto InstalledDesktopApp::GetInventoryAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::Inventory::InstalledDesktopApp>>(*)(IInstalledDesktopAppStatics const&), InstalledDesktopApp, IInstalledDesktopAppStatics>([](IInstalledDesktopAppStatics const& f) { return f.GetInventoryAsync(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::Inventory::IInstalledDesktopApp> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Inventory::IInstalledDesktopAppStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Inventory::InstalledDesktopApp> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
    template<> struct formatter<winrt::Windows::System::Inventory::InstalledDesktopApp, wchar_t> : formatter<winrt::Windows::Foundation::IStringable, wchar_t> {};
#endif
}
#endif
