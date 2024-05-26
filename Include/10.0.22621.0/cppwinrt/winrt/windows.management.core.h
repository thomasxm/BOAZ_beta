// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Management_Core_H
#define WINRT_Windows_Management_Core_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Management.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Management.Core.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::ApplicationData) consume_Windows_Management_Core_IApplicationDataManagerStatics<D>::CreateForPackageFamily(param::hstring const& packageFamilyName) const
    {
        void* applicationData{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::Core::IApplicationDataManagerStatics)->CreateForPackageFamily(*(void**)(&packageFamilyName), &applicationData));
        return winrt::Windows::Storage::ApplicationData{ applicationData, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Management::Core::IApplicationDataManager> : produce_base<D, winrt::Windows::Management::Core::IApplicationDataManager>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Management::Core::IApplicationDataManagerStatics> : produce_base<D, winrt::Windows::Management::Core::IApplicationDataManagerStatics>
    {
        int32_t __stdcall CreateForPackageFamily(void* packageFamilyName, void** applicationData) noexcept final try
        {
            clear_abi(applicationData);
            typename D::abi_guard guard(this->shim());
            *applicationData = detach_from<winrt::Windows::Storage::ApplicationData>(this->shim().CreateForPackageFamily(*reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Management::Core
{
    inline auto ApplicationDataManager::CreateForPackageFamily(param::hstring const& packageFamilyName)
    {
        return impl::call_factory<ApplicationDataManager, IApplicationDataManagerStatics>([&](IApplicationDataManagerStatics const& f) { return f.CreateForPackageFamily(packageFamilyName); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Management::Core::IApplicationDataManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Management::Core::IApplicationDataManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Management::Core::ApplicationDataManager> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
