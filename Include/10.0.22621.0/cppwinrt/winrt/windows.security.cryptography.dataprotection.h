// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Cryptography_DataProtection_H
#define WINRT_Windows_Security_Cryptography_DataProtection_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Security.Cryptography.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Security.Cryptography.DataProtection.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Security_Cryptography_DataProtection_IDataProtectionProvider<D>::ProtectAsync(winrt::Windows::Storage::Streams::IBuffer const& data) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Cryptography::DataProtection::IDataProtectionProvider)->ProtectAsync(*(void**)(&data), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Security_Cryptography_DataProtection_IDataProtectionProvider<D>::UnprotectAsync(winrt::Windows::Storage::Streams::IBuffer const& data) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Cryptography::DataProtection::IDataProtectionProvider)->UnprotectAsync(*(void**)(&data), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Security_Cryptography_DataProtection_IDataProtectionProvider<D>::ProtectStreamAsync(winrt::Windows::Storage::Streams::IInputStream const& src, winrt::Windows::Storage::Streams::IOutputStream const& dest) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Cryptography::DataProtection::IDataProtectionProvider)->ProtectStreamAsync(*(void**)(&src), *(void**)(&dest), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Security_Cryptography_DataProtection_IDataProtectionProvider<D>::UnprotectStreamAsync(winrt::Windows::Storage::Streams::IInputStream const& src, winrt::Windows::Storage::Streams::IOutputStream const& dest) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Cryptography::DataProtection::IDataProtectionProvider)->UnprotectStreamAsync(*(void**)(&src), *(void**)(&dest), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Cryptography::DataProtection::DataProtectionProvider) consume_Windows_Security_Cryptography_DataProtection_IDataProtectionProviderFactory<D>::CreateOverloadExplicit(param::hstring const& protectionDescriptor) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Cryptography::DataProtection::IDataProtectionProviderFactory)->CreateOverloadExplicit(*(void**)(&protectionDescriptor), &value));
        return winrt::Windows::Security::Cryptography::DataProtection::DataProtectionProvider{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Cryptography::DataProtection::IDataProtectionProvider> : produce_base<D, winrt::Windows::Security::Cryptography::DataProtection::IDataProtectionProvider>
    {
        int32_t __stdcall ProtectAsync(void* data, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().ProtectAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnprotectAsync(void* data, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().UnprotectAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProtectStreamAsync(void* src, void* dest, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ProtectStreamAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&src), *reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&dest)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnprotectStreamAsync(void* src, void* dest, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().UnprotectStreamAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&src), *reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&dest)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Cryptography::DataProtection::IDataProtectionProviderFactory> : produce_base<D, winrt::Windows::Security::Cryptography::DataProtection::IDataProtectionProviderFactory>
    {
        int32_t __stdcall CreateOverloadExplicit(void* protectionDescriptor, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Cryptography::DataProtection::DataProtectionProvider>(this->shim().CreateOverloadExplicit(*reinterpret_cast<hstring const*>(&protectionDescriptor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Security::Cryptography::DataProtection
{
    inline DataProtectionProvider::DataProtectionProvider() :
        DataProtectionProvider(impl::call_factory_cast<DataProtectionProvider(*)(winrt::Windows::Foundation::IActivationFactory const&), DataProtectionProvider>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DataProtectionProvider>(); }))
    {
    }
    inline DataProtectionProvider::DataProtectionProvider(param::hstring const& protectionDescriptor) :
        DataProtectionProvider(impl::call_factory<DataProtectionProvider, IDataProtectionProviderFactory>([&](IDataProtectionProviderFactory const& f) { return f.CreateOverloadExplicit(protectionDescriptor); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Security::Cryptography::DataProtection::IDataProtectionProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Cryptography::DataProtection::IDataProtectionProviderFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Cryptography::DataProtection::DataProtectionProvider> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
