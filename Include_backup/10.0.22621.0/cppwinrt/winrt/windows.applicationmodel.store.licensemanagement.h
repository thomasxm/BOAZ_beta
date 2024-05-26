// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Store_LicenseManagement_H
#define WINRT_Windows_ApplicationModel_Store_LicenseManagement_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.Store.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.ApplicationModel.Store.LicenseManagement.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseManagerStatics<D>::AddLicenseAsync(winrt::Windows::Storage::Streams::IBuffer const& license) const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics)->AddLicenseAsync(*(void**)(&license), &action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionResult>) consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseManagerStatics<D>::GetSatisfactionInfosAsync(param::async_iterable<hstring> const& contentIds, param::async_iterable<hstring> const& keyIds) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics)->GetSatisfactionInfosAsync(*(void**)(&contentIds), *(void**)(&keyIds), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseManagerStatics2<D>::RefreshLicensesAsync(winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseRefreshOption const& refreshOption) const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics2)->RefreshLicensesAsync(static_cast<int32_t>(refreshOption), &action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseSatisfactionInfo<D>::SatisfiedByDevice() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo)->get_SatisfiedByDevice(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseSatisfactionInfo<D>::SatisfiedByOpenLicense() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo)->get_SatisfiedByOpenLicense(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseSatisfactionInfo<D>::SatisfiedByTrial() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo)->get_SatisfiedByTrial(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseSatisfactionInfo<D>::SatisfiedByPass() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo)->get_SatisfiedByPass(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseSatisfactionInfo<D>::SatisfiedByInstallMedia() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo)->get_SatisfiedByInstallMedia(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseSatisfactionInfo<D>::SatisfiedBySignedInUser() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo)->get_SatisfiedBySignedInUser(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseSatisfactionInfo<D>::IsSatisfied() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo)->get_IsSatisfied(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionInfo>) consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseSatisfactionResult<D>::LicenseSatisfactionInfos() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionResult)->get_LicenseSatisfactionInfos(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionInfo>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseSatisfactionResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics>
    {
        int32_t __stdcall AddLicenseAsync(void* license, void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AddLicenseAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&license)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSatisfactionInfosAsync(void* contentIds, void* keyIds, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionResult>>(this->shim().GetSatisfactionInfosAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&contentIds), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&keyIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics2> : produce_base<D, winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics2>
    {
        int32_t __stdcall RefreshLicensesAsync(int32_t refreshOption, void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RefreshLicensesAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseRefreshOption const*>(&refreshOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo> : produce_base<D, winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo>
    {
        int32_t __stdcall get_SatisfiedByDevice(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SatisfiedByDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SatisfiedByOpenLicense(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SatisfiedByOpenLicense());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SatisfiedByTrial(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SatisfiedByTrial());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SatisfiedByPass(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SatisfiedByPass());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SatisfiedByInstallMedia(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SatisfiedByInstallMedia());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SatisfiedBySignedInUser(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SatisfiedBySignedInUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSatisfied(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSatisfied());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionResult> : produce_base<D, winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionResult>
    {
        int32_t __stdcall get_LicenseSatisfactionInfos(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionInfo>>(this->shim().LicenseSatisfactionInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Store::LicenseManagement
{
    inline auto LicenseManager::AddLicenseAsync(winrt::Windows::Storage::Streams::IBuffer const& license)
    {
        return impl::call_factory<LicenseManager, ILicenseManagerStatics>([&](ILicenseManagerStatics const& f) { return f.AddLicenseAsync(license); });
    }
    inline auto LicenseManager::GetSatisfactionInfosAsync(param::async_iterable<hstring> const& contentIds, param::async_iterable<hstring> const& keyIds)
    {
        return impl::call_factory<LicenseManager, ILicenseManagerStatics>([&](ILicenseManagerStatics const& f) { return f.GetSatisfactionInfosAsync(contentIds, keyIds); });
    }
    inline auto LicenseManager::RefreshLicensesAsync(winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseRefreshOption const& refreshOption)
    {
        return impl::call_factory<LicenseManager, ILicenseManagerStatics2>([&](ILicenseManagerStatics2 const& f) { return f.RefreshLicensesAsync(refreshOption); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionResult> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
