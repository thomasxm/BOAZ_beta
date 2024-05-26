// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Management_Workplace_H
#define WINRT_Windows_Management_Workplace_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Management.h"
#include "winrt/impl/Windows.Management.Workplace.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Management_Workplace_IMdmAllowPolicyStatics<D>::IsBrowserAllowed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::Workplace::IMdmAllowPolicyStatics)->IsBrowserAllowed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Management_Workplace_IMdmAllowPolicyStatics<D>::IsCameraAllowed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::Workplace::IMdmAllowPolicyStatics)->IsCameraAllowed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Management_Workplace_IMdmAllowPolicyStatics<D>::IsMicrosoftAccountAllowed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::Workplace::IMdmAllowPolicyStatics)->IsMicrosoftAccountAllowed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Management_Workplace_IMdmAllowPolicyStatics<D>::IsStoreAllowed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::Workplace::IMdmAllowPolicyStatics)->IsStoreAllowed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Management::Workplace::MessagingSyncPolicy) consume_Windows_Management_Workplace_IMdmPolicyStatics2<D>::GetMessagingSyncPolicy() const
    {
        winrt::Windows::Management::Workplace::MessagingSyncPolicy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::Workplace::IMdmPolicyStatics2)->GetMessagingSyncPolicy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Management_Workplace_IWorkplaceSettingsStatics<D>::IsMicrosoftAccountOptional() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::Workplace::IWorkplaceSettingsStatics)->get_IsMicrosoftAccountOptional(&value));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Management::Workplace::IMdmAllowPolicyStatics> : produce_base<D, winrt::Windows::Management::Workplace::IMdmAllowPolicyStatics>
    {
        int32_t __stdcall IsBrowserAllowed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBrowserAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsCameraAllowed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCameraAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsMicrosoftAccountAllowed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMicrosoftAccountAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsStoreAllowed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStoreAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Management::Workplace::IMdmPolicyStatics2> : produce_base<D, winrt::Windows::Management::Workplace::IMdmPolicyStatics2>
    {
        int32_t __stdcall GetMessagingSyncPolicy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Management::Workplace::MessagingSyncPolicy>(this->shim().GetMessagingSyncPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Management::Workplace::IWorkplaceSettingsStatics> : produce_base<D, winrt::Windows::Management::Workplace::IWorkplaceSettingsStatics>
    {
        int32_t __stdcall get_IsMicrosoftAccountOptional(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMicrosoftAccountOptional());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Management::Workplace
{
    inline auto MdmPolicy::IsBrowserAllowed()
    {
        return impl::call_factory_cast<bool(*)(IMdmAllowPolicyStatics const&), MdmPolicy, IMdmAllowPolicyStatics>([](IMdmAllowPolicyStatics const& f) { return f.IsBrowserAllowed(); });
    }
    inline auto MdmPolicy::IsCameraAllowed()
    {
        return impl::call_factory_cast<bool(*)(IMdmAllowPolicyStatics const&), MdmPolicy, IMdmAllowPolicyStatics>([](IMdmAllowPolicyStatics const& f) { return f.IsCameraAllowed(); });
    }
    inline auto MdmPolicy::IsMicrosoftAccountAllowed()
    {
        return impl::call_factory_cast<bool(*)(IMdmAllowPolicyStatics const&), MdmPolicy, IMdmAllowPolicyStatics>([](IMdmAllowPolicyStatics const& f) { return f.IsMicrosoftAccountAllowed(); });
    }
    inline auto MdmPolicy::IsStoreAllowed()
    {
        return impl::call_factory_cast<bool(*)(IMdmAllowPolicyStatics const&), MdmPolicy, IMdmAllowPolicyStatics>([](IMdmAllowPolicyStatics const& f) { return f.IsStoreAllowed(); });
    }
    inline auto MdmPolicy::GetMessagingSyncPolicy()
    {
        return impl::call_factory_cast<winrt::Windows::Management::Workplace::MessagingSyncPolicy(*)(IMdmPolicyStatics2 const&), MdmPolicy, IMdmPolicyStatics2>([](IMdmPolicyStatics2 const& f) { return f.GetMessagingSyncPolicy(); });
    }
    inline auto WorkplaceSettings::IsMicrosoftAccountOptional()
    {
        return impl::call_factory_cast<bool(*)(IWorkplaceSettingsStatics const&), WorkplaceSettings, IWorkplaceSettingsStatics>([](IWorkplaceSettingsStatics const& f) { return f.IsMicrosoftAccountOptional(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Management::Workplace::IMdmAllowPolicyStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Management::Workplace::IMdmPolicyStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Management::Workplace::IWorkplaceSettingsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Management::Workplace::MdmPolicy> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Management::Workplace::WorkplaceSettings> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
