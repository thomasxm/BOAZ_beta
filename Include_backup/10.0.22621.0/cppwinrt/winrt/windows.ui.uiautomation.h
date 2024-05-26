// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_UIAutomation_H
#define WINRT_Windows_UI_UIAutomation_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.h"
#include "winrt/impl/Windows.UI.UIAutomation.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_UIAutomation_IAutomationConnection<D>::IsRemoteSystem() const noexcept
    {
        bool value{};
        WINRT_VERIFY_(0, WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::IAutomationConnection)->get_IsRemoteSystem(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_UIAutomation_IAutomationConnection<D>::AppUserModelId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::IAutomationConnection)->get_AppUserModelId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_UIAutomation_IAutomationConnection<D>::ExecutableFileName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::IAutomationConnection)->get_ExecutableFileName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::UIAutomation::AutomationConnection) consume_Windows_UI_UIAutomation_IAutomationConnectionBoundObject<D>::Connection() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::IAutomationConnectionBoundObject)->get_Connection(&value));
        return winrt::Windows::UI::UIAutomation::AutomationConnection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_UIAutomation_IAutomationElement<D>::IsRemoteSystem() const noexcept
    {
        bool value{};
        WINRT_VERIFY_(0, WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::IAutomationElement)->get_IsRemoteSystem(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_UIAutomation_IAutomationElement<D>::AppUserModelId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::IAutomationElement)->get_AppUserModelId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_UIAutomation_IAutomationElement<D>::ExecutableFileName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::IAutomationElement)->get_ExecutableFileName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::IAutomationConnection> : produce_base<D, winrt::Windows::UI::UIAutomation::IAutomationConnection>
    {
        int32_t __stdcall get_IsRemoteSystem(bool* value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRemoteSystem());
            return 0;
        }
        int32_t __stdcall get_AppUserModelId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppUserModelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExecutableFileName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExecutableFileName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::IAutomationConnectionBoundObject> : produce_base<D, winrt::Windows::UI::UIAutomation::IAutomationConnectionBoundObject>
    {
        int32_t __stdcall get_Connection(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::UIAutomation::AutomationConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::IAutomationElement> : produce_base<D, winrt::Windows::UI::UIAutomation::IAutomationElement>
    {
        int32_t __stdcall get_IsRemoteSystem(bool* value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRemoteSystem());
            return 0;
        }
        int32_t __stdcall get_AppUserModelId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppUserModelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExecutableFileName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExecutableFileName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::IAutomationTextRange> : produce_base<D, winrt::Windows::UI::UIAutomation::IAutomationTextRange>
    {
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::UIAutomation
{
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::UIAutomation::IAutomationConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::IAutomationConnectionBoundObject> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::IAutomationElement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::IAutomationTextRange> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::AutomationConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::AutomationConnectionBoundObject> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::AutomationElement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::AutomationTextRange> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
