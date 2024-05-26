// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_RemoteDesktop_Provider_H
#define WINRT_Windows_System_RemoteDesktop_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.RemoteDesktop.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.System.RemoteDesktop.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopLocalAction) consume_Windows_System_RemoteDesktop_Provider_IPerformLocalActionRequestedEventArgs<D>::Action() const
    {
        winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopLocalAction value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IPerformLocalActionRequestedEventArgs)->get_Action(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionInfo<D>::SetConnectionStatus(winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionStatus const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfo)->SetConnectionStatus(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionInfo<D>::SwitchToLocalSession() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfo)->SwitchToLocalSession());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionInfo) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionInfoStatics<D>::GetForLaunchUri(winrt::Windows::Foundation::Uri const& launchUri, winrt::Windows::UI::WindowId const& windowId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfoStatics)->GetForLaunchUri(*(void**)(&launchUri), impl::bind_in(windowId), &result));
        return winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionInfo{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfo<D>::ReportSwitched() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo)->ReportSwitched());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfo<D>::SwitchToLocalSessionRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo)->add_SwitchToLocalSessionRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfo<D>::SwitchToLocalSessionRequested_revoker consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfo<D>::SwitchToLocalSessionRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SwitchToLocalSessionRequested_revoker>(this, SwitchToLocalSessionRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfo<D>::SwitchToLocalSessionRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo)->remove_SwitchToLocalSessionRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfo<D>::PerformLocalActionRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo, winrt::Windows::System::RemoteDesktop::Provider::PerformLocalActionRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo)->add_PerformLocalActionRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfo<D>::PerformLocalActionRequested_revoker consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfo<D>::PerformLocalActionRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo, winrt::Windows::System::RemoteDesktop::Provider::PerformLocalActionRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PerformLocalActionRequested_revoker>(this, PerformLocalActionRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfo<D>::PerformLocalActionRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo)->remove_PerformLocalActionRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfoStatics<D>::IsSwitchSupported() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfoStatics)->IsSwitchSupported(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopConnectionRemoteInfoStatics<D>::GetForLaunchUri(winrt::Windows::Foundation::Uri const& launchUri) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfoStatics)->GetForLaunchUri(*(void**)(&launchUri), &result));
        return winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopInfo<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfo)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopInfo<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfo)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopInfo) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopInfoFactory<D>::CreateInstance(param::hstring const& id, param::hstring const& displayName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfoFactory)->CreateInstance(*(void**)(&id), *(void**)(&displayName), &value));
        return winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopInfo>) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopRegistrarStatics<D>::DesktopInfos() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopRegistrarStatics)->get_DesktopInfos(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopInfo>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_RemoteDesktop_Provider_IRemoteDesktopRegistrarStatics<D>::IsSwitchToLocalSessionEnabled() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopRegistrarStatics)->IsSwitchToLocalSessionEnabled(&result));
        return result;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteDesktop::Provider::IPerformLocalActionRequestedEventArgs> : produce_base<D, winrt::Windows::System::RemoteDesktop::Provider::IPerformLocalActionRequestedEventArgs>
    {
        int32_t __stdcall get_Action(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopLocalAction>(this->shim().Action());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfo> : produce_base<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfo>
    {
        int32_t __stdcall SetConnectionStatus(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetConnectionStatus(*reinterpret_cast<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SwitchToLocalSession() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SwitchToLocalSession();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfoStatics> : produce_base<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfoStatics>
    {
        int32_t __stdcall GetForLaunchUri(void* launchUri, struct struct_Windows_UI_WindowId windowId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionInfo>(this->shim().GetForLaunchUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&launchUri), *reinterpret_cast<winrt::Windows::UI::WindowId const*>(&windowId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo> : produce_base<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo>
    {
        int32_t __stdcall ReportSwitched() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportSwitched();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SwitchToLocalSessionRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SwitchToLocalSessionRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SwitchToLocalSessionRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SwitchToLocalSessionRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PerformLocalActionRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PerformLocalActionRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo, winrt::Windows::System::RemoteDesktop::Provider::PerformLocalActionRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PerformLocalActionRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PerformLocalActionRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfoStatics> : produce_base<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfoStatics>
    {
        int32_t __stdcall IsSwitchSupported(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSwitchSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForLaunchUri(void* launchUri, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo>(this->shim().GetForLaunchUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&launchUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfo> : produce_base<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfo>
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfoFactory> : produce_base<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfoFactory>
    {
        int32_t __stdcall CreateInstance(void* id, void* displayName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopInfo>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<hstring const*>(&displayName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopRegistrarStatics> : produce_base<D, winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopRegistrarStatics>
    {
        int32_t __stdcall get_DesktopInfos(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopInfo>>(this->shim().DesktopInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsSwitchToLocalSessionEnabled(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSwitchToLocalSessionEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::RemoteDesktop::Provider
{
    inline auto RemoteDesktopConnectionInfo::GetForLaunchUri(winrt::Windows::Foundation::Uri const& launchUri, winrt::Windows::UI::WindowId const& windowId)
    {
        return impl::call_factory<RemoteDesktopConnectionInfo, IRemoteDesktopConnectionInfoStatics>([&](IRemoteDesktopConnectionInfoStatics const& f) { return f.GetForLaunchUri(launchUri, windowId); });
    }
    inline auto RemoteDesktopConnectionRemoteInfo::IsSwitchSupported()
    {
        return impl::call_factory_cast<bool(*)(IRemoteDesktopConnectionRemoteInfoStatics const&), RemoteDesktopConnectionRemoteInfo, IRemoteDesktopConnectionRemoteInfoStatics>([](IRemoteDesktopConnectionRemoteInfoStatics const& f) { return f.IsSwitchSupported(); });
    }
    inline auto RemoteDesktopConnectionRemoteInfo::GetForLaunchUri(winrt::Windows::Foundation::Uri const& launchUri)
    {
        return impl::call_factory<RemoteDesktopConnectionRemoteInfo, IRemoteDesktopConnectionRemoteInfoStatics>([&](IRemoteDesktopConnectionRemoteInfoStatics const& f) { return f.GetForLaunchUri(launchUri); });
    }
    inline RemoteDesktopInfo::RemoteDesktopInfo(param::hstring const& id, param::hstring const& displayName) :
        RemoteDesktopInfo(impl::call_factory<RemoteDesktopInfo, IRemoteDesktopInfoFactory>([&](IRemoteDesktopInfoFactory const& f) { return f.CreateInstance(id, displayName); }))
    {
    }
    inline auto RemoteDesktopRegistrar::DesktopInfos()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopInfo>(*)(IRemoteDesktopRegistrarStatics const&), RemoteDesktopRegistrar, IRemoteDesktopRegistrarStatics>([](IRemoteDesktopRegistrarStatics const& f) { return f.DesktopInfos(); });
    }
    inline auto RemoteDesktopRegistrar::IsSwitchToLocalSessionEnabled()
    {
        return impl::call_factory_cast<bool(*)(IRemoteDesktopRegistrarStatics const&), RemoteDesktopRegistrar, IRemoteDesktopRegistrarStatics>([](IRemoteDesktopRegistrarStatics const& f) { return f.IsSwitchToLocalSessionEnabled(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::RemoteDesktop::Provider::IPerformLocalActionRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionInfoStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopConnectionRemoteInfoStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopInfoFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteDesktop::Provider::IRemoteDesktopRegistrarStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteDesktop::Provider::PerformLocalActionRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopConnectionRemoteInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::RemoteDesktop::Provider::RemoteDesktopRegistrar> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
