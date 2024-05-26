// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_AppBroadcasting_H
#define WINRT_Windows_Media_AppBroadcasting_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Media.AppBroadcasting.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_AppBroadcasting_IAppBroadcastingMonitor<D>::IsCurrentAppBroadcasting() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingMonitor)->get_IsCurrentAppBroadcasting(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_AppBroadcasting_IAppBroadcastingMonitor<D>::IsCurrentAppBroadcastingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::AppBroadcasting::AppBroadcastingMonitor, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingMonitor)->add_IsCurrentAppBroadcastingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_AppBroadcasting_IAppBroadcastingMonitor<D>::IsCurrentAppBroadcastingChanged_revoker consume_Windows_Media_AppBroadcasting_IAppBroadcastingMonitor<D>::IsCurrentAppBroadcastingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::AppBroadcasting::AppBroadcastingMonitor, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, IsCurrentAppBroadcastingChanged_revoker>(this, IsCurrentAppBroadcastingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_AppBroadcasting_IAppBroadcastingMonitor<D>::IsCurrentAppBroadcastingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingMonitor)->remove_IsCurrentAppBroadcastingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatus<D>::CanStartBroadcast() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatus)->get_CanStartBroadcast(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AppBroadcasting::AppBroadcastingStatusDetails) consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatus<D>::Details() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatus)->get_Details(&value));
        return winrt::Windows::Media::AppBroadcasting::AppBroadcastingStatusDetails{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsAnyAppBroadcasting() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsAnyAppBroadcasting(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsCaptureResourceUnavailable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsCaptureResourceUnavailable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsGameStreamInProgress() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsGameStreamInProgress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsGpuConstrained() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsGpuConstrained(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsAppInactive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsAppInactive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsBlockedForApp() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsBlockedForApp(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsDisabledByUser() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsDisabledByUser(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsDisabledBySystem() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsDisabledBySystem(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AppBroadcasting::AppBroadcastingStatus) consume_Windows_Media_AppBroadcasting_IAppBroadcastingUI<D>::GetStatus() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUI)->GetStatus(&result));
        return winrt::Windows::Media::AppBroadcasting::AppBroadcastingStatus{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_AppBroadcasting_IAppBroadcastingUI<D>::ShowBroadcastUI() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUI)->ShowBroadcastUI());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AppBroadcasting::AppBroadcastingUI) consume_Windows_Media_AppBroadcasting_IAppBroadcastingUIStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUIStatics)->GetDefault(&result));
        return winrt::Windows::Media::AppBroadcasting::AppBroadcastingUI{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AppBroadcasting::AppBroadcastingUI) consume_Windows_Media_AppBroadcasting_IAppBroadcastingUIStatics<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUIStatics)->GetForUser(*(void**)(&user), &result));
        return winrt::Windows::Media::AppBroadcasting::AppBroadcastingUI{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::AppBroadcasting::IAppBroadcastingMonitor> : produce_base<D, winrt::Windows::Media::AppBroadcasting::IAppBroadcastingMonitor>
    {
        int32_t __stdcall get_IsCurrentAppBroadcasting(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCurrentAppBroadcasting());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_IsCurrentAppBroadcastingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().IsCurrentAppBroadcastingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::AppBroadcasting::AppBroadcastingMonitor, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_IsCurrentAppBroadcastingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsCurrentAppBroadcastingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatus> : produce_base<D, winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatus>
    {
        int32_t __stdcall get_CanStartBroadcast(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanStartBroadcast());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Details(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::AppBroadcasting::AppBroadcastingStatusDetails>(this->shim().Details());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails> : produce_base<D, winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails>
    {
        int32_t __stdcall get_IsAnyAppBroadcasting(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAnyAppBroadcasting());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCaptureResourceUnavailable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCaptureResourceUnavailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsGameStreamInProgress(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsGameStreamInProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsGpuConstrained(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsGpuConstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAppInactive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAppInactive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsBlockedForApp(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBlockedForApp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDisabledByUser(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDisabledByUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDisabledBySystem(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDisabledBySystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUI> : produce_base<D, winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUI>
    {
        int32_t __stdcall GetStatus(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::AppBroadcasting::AppBroadcastingStatus>(this->shim().GetStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowBroadcastUI() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowBroadcastUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUIStatics> : produce_base<D, winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUIStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::AppBroadcasting::AppBroadcastingUI>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::AppBroadcasting::AppBroadcastingUI>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::AppBroadcasting
{
    inline AppBroadcastingMonitor::AppBroadcastingMonitor() :
        AppBroadcastingMonitor(impl::call_factory_cast<AppBroadcastingMonitor(*)(winrt::Windows::Foundation::IActivationFactory const&), AppBroadcastingMonitor>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AppBroadcastingMonitor>(); }))
    {
    }
    inline auto AppBroadcastingUI::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Media::AppBroadcasting::AppBroadcastingUI(*)(IAppBroadcastingUIStatics const&), AppBroadcastingUI, IAppBroadcastingUIStatics>([](IAppBroadcastingUIStatics const& f) { return f.GetDefault(); });
    }
    inline auto AppBroadcastingUI::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<AppBroadcastingUI, IAppBroadcastingUIStatics>([&](IAppBroadcastingUIStatics const& f) { return f.GetForUser(user); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingMonitor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatus> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUIStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::AppBroadcasting::AppBroadcastingMonitor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::AppBroadcasting::AppBroadcastingStatus> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::AppBroadcasting::AppBroadcastingStatusDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::AppBroadcasting::AppBroadcastingUI> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
