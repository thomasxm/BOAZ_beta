// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Core_Preview_H
#define WINRT_Windows_UI_Core_Preview_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Core.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.WindowManagement.2.h"
#include "winrt/impl/Windows.UI.Core.Preview.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Core_Preview_ICoreAppWindowPreviewStatics<D>::GetIdFromWindow(winrt::Windows::UI::WindowManagement::AppWindow const& window) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics)->GetIdFromWindow(*(void**)(&window), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_Preview_ISystemNavigationCloseRequestedPreviewEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_ISystemNavigationCloseRequestedPreviewEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_UI_Core_Preview_ISystemNavigationCloseRequestedPreviewEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreview<D>::CloseRequested(winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreview)->add_CloseRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreview<D>::CloseRequested_revoker consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreview<D>::CloseRequested(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CloseRequested_revoker>(this, CloseRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreview<D>::CloseRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreview)->remove_CloseRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::Preview::SystemNavigationManagerPreview) consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreviewStatics<D>::GetForCurrentView() const
    {
        void* loader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics)->GetForCurrentView(&loader));
        return winrt::Windows::UI::Core::Preview::SystemNavigationManagerPreview{ loader, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::Preview::ICoreAppWindowPreview> : produce_base<D, winrt::Windows::UI::Core::Preview::ICoreAppWindowPreview>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics> : produce_base<D, winrt::Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics>
    {
        int32_t __stdcall GetIdFromWindow(void* window, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().GetIdFromWindow(*reinterpret_cast<winrt::Windows::UI::WindowManagement::AppWindow const*>(&window)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs> : produce_base<D, winrt::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs>
    {
        int32_t __stdcall get_Handled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Handled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreview> : produce_base<D, winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreview>
    {
        int32_t __stdcall add_CloseRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CloseRequested(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CloseRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CloseRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics> : produce_base<D, winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics>
    {
        int32_t __stdcall GetForCurrentView(void** loader) noexcept final try
        {
            clear_abi(loader);
            typename D::abi_guard guard(this->shim());
            *loader = detach_from<winrt::Windows::UI::Core::Preview::SystemNavigationManagerPreview>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Core::Preview
{
    inline auto CoreAppWindowPreview::GetIdFromWindow(winrt::Windows::UI::WindowManagement::AppWindow const& window)
    {
        return impl::call_factory<CoreAppWindowPreview, ICoreAppWindowPreviewStatics>([&](ICoreAppWindowPreviewStatics const& f) { return f.GetIdFromWindow(window); });
    }
    inline auto SystemNavigationManagerPreview::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Core::Preview::SystemNavigationManagerPreview(*)(ISystemNavigationManagerPreviewStatics const&), SystemNavigationManagerPreview, ISystemNavigationManagerPreviewStatics>([](ISystemNavigationManagerPreviewStatics const& f) { return f.GetForCurrentView(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Core::Preview::ICoreAppWindowPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::CoreAppWindowPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::Preview::SystemNavigationManagerPreview> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
