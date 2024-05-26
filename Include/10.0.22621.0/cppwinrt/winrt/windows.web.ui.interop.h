// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_UI_Interop_H
#define WINRT_Windows_Web_UI_Interop_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Web.UI.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.Web.UI.2.h"
#include "winrt/impl/Windows.Web.UI.Interop.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreAcceleratorKeyEventType) consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs<D>::EventType() const
    {
        winrt::Windows::UI::Core::CoreAcceleratorKeyEventType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs)->get_EventType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs<D>::VirtualKey() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs)->get_VirtualKey(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CorePhysicalKeyStatus) consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs<D>::KeyStatus() const
    {
        winrt::Windows::UI::Core::CorePhysicalKeyStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs)->get_KeyStatus(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyRoutingStage) consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs<D>::RoutingStage() const
    {
        winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyRoutingStage value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs)->get_RoutingStage(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusReason) consume_Windows_Web_UI_Interop_IWebViewControlMoveFocusRequestedEventArgs<D>::Reason() const
    {
        winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::ProcessId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlProcess)->get_ProcessId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::EnterpriseId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlProcess)->get_EnterpriseId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::IsPrivateNetworkClientServerCapabilityEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlProcess)->get_IsPrivateNetworkClientServerCapabilityEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Web::UI::Interop::WebViewControl>) consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::CreateWebViewControlAsync(int64_t hostWindowHandle, winrt::Windows::Foundation::Rect const& bounds) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlProcess)->CreateWebViewControlAsync(hostWindowHandle, impl::bind_in(bounds), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Web::UI::Interop::WebViewControl>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::UI::Interop::WebViewControl>) consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::GetWebViewControls() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlProcess)->GetWebViewControls(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::UI::Interop::WebViewControl>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::Terminate() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlProcess)->Terminate());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::ProcessExited(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControlProcess, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlProcess)->add_ProcessExited(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::ProcessExited_revoker consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::ProcessExited(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControlProcess, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ProcessExited_revoker>(this, ProcessExited(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::ProcessExited(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlProcess)->remove_ProcessExited(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::UI::Interop::WebViewControlProcess) consume_Windows_Web_UI_Interop_IWebViewControlProcessFactory<D>::CreateWithOptions(winrt::Windows::Web::UI::Interop::WebViewControlProcessOptions const& processOptions) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlProcessFactory)->CreateWithOptions(*(void**)(&processOptions), &result));
        return winrt::Windows::Web::UI::Interop::WebViewControlProcess{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlProcessOptions<D>::EnterpriseId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions)->put_EnterpriseId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_UI_Interop_IWebViewControlProcessOptions<D>::EnterpriseId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions)->get_EnterpriseId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlProcessOptions<D>::PrivateNetworkClientServerCapability(winrt::Windows::Web::UI::Interop::WebViewControlProcessCapabilityState const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions)->put_PrivateNetworkClientServerCapability(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::UI::Interop::WebViewControlProcessCapabilityState) consume_Windows_Web_UI_Interop_IWebViewControlProcessOptions<D>::PrivateNetworkClientServerCapability() const
    {
        winrt::Windows::Web::UI::Interop::WebViewControlProcessCapabilityState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions)->get_PrivateNetworkClientServerCapability(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::UI::Interop::WebViewControlProcess) consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::Process() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite)->get_Process(&value));
        return winrt::Windows::Web::UI::Interop::WebViewControlProcess{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::Scale(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite)->put_Scale(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::Scale() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite)->get_Scale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::Bounds(winrt::Windows::Foundation::Rect const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite)->put_Bounds(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::Bounds() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite)->get_Bounds(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::IsVisible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite)->put_IsVisible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::IsVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite)->get_IsVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::Close() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite)->Close());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::MoveFocus(winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusReason const& reason) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite)->MoveFocus(static_cast<int32_t>(reason)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::MoveFocusRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite)->add_MoveFocusRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::MoveFocusRequested_revoker consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::MoveFocusRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, MoveFocusRequested_revoker>(this, MoveFocusRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::MoveFocusRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite)->remove_MoveFocusRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::AcceleratorKeyPressed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite)->add_AcceleratorKeyPressed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::AcceleratorKeyPressed_revoker consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::AcceleratorKeyPressed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AcceleratorKeyPressed_revoker>(this, AcceleratorKeyPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::AcceleratorKeyPressed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite)->remove_AcceleratorKeyPressed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::GotFocus(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite2)->add_GotFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::GotFocus_revoker consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::GotFocus(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::GotFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite2)->remove_GotFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::LostFocus(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite2)->add_LostFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::LostFocus_revoker consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::LostFocus(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, LostFocus_revoker>(this, LostFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::LostFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::Interop::IWebViewControlSite2)->remove_LostFocus(impl::bind_in(token));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs> : produce_base<D, winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs>
    {
        int32_t __stdcall get_EventType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreAcceleratorKeyEventType>(this->shim().EventType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VirtualKey(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().VirtualKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyStatus(struct struct_Windows_UI_Core_CorePhysicalKeyStatus* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Core::CorePhysicalKeyStatus>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CorePhysicalKeyStatus>(this->shim().KeyStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoutingStage(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyRoutingStage>(this->shim().RoutingStage());
            return 0;
        }
        catch (...) { return to_hresult(); }
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs> : produce_base<D, winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::Interop::IWebViewControlProcess> : produce_base<D, winrt::Windows::Web::UI::Interop::IWebViewControlProcess>
    {
        int32_t __stdcall get_ProcessId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ProcessId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnterpriseId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EnterpriseId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPrivateNetworkClientServerCapabilityEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPrivateNetworkClientServerCapabilityEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWebViewControlAsync(int64_t hostWindowHandle, winrt::Windows::Foundation::Rect bounds, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Web::UI::Interop::WebViewControl>>(this->shim().CreateWebViewControlAsync(hostWindowHandle, *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&bounds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetWebViewControls(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::UI::Interop::WebViewControl>>(this->shim().GetWebViewControls());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Terminate() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Terminate();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ProcessExited(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ProcessExited(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControlProcess, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ProcessExited(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessExited(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::Interop::IWebViewControlProcessFactory> : produce_base<D, winrt::Windows::Web::UI::Interop::IWebViewControlProcessFactory>
    {
        int32_t __stdcall CreateWithOptions(void* processOptions, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Web::UI::Interop::WebViewControlProcess>(this->shim().CreateWithOptions(*reinterpret_cast<winrt::Windows::Web::UI::Interop::WebViewControlProcessOptions const*>(&processOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions> : produce_base<D, winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions>
    {
        int32_t __stdcall put_EnterpriseId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnterpriseId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnterpriseId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EnterpriseId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PrivateNetworkClientServerCapability(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrivateNetworkClientServerCapability(*reinterpret_cast<winrt::Windows::Web::UI::Interop::WebViewControlProcessCapabilityState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PrivateNetworkClientServerCapability(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::UI::Interop::WebViewControlProcessCapabilityState>(this->shim().PrivateNetworkClientServerCapability());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::Interop::IWebViewControlSite> : produce_base<D, winrt::Windows::Web::UI::Interop::IWebViewControlSite>
    {
        int32_t __stdcall get_Process(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::UI::Interop::WebViewControlProcess>(this->shim().Process());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Scale(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Scale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Scale(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Bounds(winrt::Windows::Foundation::Rect value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Bounds(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bounds(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().Bounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsVisible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Close() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Close();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveFocus(int32_t reason) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MoveFocus(*reinterpret_cast<winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusReason const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_MoveFocusRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MoveFocusRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MoveFocusRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MoveFocusRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AcceleratorKeyPressed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AcceleratorKeyPressed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AcceleratorKeyPressed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AcceleratorKeyPressed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::Interop::IWebViewControlSite2> : produce_base<D, winrt::Windows::Web::UI::Interop::IWebViewControlSite2>
    {
        int32_t __stdcall add_GotFocus(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_GotFocus(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GotFocus(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_LostFocus(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().LostFocus(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::Interop::WebViewControl, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LostFocus(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LostFocus(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Web::UI::Interop
{
    inline WebViewControlProcess::WebViewControlProcess() :
        WebViewControlProcess(impl::call_factory_cast<WebViewControlProcess(*)(winrt::Windows::Foundation::IActivationFactory const&), WebViewControlProcess>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WebViewControlProcess>(); }))
    {
    }
    inline WebViewControlProcess::WebViewControlProcess(winrt::Windows::Web::UI::Interop::WebViewControlProcessOptions const& processOptions) :
        WebViewControlProcess(impl::call_factory<WebViewControlProcess, IWebViewControlProcessFactory>([&](IWebViewControlProcessFactory const& f) { return f.CreateWithOptions(processOptions); }))
    {
    }
    inline WebViewControlProcessOptions::WebViewControlProcessOptions() :
        WebViewControlProcessOptions(impl::call_factory_cast<WebViewControlProcessOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), WebViewControlProcessOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WebViewControlProcessOptions>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlProcess> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlProcessFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlSite> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlSite2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::Interop::WebViewControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::Interop::WebViewControlProcess> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::Interop::WebViewControlProcessOptions> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
