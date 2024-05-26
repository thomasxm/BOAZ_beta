// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_WebUI_Core_H
#define WINRT_Windows_UI_WebUI_Core_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.WebUI.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.WebUI.Core.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::Visible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->get_Visible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::Visible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->put_Visible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::Opacity() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->get_Opacity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::Opacity(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->put_Opacity(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::ForegroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->get_ForegroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::ForegroundColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->put_ForegroundColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::BackgroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->get_BackgroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::BackgroundColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->put_BackgroundColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::ClosedDisplayMode() const
    {
        winrt::Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->get_ClosedDisplayMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::ClosedDisplayMode(winrt::Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->put_ClosedDisplayMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::IsOpen() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->get_IsOpen(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::IsOpen(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->put_IsOpen(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::Size() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->get_Size(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::PrimaryCommands() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->get_PrimaryCommands(&value));
        return winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::SecondaryCommands() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->get_SecondaryCommands(&value));
        return winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuOpened(winrt::Windows::UI::WebUI::Core::MenuOpenedEventHandler const& handler) const
    {
        winrt::event_token value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->add_MenuOpened(*(void**)(&handler), put_abi(value)));
        return value;
    }
    template <typename D> typename consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuOpened_revoker consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuOpened(auto_revoke_t, winrt::Windows::UI::WebUI::Core::MenuOpenedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, MenuOpened_revoker>(this, MenuOpened(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuOpened(winrt::event_token const& value) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->remove_MenuOpened(impl::bind_in(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuClosed(winrt::Windows::UI::WebUI::Core::MenuClosedEventHandler const& handler) const
    {
        winrt::event_token value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->add_MenuClosed(*(void**)(&handler), put_abi(value)));
        return value;
    }
    template <typename D> typename consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuClosed_revoker consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuClosed(auto_revoke_t, winrt::Windows::UI::WebUI::Core::MenuClosedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, MenuClosed_revoker>(this, MenuClosed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuClosed(winrt::event_token const& value) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->remove_MenuClosed(impl::bind_in(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::SizeChanged(winrt::Windows::UI::WebUI::Core::SizeChangedEventHandler const& handler) const
    {
        winrt::event_token value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->add_SizeChanged(*(void**)(&handler), put_abi(value)));
        return value;
    }
    template <typename D> typename consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::SizeChanged_revoker consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::SizeChanged(auto_revoke_t, winrt::Windows::UI::WebUI::Core::SizeChangedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, SizeChanged_revoker>(this, SizeChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::SizeChanged(winrt::event_token const& value) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBar)->remove_SizeChanged(impl::bind_in(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_UI_WebUI_Core_IWebUICommandBarBitmapIcon<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBarBitmapIcon<D>::Uri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon)->put_Uri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon) consume_Windows_UI_WebUI_Core_IWebUICommandBarBitmapIconFactory<D>::Create(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory)->Create(*(void**)(&uri), &instance));
        return winrt::Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton<D>::Text(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton)->put_Text(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton<D>::ItemInvoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton, winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton)->add_ItemInvoked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton<D>::ItemInvoked_revoker consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton<D>::ItemInvoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton, winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ItemInvoked_revoker>(this, ItemInvoked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton<D>::ItemInvoked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton)->remove_ItemInvoked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::Enabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->get_Enabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::Enabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->put_Enabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::Label() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->get_Label(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::Label(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->put_Label(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::IsToggleButton() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->get_IsToggleButton(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::IsToggleButton(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->put_IsToggleButton(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::IsChecked() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->get_IsChecked(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::IsChecked(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->put_IsChecked(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon) consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::Icon() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->get_Icon(&value));
        return winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::Icon(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->put_Icon(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::ItemInvoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WebUI::Core::WebUICommandBarIconButton, winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->add_ItemInvoked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::ItemInvoked_revoker consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::ItemInvoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WebUI::Core::WebUICommandBarIconButton, winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ItemInvoked_revoker>(this, ItemInvoked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::ItemInvoked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->remove_ItemInvoked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WebUI_Core_IWebUICommandBarItemInvokedEventArgs<D>::IsPrimaryCommand() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs)->get_IsPrimaryCommand(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_WebUI_Core_IWebUICommandBarSizeChangedEventArgs<D>::Size() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs)->get_Size(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WebUI::Core::WebUICommandBar) consume_Windows_UI_WebUI_Core_IWebUICommandBarStatics<D>::GetForCurrentView() const
    {
        void* commandBar{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarStatics)->GetForCurrentView(&commandBar));
        return winrt::Windows::UI::WebUI::Core::WebUICommandBar{ commandBar, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_WebUI_Core_IWebUICommandBarSymbolIcon<D>::Symbol() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon)->get_Symbol(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WebUI_Core_IWebUICommandBarSymbolIcon<D>::Symbol(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon)->put_Symbol(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon) consume_Windows_UI_WebUI_Core_IWebUICommandBarSymbolIconFactory<D>::Create(param::hstring const& symbol) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory)->Create(*(void**)(&symbol), &instance));
        return winrt::Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon{ instance, take_ownership_from_abi };
    }
    template <typename H> struct delegate<winrt::Windows::UI::WebUI::Core::MenuClosedEventHandler, H> final : implements_delegate<winrt::Windows::UI::WebUI::Core::MenuClosedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::WebUI::Core::MenuClosedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke() noexcept final try
        {
            (*this)();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::WebUI::Core::MenuOpenedEventHandler, H> final : implements_delegate<winrt::Windows::UI::WebUI::Core::MenuOpenedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::WebUI::Core::MenuOpenedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke() noexcept final try
        {
            (*this)();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::WebUI::Core::SizeChangedEventHandler, H> final : implements_delegate<winrt::Windows::UI::WebUI::Core::SizeChangedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::WebUI::Core::SizeChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* eventArgs) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::UI::WebUI::Core::WebUICommandBarSizeChangedEventArgs const*>(&eventArgs));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBar> : produce_base<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBar>
    {
        int32_t __stdcall get_Visible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Visible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Visible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Visible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Opacity(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Opacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Opacity(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Opacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ForegroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().ForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ForegroundColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ForegroundColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BackgroundColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedDisplayMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode>(this->shim().ClosedDisplayMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClosedDisplayMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClosedDisplayMode(*reinterpret_cast<winrt::Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOpen(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsOpen(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsOpen(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Size(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PrimaryCommands(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>>(this->shim().PrimaryCommands());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SecondaryCommands(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>>(this->shim().SecondaryCommands());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_MenuOpened(void* handler, winrt::event_token* value) noexcept final try
        {
            zero_abi<winrt::event_token>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::event_token>(this->shim().MenuOpened(*reinterpret_cast<winrt::Windows::UI::WebUI::Core::MenuOpenedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MenuOpened(winrt::event_token value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MenuOpened(*reinterpret_cast<winrt::event_token const*>(&value));
            return 0;
        }
        int32_t __stdcall add_MenuClosed(void* handler, winrt::event_token* value) noexcept final try
        {
            zero_abi<winrt::event_token>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::event_token>(this->shim().MenuClosed(*reinterpret_cast<winrt::Windows::UI::WebUI::Core::MenuClosedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MenuClosed(winrt::event_token value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MenuClosed(*reinterpret_cast<winrt::event_token const*>(&value));
            return 0;
        }
        int32_t __stdcall add_SizeChanged(void* handler, winrt::event_token* value) noexcept final try
        {
            zero_abi<winrt::event_token>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::event_token>(this->shim().SizeChanged(*reinterpret_cast<winrt::Windows::UI::WebUI::Core::SizeChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SizeChanged(winrt::event_token value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SizeChanged(*reinterpret_cast<winrt::event_token const*>(&value));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon> : produce_base<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Uri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Uri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory> : produce_base<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory>
    {
        int32_t __stdcall Create(void* uri, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon>(this->shim().Create(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton> : produce_base<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton>
    {
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Text(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ItemInvoked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ItemInvoked(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton, winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ItemInvoked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ItemInvoked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement> : produce_base<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>
    {
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon> : produce_base<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon>
    {
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton> : produce_base<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton>
    {
        int32_t __stdcall get_Enabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Enabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Label(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Label(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Label(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsToggleButton(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsToggleButton());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsToggleButton(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsToggleButton(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsChecked(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsChecked());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsChecked(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsChecked(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Icon(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon>(this->shim().Icon());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Icon(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Icon(*reinterpret_cast<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ItemInvoked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ItemInvoked(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WebUI::Core::WebUICommandBarIconButton, winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ItemInvoked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ItemInvoked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs> : produce_base<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs>
    {
        int32_t __stdcall get_IsPrimaryCommand(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPrimaryCommand());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs> : produce_base<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs>
    {
        int32_t __stdcall get_Size(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarStatics> : produce_base<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarStatics>
    {
        int32_t __stdcall GetForCurrentView(void** commandBar) noexcept final try
        {
            clear_abi(commandBar);
            typename D::abi_guard guard(this->shim());
            *commandBar = detach_from<winrt::Windows::UI::WebUI::Core::WebUICommandBar>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon> : produce_base<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon>
    {
        int32_t __stdcall get_Symbol(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Symbol());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Symbol(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Symbol(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory> : produce_base<D, winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory>
    {
        int32_t __stdcall Create(void* symbol, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon>(this->shim().Create(*reinterpret_cast<hstring const*>(&symbol)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::WebUI::Core
{
    inline auto WebUICommandBar::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::WebUI::Core::WebUICommandBar(*)(IWebUICommandBarStatics const&), WebUICommandBar, IWebUICommandBarStatics>([](IWebUICommandBarStatics const& f) { return f.GetForCurrentView(); });
    }
    inline WebUICommandBarBitmapIcon::WebUICommandBarBitmapIcon() :
        WebUICommandBarBitmapIcon(impl::call_factory_cast<WebUICommandBarBitmapIcon(*)(winrt::Windows::Foundation::IActivationFactory const&), WebUICommandBarBitmapIcon>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WebUICommandBarBitmapIcon>(); }))
    {
    }
    inline WebUICommandBarBitmapIcon::WebUICommandBarBitmapIcon(winrt::Windows::Foundation::Uri const& uri) :
        WebUICommandBarBitmapIcon(impl::call_factory<WebUICommandBarBitmapIcon, IWebUICommandBarBitmapIconFactory>([&](IWebUICommandBarBitmapIconFactory const& f) { return f.Create(uri); }))
    {
    }
    inline WebUICommandBarConfirmationButton::WebUICommandBarConfirmationButton() :
        WebUICommandBarConfirmationButton(impl::call_factory_cast<WebUICommandBarConfirmationButton(*)(winrt::Windows::Foundation::IActivationFactory const&), WebUICommandBarConfirmationButton>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WebUICommandBarConfirmationButton>(); }))
    {
    }
    inline WebUICommandBarIconButton::WebUICommandBarIconButton() :
        WebUICommandBarIconButton(impl::call_factory_cast<WebUICommandBarIconButton(*)(winrt::Windows::Foundation::IActivationFactory const&), WebUICommandBarIconButton>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WebUICommandBarIconButton>(); }))
    {
    }
    inline WebUICommandBarSymbolIcon::WebUICommandBarSymbolIcon() :
        WebUICommandBarSymbolIcon(impl::call_factory_cast<WebUICommandBarSymbolIcon(*)(winrt::Windows::Foundation::IActivationFactory const&), WebUICommandBarSymbolIcon>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WebUICommandBarSymbolIcon>(); }))
    {
    }
    inline WebUICommandBarSymbolIcon::WebUICommandBarSymbolIcon(param::hstring const& symbol) :
        WebUICommandBarSymbolIcon(impl::call_factory<WebUICommandBarSymbolIcon, IWebUICommandBarSymbolIconFactory>([&](IWebUICommandBarSymbolIconFactory const& f) { return f.Create(symbol); }))
    {
    }
    template <typename L> MenuClosedEventHandler::MenuClosedEventHandler(L handler) :
        MenuClosedEventHandler(impl::make_delegate<MenuClosedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> MenuClosedEventHandler::MenuClosedEventHandler(F* handler) :
        MenuClosedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> MenuClosedEventHandler::MenuClosedEventHandler(O* object, M method) :
        MenuClosedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> MenuClosedEventHandler::MenuClosedEventHandler(com_ptr<O>&& object, M method) :
        MenuClosedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> MenuClosedEventHandler::MenuClosedEventHandler(weak_ref<O>&& object, M method) :
        MenuClosedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto MenuClosedEventHandler::operator()() const
    {
        check_hresult((*(impl::abi_t<MenuClosedEventHandler>**)this)->Invoke());
    }
    template <typename L> MenuOpenedEventHandler::MenuOpenedEventHandler(L handler) :
        MenuOpenedEventHandler(impl::make_delegate<MenuOpenedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> MenuOpenedEventHandler::MenuOpenedEventHandler(F* handler) :
        MenuOpenedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> MenuOpenedEventHandler::MenuOpenedEventHandler(O* object, M method) :
        MenuOpenedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> MenuOpenedEventHandler::MenuOpenedEventHandler(com_ptr<O>&& object, M method) :
        MenuOpenedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> MenuOpenedEventHandler::MenuOpenedEventHandler(weak_ref<O>&& object, M method) :
        MenuOpenedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto MenuOpenedEventHandler::operator()() const
    {
        check_hresult((*(impl::abi_t<MenuOpenedEventHandler>**)this)->Invoke());
    }
    template <typename L> SizeChangedEventHandler::SizeChangedEventHandler(L handler) :
        SizeChangedEventHandler(impl::make_delegate<SizeChangedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> SizeChangedEventHandler::SizeChangedEventHandler(F* handler) :
        SizeChangedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> SizeChangedEventHandler::SizeChangedEventHandler(O* object, M method) :
        SizeChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> SizeChangedEventHandler::SizeChangedEventHandler(com_ptr<O>&& object, M method) :
        SizeChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> SizeChangedEventHandler::SizeChangedEventHandler(weak_ref<O>&& object, M method) :
        SizeChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto SizeChangedEventHandler::operator()(winrt::Windows::UI::WebUI::Core::WebUICommandBarSizeChangedEventArgs const& eventArgs) const
    {
        check_hresult((*(impl::abi_t<SizeChangedEventHandler>**)this)->Invoke(*(void**)(&eventArgs)));
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBarIconButton> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBarSizeChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
