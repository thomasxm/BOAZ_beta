// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Input_H
#define WINRT_Windows_UI_Xaml_Input_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Xaml.h"
#include "winrt/impl/Windows.Devices.Input.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.2.h"
#include "winrt/impl/Windows.UI.Xaml.Input.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Input_IAccessKeyDisplayRequestedEventArgs<D>::PressedKeys() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs)->get_PressedKeys(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IAccessKeyInvokedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IAccessKeyInvokedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics<D>::IsDisplayModeEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics)->get_IsDisplayModeEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics<D>::IsDisplayModeEnabledChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics)->add_IsDisplayModeEnabledChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics<D>::IsDisplayModeEnabledChanged_revoker consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics<D>::IsDisplayModeEnabledChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, IsDisplayModeEnabledChanged_revoker>(this, IsDisplayModeEnabledChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics<D>::IsDisplayModeEnabledChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics)->remove_IsDisplayModeEnabledChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics<D>::ExitDisplayMode() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics)->ExitDisplayMode());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics2<D>::AreKeyTipsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics2)->get_AreKeyTipsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics2<D>::AreKeyTipsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics2)->put_AreKeyTipsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Input_ICanExecuteRequestedEventArgs<D>::Parameter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs)->get_Parameter(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_ICanExecuteRequestedEventArgs<D>::CanExecute() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs)->get_CanExecute(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_ICanExecuteRequestedEventArgs<D>::CanExecute(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs)->put_CanExecute(value));
    }
    template <typename D> WINRT_IMPL_AUTO(char16_t) consume_Windows_UI_Xaml_Input_ICharacterReceivedRoutedEventArgs<D>::Character() const
    {
        char16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs)->get_Character(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CorePhysicalKeyStatus) consume_Windows_UI_Xaml_Input_ICharacterReceivedRoutedEventArgs<D>::KeyStatus() const
    {
        winrt::Windows::UI::Core::CorePhysicalKeyStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs)->get_KeyStatus(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_ICharacterReceivedRoutedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_ICharacterReceivedRoutedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Input_ICommand<D>::CanExecuteChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ICommand)->add_CanExecuteChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Input_ICommand<D>::CanExecuteChanged_revoker consume_Windows_UI_Xaml_Input_ICommand<D>::CanExecuteChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, CanExecuteChanged_revoker>(this, CanExecuteChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_ICommand<D>::CanExecuteChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ICommand)->remove_CanExecuteChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_ICommand<D>::CanExecute(winrt::Windows::Foundation::IInspectable const& parameter) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ICommand)->CanExecute(*(void**)(&parameter), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_ICommand<D>::Execute(winrt::Windows::Foundation::IInspectable const& parameter) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ICommand)->Execute(*(void**)(&parameter)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IContextRequestedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IContextRequestedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IContextRequestedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IContextRequestedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IContextRequestedEventArgs<D>::TryGetPosition(winrt::Windows::UI::Xaml::UIElement const& relativeTo, winrt::Windows::Foundation::Point& point) const
    {
        bool returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IContextRequestedEventArgs)->TryGetPosition(*(void**)(&relativeTo), impl::bind_out(point), &returnValue));
        return returnValue;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Xaml_Input_IDoubleTappedRoutedEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IDoubleTappedRoutedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IDoubleTappedRoutedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_Input_IDoubleTappedRoutedEventArgs<D>::GetPosition(winrt::Windows::UI::Xaml::UIElement const& relativeTo) const
    {
        winrt::Windows::Foundation::Point result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs)->GetPosition(*(void**)(&relativeTo), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Input_IExecuteRequestedEventArgs<D>::Parameter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IExecuteRequestedEventArgs)->get_Parameter(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::SearchRoot() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFindNextElementOptions)->get_SearchRoot(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::SearchRoot(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFindNextElementOptions)->put_SearchRoot(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::ExclusionRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFindNextElementOptions)->get_ExclusionRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::ExclusionRect(winrt::Windows::Foundation::Rect const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFindNextElementOptions)->put_ExclusionRect(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::HintRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFindNextElementOptions)->get_HintRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::HintRect(winrt::Windows::Foundation::Rect const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFindNextElementOptions)->put_HintRect(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride) consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::XYFocusNavigationStrategyOverride() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFindNextElementOptions)->get_XYFocusNavigationStrategyOverride(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::XYFocusNavigationStrategyOverride(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFindNextElementOptions)->put_XYFocusNavigationStrategyOverride(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Input_IFocusManagerGotFocusEventArgs<D>::NewFocusedElement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs)->get_NewFocusedElement(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_UI_Xaml_Input_IFocusManagerGotFocusEventArgs<D>::CorrelationId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs)->get_CorrelationId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Input_IFocusManagerLostFocusEventArgs<D>::OldFocusedElement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs)->get_OldFocusedElement(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_UI_Xaml_Input_IFocusManagerLostFocusEventArgs<D>::CorrelationId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs)->get_CorrelationId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Input_IFocusManagerStatics<D>::GetFocusedElement() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics)->GetFocusedElement(&result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IFocusManagerStatics2<D>::TryMoveFocus(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics2)->TryMoveFocus(static_cast<int32_t>(focusNavigationDirection), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Input_IFocusManagerStatics3<D>::FindNextFocusableElement(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics3)->FindNextFocusableElement(static_cast<int32_t>(focusNavigationDirection), &result));
        return winrt::Windows::UI::Xaml::UIElement{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Input_IFocusManagerStatics3<D>::FindNextFocusableElement(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, winrt::Windows::Foundation::Rect const& hintRect) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics3)->FindNextFocusableElementWithHint(static_cast<int32_t>(focusNavigationDirection), impl::bind_in(hintRect), &result));
        return winrt::Windows::UI::Xaml::UIElement{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IFocusManagerStatics4<D>::TryMoveFocus(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, winrt::Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics4)->TryMoveFocusWithOptions(static_cast<int32_t>(focusNavigationDirection), *(void**)(&focusNavigationOptions), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Input_IFocusManagerStatics4<D>::FindNextElement(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics4)->FindNextElement(static_cast<int32_t>(focusNavigationDirection), &result));
        return winrt::Windows::UI::Xaml::DependencyObject{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Input_IFocusManagerStatics4<D>::FindFirstFocusableElement(winrt::Windows::UI::Xaml::DependencyObject const& searchScope) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics4)->FindFirstFocusableElement(*(void**)(&searchScope), &result));
        return winrt::Windows::UI::Xaml::DependencyObject{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Input_IFocusManagerStatics4<D>::FindLastFocusableElement(winrt::Windows::UI::Xaml::DependencyObject const& searchScope) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics4)->FindLastFocusableElement(*(void**)(&searchScope), &result));
        return winrt::Windows::UI::Xaml::DependencyObject{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Input_IFocusManagerStatics4<D>::FindNextElement(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, winrt::Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics4)->FindNextElementWithOptions(static_cast<int32_t>(focusNavigationDirection), *(void**)(&focusNavigationOptions), &result));
        return winrt::Windows::UI::Xaml::DependencyObject{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Input::FocusMovementResult>) consume_Windows_UI_Xaml_Input_IFocusManagerStatics5<D>::TryFocusAsync(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FocusState const& value) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics5)->TryFocusAsync(*(void**)(&element), static_cast<int32_t>(value), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Input::FocusMovementResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Input::FocusMovementResult>) consume_Windows_UI_Xaml_Input_IFocusManagerStatics5<D>::TryMoveFocusAsync(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics5)->TryMoveFocusAsync(static_cast<int32_t>(focusNavigationDirection), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Input::FocusMovementResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Input::FocusMovementResult>) consume_Windows_UI_Xaml_Input_IFocusManagerStatics5<D>::TryMoveFocusAsync(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, winrt::Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics5)->TryMoveFocusWithOptionsAsync(static_cast<int32_t>(focusNavigationDirection), *(void**)(&focusNavigationOptions), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Input::FocusMovementResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GotFocus(winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6)->add_GotFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GotFocus_revoker consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GotFocus(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GotFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6)->remove_GotFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LostFocus(winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6)->add_LostFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LostFocus_revoker consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LostFocus(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, LostFocus_revoker>(this, LostFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LostFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6)->remove_LostFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GettingFocus(winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6)->add_GettingFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GettingFocus_revoker consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GettingFocus(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, GettingFocus_revoker>(this, GettingFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GettingFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6)->remove_GettingFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LosingFocus(winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6)->add_LosingFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LosingFocus_revoker consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LosingFocus(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, LosingFocus_revoker>(this, LosingFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LosingFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6)->remove_LosingFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Input_IFocusManagerStatics7<D>::GetFocusedElement(winrt::Windows::UI::Xaml::XamlRoot const& xamlRoot) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusManagerStatics7)->GetFocusedElement(*(void**)(&xamlRoot), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IFocusMovementResult<D>::Succeeded() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IFocusMovementResult)->get_Succeeded(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::OldFocusedElement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_OldFocusedElement(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::NewFocusedElement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_NewFocusedElement(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::NewFocusedElement(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs)->put_NewFocusedElement(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FocusState) consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::FocusState() const
    {
        winrt::Windows::UI::Xaml::FocusState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_FocusState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection) consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::Direction() const
    {
        winrt::Windows::UI::Xaml::Input::FocusNavigationDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_Direction(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::FocusInputDeviceKind) consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::InputDevice() const
    {
        winrt::Windows::UI::Xaml::Input::FocusInputDeviceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_InputDevice(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::Cancel() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_Cancel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::Cancel(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs)->put_Cancel(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs2<D>::TryCancel() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs2)->TryCancel(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs2<D>::TrySetNewFocusedElement(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs2)->TrySetNewFocusedElement(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs3<D>::CorrelationId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs3)->get_CorrelationId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Xaml_Input_IHoldingRoutedEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IHoldingRoutedEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::HoldingState) consume_Windows_UI_Xaml_Input_IHoldingRoutedEventArgs<D>::HoldingState() const
    {
        winrt::Windows::UI::Input::HoldingState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IHoldingRoutedEventArgs)->get_HoldingState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IHoldingRoutedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IHoldingRoutedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IHoldingRoutedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IHoldingRoutedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_Input_IHoldingRoutedEventArgs<D>::GetPosition(winrt::Windows::UI::Xaml::UIElement const& relativeTo) const
    {
        winrt::Windows::Foundation::Point result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IHoldingRoutedEventArgs)->GetPosition(*(void**)(&relativeTo), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Input_IInertiaExpansionBehavior<D>::DesiredDeceleration() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInertiaExpansionBehavior)->get_DesiredDeceleration(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IInertiaExpansionBehavior<D>::DesiredDeceleration(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInertiaExpansionBehavior)->put_DesiredDeceleration(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Input_IInertiaExpansionBehavior<D>::DesiredExpansion() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInertiaExpansionBehavior)->get_DesiredExpansion(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IInertiaExpansionBehavior<D>::DesiredExpansion(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInertiaExpansionBehavior)->put_DesiredExpansion(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Input_IInertiaRotationBehavior<D>::DesiredDeceleration() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInertiaRotationBehavior)->get_DesiredDeceleration(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IInertiaRotationBehavior<D>::DesiredDeceleration(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInertiaRotationBehavior)->put_DesiredDeceleration(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Input_IInertiaRotationBehavior<D>::DesiredRotation() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInertiaRotationBehavior)->get_DesiredRotation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IInertiaRotationBehavior<D>::DesiredRotation(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInertiaRotationBehavior)->put_DesiredRotation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Input_IInertiaTranslationBehavior<D>::DesiredDeceleration() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInertiaTranslationBehavior)->get_DesiredDeceleration(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IInertiaTranslationBehavior<D>::DesiredDeceleration(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInertiaTranslationBehavior)->put_DesiredDeceleration(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Input_IInertiaTranslationBehavior<D>::DesiredDisplacement() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInertiaTranslationBehavior)->get_DesiredDisplacement(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IInertiaTranslationBehavior<D>::DesiredDisplacement(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInertiaTranslationBehavior)->put_DesiredDisplacement(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Input::InputScopeName>) consume_Windows_UI_Xaml_Input_IInputScope<D>::Names() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInputScope)->get_Names(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Input::InputScopeName>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::InputScopeNameValue) consume_Windows_UI_Xaml_Input_IInputScopeName<D>::NameValue() const
    {
        winrt::Windows::UI::Xaml::Input::InputScopeNameValue value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInputScopeName)->get_NameValue(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IInputScopeName<D>::NameValue(winrt::Windows::UI::Xaml::Input::InputScopeNameValue const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInputScopeName)->put_NameValue(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::InputScopeName) consume_Windows_UI_Xaml_Input_IInputScopeNameFactory<D>::CreateInstance(winrt::Windows::UI::Xaml::Input::InputScopeNameValue const& nameValue) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IInputScopeNameFactory)->CreateInstance(static_cast<int32_t>(nameValue), &value));
        return winrt::Windows::UI::Xaml::Input::InputScopeName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs<D>::Key() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs)->get_Key(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CorePhysicalKeyStatus) consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs<D>::KeyStatus() const
    {
        winrt::Windows::UI::Core::CorePhysicalKeyStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs)->get_KeyStatus(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs2<D>::OriginalKey() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs2)->get_OriginalKey(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs3<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs3)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Key() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator)->get_Key(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Key(winrt::Windows::System::VirtualKey const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator)->put_Key(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKeyModifiers) consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Modifiers() const
    {
        winrt::Windows::System::VirtualKeyModifiers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator)->get_Modifiers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Modifiers(winrt::Windows::System::VirtualKeyModifiers const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator)->put_Modifiers(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::ScopeOwner() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator)->get_ScopeOwner(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::ScopeOwner(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator)->put_ScopeOwner(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Invoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator, winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator)->add_Invoked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Invoked_revoker consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Invoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator, winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Invoked_revoker>(this, Invoked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Invoked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator)->remove_Invoked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::KeyboardAccelerator) consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Input::KeyboardAccelerator{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorInvokedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorInvokedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorInvokedEventArgs<D>::Element() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs)->get_Element(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::KeyboardAccelerator) consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorInvokedEventArgs2<D>::KeyboardAccelerator() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2)->get_KeyboardAccelerator(&value));
        return winrt::Windows::UI::Xaml::Input::KeyboardAccelerator{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorStatics<D>::KeyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics)->get_KeyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorStatics<D>::ModifiersProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics)->get_ModifiersProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorStatics<D>::IsEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics)->get_IsEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorStatics<D>::ScopeOwnerProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics)->get_ScopeOwnerProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::OldFocusedElement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_OldFocusedElement(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::NewFocusedElement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_NewFocusedElement(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::NewFocusedElement(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs)->put_NewFocusedElement(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FocusState) consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::FocusState() const
    {
        winrt::Windows::UI::Xaml::FocusState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_FocusState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection) consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::Direction() const
    {
        winrt::Windows::UI::Xaml::Input::FocusNavigationDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_Direction(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::FocusInputDeviceKind) consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::InputDevice() const
    {
        winrt::Windows::UI::Xaml::Input::FocusInputDeviceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_InputDevice(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::Cancel() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_Cancel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::Cancel(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs)->put_Cancel(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs2<D>::TryCancel() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs2)->TryCancel(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs2<D>::TrySetNewFocusedElement(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs2)->TrySetNewFocusedElement(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs3<D>::CorrelationId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs3)->get_CorrelationId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::Container() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_Container(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::IsInertial() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_IsInertial(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::Cumulative() const
    {
        winrt::Windows::UI::Input::ManipulationDelta value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_Cumulative(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationVelocities) consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::Velocities() const
    {
        winrt::Windows::UI::Input::ManipulationVelocities value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_Velocities(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Container() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_Container(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::IsInertial() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_IsInertial(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Delta() const
    {
        winrt::Windows::UI::Input::ManipulationDelta value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_Delta(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Cumulative() const
    {
        winrt::Windows::UI::Input::ManipulationDelta value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_Cumulative(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationVelocities) consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Velocities() const
    {
        winrt::Windows::UI::Input::ManipulationVelocities value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_Velocities(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::Container() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_Container(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::InertiaExpansionBehavior) consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::ExpansionBehavior() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_ExpansionBehavior(&value));
        return winrt::Windows::UI::Xaml::Input::InertiaExpansionBehavior{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::ExpansionBehavior(winrt::Windows::UI::Xaml::Input::InertiaExpansionBehavior const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->put_ExpansionBehavior(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::InertiaRotationBehavior) consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::RotationBehavior() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_RotationBehavior(&value));
        return winrt::Windows::UI::Xaml::Input::InertiaRotationBehavior{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::RotationBehavior(winrt::Windows::UI::Xaml::Input::InertiaRotationBehavior const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->put_RotationBehavior(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::InertiaTranslationBehavior) consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::TranslationBehavior() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_TranslationBehavior(&value));
        return winrt::Windows::UI::Xaml::Input::InertiaTranslationBehavior{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::TranslationBehavior(winrt::Windows::UI::Xaml::Input::InertiaTranslationBehavior const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->put_TranslationBehavior(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::Delta() const
    {
        winrt::Windows::UI::Input::ManipulationDelta value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_Delta(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::Cumulative() const
    {
        winrt::Windows::UI::Input::ManipulationDelta value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_Cumulative(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationVelocities) consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::Velocities() const
    {
        winrt::Windows::UI::Input::ManipulationVelocities value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_Velocities(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_Input_IManipulationPivot<D>::Center() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationPivot)->get_Center(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationPivot<D>::Center(winrt::Windows::Foundation::Point const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationPivot)->put_Center(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Input_IManipulationPivot<D>::Radius() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationPivot)->get_Radius(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationPivot<D>::Radius(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationPivot)->put_Radius(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::ManipulationPivot) consume_Windows_UI_Xaml_Input_IManipulationPivotFactory<D>::CreateInstanceWithCenterAndRadius(winrt::Windows::Foundation::Point const& center, double radius) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationPivotFactory)->CreateInstanceWithCenterAndRadius(impl::bind_in(center), radius, &value));
        return winrt::Windows::UI::Xaml::Input::ManipulationPivot{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::Container() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->get_Container(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::Cumulative() const
    {
        winrt::Windows::UI::Input::ManipulationDelta value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->get_Cumulative(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs) consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgsFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::ManipulationModes) consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Mode() const
    {
        winrt::Windows::UI::Xaml::Input::ManipulationModes value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->get_Mode(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Mode(winrt::Windows::UI::Xaml::Input::ManipulationModes const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->put_Mode(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Container() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->get_Container(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Container(winrt::Windows::UI::Xaml::UIElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->put_Container(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::ManipulationPivot) consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Pivot() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->get_Pivot(&value));
        return winrt::Windows::UI::Xaml::Input::ManipulationPivot{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Pivot(winrt::Windows::UI::Xaml::Input::ManipulationPivot const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->put_Pivot(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection) consume_Windows_UI_Xaml_Input_INoFocusCandidateFoundEventArgs<D>::Direction() const
    {
        winrt::Windows::UI::Xaml::Input::FocusNavigationDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs)->get_Direction(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_INoFocusCandidateFoundEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_INoFocusCandidateFoundEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::FocusInputDeviceKind) consume_Windows_UI_Xaml_Input_INoFocusCandidateFoundEventArgs<D>::InputDevice() const
    {
        winrt::Windows::UI::Xaml::Input::FocusInputDeviceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs)->get_InputDevice(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Xaml_Input_IPointer<D>::PointerId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IPointer)->get_PointerId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Xaml_Input_IPointer<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IPointer)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IPointer<D>::IsInContact() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IPointer)->get_IsInContact(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IPointer<D>::IsInRange() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IPointer)->get_IsInRange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::Pointer) consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs<D>::Pointer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs)->get_Pointer(&value));
        return winrt::Windows::UI::Xaml::Input::Pointer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKeyModifiers) consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs<D>::KeyModifiers() const
    {
        winrt::Windows::System::VirtualKeyModifiers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs)->get_KeyModifiers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::PointerPoint) consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs<D>::GetCurrentPoint(winrt::Windows::UI::Xaml::UIElement const& relativeTo) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs)->GetCurrentPoint(*(void**)(&relativeTo), &result));
        return winrt::Windows::UI::Input::PointerPoint{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>) consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs<D>::GetIntermediatePoints(winrt::Windows::UI::Xaml::UIElement const& relativeTo) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs)->GetIntermediatePoints(*(void**)(&relativeTo), &result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs2<D>::IsGenerated() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs2)->get_IsGenerated(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_UI_Xaml_Input_IProcessKeyboardAcceleratorEventArgs<D>::Key() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs)->get_Key(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKeyModifiers) consume_Windows_UI_Xaml_Input_IProcessKeyboardAcceleratorEventArgs<D>::Modifiers() const
    {
        winrt::Windows::System::VirtualKeyModifiers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs)->get_Modifiers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IProcessKeyboardAcceleratorEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IProcessKeyboardAcceleratorEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Xaml_Input_IRightTappedRoutedEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_IRightTappedRoutedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IRightTappedRoutedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_Input_IRightTappedRoutedEventArgs<D>::GetPosition(winrt::Windows::UI::Xaml::UIElement const& relativeTo) const
    {
        winrt::Windows::Foundation::Point result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs)->GetPosition(*(void**)(&relativeTo), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::StandardUICommandKind) consume_Windows_UI_Xaml_Input_IStandardUICommand<D>::Kind() const
    {
        winrt::Windows::UI::Xaml::Input::StandardUICommandKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IStandardUICommand)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IStandardUICommand2<D>::Kind(winrt::Windows::UI::Xaml::Input::StandardUICommandKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IStandardUICommand2)->put_Kind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::StandardUICommand) consume_Windows_UI_Xaml_Input_IStandardUICommandFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IStandardUICommandFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Input::StandardUICommand{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::StandardUICommand) consume_Windows_UI_Xaml_Input_IStandardUICommandFactory<D>::CreateInstanceWithKind(winrt::Windows::UI::Xaml::Input::StandardUICommandKind const& kind, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IStandardUICommandFactory)->CreateInstanceWithKind(static_cast<int32_t>(kind), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Input::StandardUICommand{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Input_IStandardUICommandStatics<D>::KindProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IStandardUICommandStatics)->get_KindProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Xaml_Input_ITappedRoutedEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ITappedRoutedEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Input_ITappedRoutedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ITappedRoutedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_ITappedRoutedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ITappedRoutedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_Input_ITappedRoutedEventArgs<D>::GetPosition(winrt::Windows::UI::Xaml::UIElement const& relativeTo) const
    {
        winrt::Windows::Foundation::Point result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::ITappedRoutedEventArgs)->GetPosition(*(void**)(&relativeTo), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::Label() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->get_Label(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::Label(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->put_Label(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::IconSource) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::IconSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->get_IconSource(&value));
        return winrt::Windows::UI::Xaml::Controls::IconSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::IconSource(winrt::Windows::UI::Xaml::Controls::IconSource const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->put_IconSource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator>) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::KeyboardAccelerators() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->get_KeyboardAccelerators(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::AccessKey() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->get_AccessKey(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::AccessKey(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->put_AccessKey(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::ICommand) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::Command() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->get_Command(&value));
        return winrt::Windows::UI::Xaml::Input::ICommand{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::Command(winrt::Windows::UI::Xaml::Input::ICommand const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->put_Command(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::ExecuteRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Input::XamlUICommand, winrt::Windows::UI::Xaml::Input::ExecuteRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->add_ExecuteRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::ExecuteRequested_revoker consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::ExecuteRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Input::XamlUICommand, winrt::Windows::UI::Xaml::Input::ExecuteRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ExecuteRequested_revoker>(this, ExecuteRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::ExecuteRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->remove_ExecuteRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::CanExecuteRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Input::XamlUICommand, winrt::Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->add_CanExecuteRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::CanExecuteRequested_revoker consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::CanExecuteRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Input::XamlUICommand, winrt::Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CanExecuteRequested_revoker>(this, CanExecuteRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::CanExecuteRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->remove_CanExecuteRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::NotifyCanExecuteChanged() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommand)->NotifyCanExecuteChanged());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XamlUICommand) consume_Windows_UI_Xaml_Input_IXamlUICommandFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommandFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Input::XamlUICommand{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Input_IXamlUICommandStatics<D>::LabelProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommandStatics)->get_LabelProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Input_IXamlUICommandStatics<D>::IconSourceProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommandStatics)->get_IconSourceProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Input_IXamlUICommandStatics<D>::KeyboardAcceleratorsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommandStatics)->get_KeyboardAcceleratorsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Input_IXamlUICommandStatics<D>::AccessKeyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommandStatics)->get_AccessKeyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Input_IXamlUICommandStatics<D>::DescriptionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommandStatics)->get_DescriptionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Input_IXamlUICommandStatics<D>::CommandProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Input::IXamlUICommandStatics)->get_CommandProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Input::DoubleTappedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Input::DoubleTappedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Input::DoubleTappedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::DoubleTappedRoutedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Input::HoldingEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Input::HoldingEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Input::HoldingEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::HoldingRoutedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Input::KeyEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Input::KeyEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Input::KeyEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::KeyRoutedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Input::ManipulationCompletedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Input::ManipulationCompletedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Input::ManipulationCompletedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Input::ManipulationDeltaEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Input::ManipulationDeltaEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Input::ManipulationDeltaEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::ManipulationDeltaRoutedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::ManipulationInertiaStartingRoutedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Input::ManipulationStartedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Input::ManipulationStartedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Input::ManipulationStartedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Input::ManipulationStartingEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Input::ManipulationStartingEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Input::ManipulationStartingEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Input::PointerEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Input::PointerEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Input::PointerEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::PointerRoutedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Input::RightTappedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Input::RightTappedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Input::RightTappedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::RightTappedRoutedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Input::TappedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Input::TappedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Input::TappedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::TappedRoutedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs>
    {
        int32_t __stdcall get_PressedKeys(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PressedKeys());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs>
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IAccessKeyManager> : produce_base<D, winrt::Windows::UI::Xaml::Input::IAccessKeyManager>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics> : produce_base<D, winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics>
    {
        int32_t __stdcall get_IsDisplayModeEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDisplayModeEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_IsDisplayModeEnabledChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().IsDisplayModeEnabledChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_IsDisplayModeEnabledChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsDisplayModeEnabledChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall ExitDisplayMode() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExitDisplayMode();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics2>
    {
        int32_t __stdcall get_AreKeyTipsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AreKeyTipsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AreKeyTipsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AreKeyTipsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs>
    {
        int32_t __stdcall get_Parameter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Parameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanExecute(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanExecute());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanExecute(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanExecute(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs>
    {
        int32_t __stdcall get_Character(char16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<char16_t>(this->shim().Character());
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
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::ICommand> : produce_base<D, winrt::Windows::UI::Xaml::Input::ICommand>
    {
        int32_t __stdcall add_CanExecuteChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CanExecuteChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CanExecuteChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanExecuteChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall CanExecute(void* parameter, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().CanExecute(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&parameter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Execute(void* parameter) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Execute(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&parameter));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IContextRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IContextRequestedEventArgs>
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
        int32_t __stdcall TryGetPosition(void* relativeTo, winrt::Windows::Foundation::Point* point, bool* returnValue) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(point);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<bool>(this->shim().TryGetPosition(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&relativeTo), *reinterpret_cast<winrt::Windows::Foundation::Point*>(point)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs>
    {
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
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
        int32_t __stdcall GetPosition(void* relativeTo, winrt::Windows::Foundation::Point* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Point>(this->shim().GetPosition(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IExecuteRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IExecuteRequestedEventArgs>
    {
        int32_t __stdcall get_Parameter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Parameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IFindNextElementOptions> : produce_base<D, winrt::Windows::UI::Xaml::Input::IFindNextElementOptions>
    {
        int32_t __stdcall get_SearchRoot(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().SearchRoot());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SearchRoot(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SearchRoot(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExclusionRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().ExclusionRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExclusionRect(winrt::Windows::Foundation::Rect value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExclusionRect(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HintRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().HintRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HintRect(winrt::Windows::Foundation::Rect value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HintRect(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusNavigationStrategyOverride(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride>(this->shim().XYFocusNavigationStrategyOverride());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusNavigationStrategyOverride(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusNavigationStrategyOverride(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IFocusManager> : produce_base<D, winrt::Windows::UI::Xaml::Input::IFocusManager>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs>
    {
        int32_t __stdcall get_NewFocusedElement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().NewFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CorrelationId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().CorrelationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs>
    {
        int32_t __stdcall get_OldFocusedElement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().OldFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CorrelationId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().CorrelationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics> : produce_base<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics>
    {
        int32_t __stdcall GetFocusedElement(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics2>
    {
        int32_t __stdcall TryMoveFocus(int32_t focusNavigationDirection, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryMoveFocus(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics3> : produce_base<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics3>
    {
        int32_t __stdcall FindNextFocusableElement(int32_t focusNavigationDirection, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().FindNextFocusableElement(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindNextFocusableElementWithHint(int32_t focusNavigationDirection, winrt::Windows::Foundation::Rect hintRect, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().FindNextFocusableElement(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&hintRect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics4> : produce_base<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics4>
    {
        int32_t __stdcall TryMoveFocusWithOptions(int32_t focusNavigationDirection, void* focusNavigationOptions, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryMoveFocus(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::FindNextElementOptions const*>(&focusNavigationOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindNextElement(int32_t focusNavigationDirection, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().FindNextElement(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindFirstFocusableElement(void* searchScope, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().FindFirstFocusableElement(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&searchScope)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindLastFocusableElement(void* searchScope, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().FindLastFocusableElement(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&searchScope)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindNextElementWithOptions(int32_t focusNavigationDirection, void* focusNavigationOptions, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().FindNextElement(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::FindNextElementOptions const*>(&focusNavigationOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics5> : produce_base<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics5>
    {
        int32_t __stdcall TryFocusAsync(void* element, int32_t value, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Input::FocusMovementResult>>(this->shim().TryFocusAsync(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<winrt::Windows::UI::Xaml::FocusState const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryMoveFocusAsync(int32_t focusNavigationDirection, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Input::FocusMovementResult>>(this->shim().TryMoveFocusAsync(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryMoveFocusWithOptionsAsync(int32_t focusNavigationDirection, void* focusNavigationOptions, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Input::FocusMovementResult>>(this->shim().TryMoveFocusAsync(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection), *reinterpret_cast<winrt::Windows::UI::Xaml::Input::FindNextElementOptions const*>(&focusNavigationOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6> : produce_base<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6>
    {
        int32_t __stdcall add_GotFocus(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const*>(&handler)));
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
            *token = detach_from<winrt::event_token>(this->shim().LostFocus(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LostFocus(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LostFocus(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_GettingFocus(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GettingFocus(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::GettingFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_GettingFocus(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GettingFocus(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_LosingFocus(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().LosingFocus(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::LosingFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LosingFocus(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LosingFocus(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics7> : produce_base<D, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics7>
    {
        int32_t __stdcall GetFocusedElement(void* xamlRoot, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetFocusedElement(*reinterpret_cast<winrt::Windows::UI::Xaml::XamlRoot const*>(&xamlRoot)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IFocusMovementResult> : produce_base<D, winrt::Windows::UI::Xaml::Input::IFocusMovementResult>
    {
        int32_t __stdcall get_Succeeded(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Succeeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs>
    {
        int32_t __stdcall get_OldFocusedElement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().OldFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NewFocusedElement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().NewFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NewFocusedElement(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NewFocusedElement(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::FocusState>(this->shim().FocusState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Direction(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::FocusNavigationDirection>(this->shim().Direction());
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
        int32_t __stdcall get_InputDevice(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::FocusInputDeviceKind>(this->shim().InputDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Cancel(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Cancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Cancel(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cancel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs2> : produce_base<D, winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs2>
    {
        int32_t __stdcall TryCancel(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryCancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySetNewFocusedElement(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TrySetNewFocusedElement(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs3> : produce_base<D, winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs3>
    {
        int32_t __stdcall get_CorrelationId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().CorrelationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IHoldingRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IHoldingRoutedEventArgs>
    {
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HoldingState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::HoldingState>(this->shim().HoldingState());
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
        int32_t __stdcall GetPosition(void* relativeTo, winrt::Windows::Foundation::Point* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Point>(this->shim().GetPosition(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IInertiaExpansionBehavior> : produce_base<D, winrt::Windows::UI::Xaml::Input::IInertiaExpansionBehavior>
    {
        int32_t __stdcall get_DesiredDeceleration(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DesiredDeceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredDeceleration(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredDeceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredExpansion(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DesiredExpansion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredExpansion(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredExpansion(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IInertiaRotationBehavior> : produce_base<D, winrt::Windows::UI::Xaml::Input::IInertiaRotationBehavior>
    {
        int32_t __stdcall get_DesiredDeceleration(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DesiredDeceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredDeceleration(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredDeceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredRotation(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DesiredRotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredRotation(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredRotation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IInertiaTranslationBehavior> : produce_base<D, winrt::Windows::UI::Xaml::Input::IInertiaTranslationBehavior>
    {
        int32_t __stdcall get_DesiredDeceleration(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DesiredDeceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredDeceleration(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredDeceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredDisplacement(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DesiredDisplacement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredDisplacement(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredDisplacement(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IInputScope> : produce_base<D, winrt::Windows::UI::Xaml::Input::IInputScope>
    {
        int32_t __stdcall get_Names(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Input::InputScopeName>>(this->shim().Names());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IInputScopeName> : produce_base<D, winrt::Windows::UI::Xaml::Input::IInputScopeName>
    {
        int32_t __stdcall get_NameValue(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::InputScopeNameValue>(this->shim().NameValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NameValue(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NameValue(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::InputScopeNameValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IInputScopeNameFactory> : produce_base<D, winrt::Windows::UI::Xaml::Input::IInputScopeNameFactory>
    {
        int32_t __stdcall CreateInstance(int32_t nameValue, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::InputScopeName>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::InputScopeNameValue const*>(&nameValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs>
    {
        int32_t __stdcall get_Key(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().Key());
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
    struct produce<D, winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs2> : produce_base<D, winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs2>
    {
        int32_t __stdcall get_OriginalKey(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().OriginalKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs3> : produce_base<D, winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs3>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator> : produce_base<D, winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator>
    {
        int32_t __stdcall get_Key(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().Key());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Key(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Key(*reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Modifiers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKeyModifiers>(this->shim().Modifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Modifiers(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Modifiers(*reinterpret_cast<winrt::Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScopeOwner(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().ScopeOwner());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScopeOwner(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScopeOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Invoked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Invoked(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator, winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Invoked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Invoked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory> : produce_base<D, winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs>
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
        int32_t __stdcall get_Element(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().Element());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2> : produce_base<D, winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2>
    {
        int32_t __stdcall get_KeyboardAccelerator(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator>(this->shim().KeyboardAccelerator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics> : produce_base<D, winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics>
    {
        int32_t __stdcall get_KeyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ModifiersProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ModifiersProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScopeOwnerProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ScopeOwnerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs>
    {
        int32_t __stdcall get_OldFocusedElement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().OldFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NewFocusedElement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().NewFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NewFocusedElement(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NewFocusedElement(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::FocusState>(this->shim().FocusState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Direction(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::FocusNavigationDirection>(this->shim().Direction());
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
        int32_t __stdcall get_InputDevice(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::FocusInputDeviceKind>(this->shim().InputDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Cancel(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Cancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Cancel(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cancel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs2> : produce_base<D, winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs2>
    {
        int32_t __stdcall TryCancel(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryCancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySetNewFocusedElement(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TrySetNewFocusedElement(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs3> : produce_base<D, winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs3>
    {
        int32_t __stdcall get_CorrelationId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().CorrelationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs>
    {
        int32_t __stdcall get_Container(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().Container());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInertial(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInertial());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::ManipulationDelta>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::ManipulationDelta>(this->shim().Cumulative());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Velocities(struct struct_Windows_UI_Input_ManipulationVelocities* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::ManipulationVelocities>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::ManipulationVelocities>(this->shim().Velocities());
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
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs>
    {
        int32_t __stdcall get_Container(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().Container());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInertial(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInertial());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Delta(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::ManipulationDelta>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::ManipulationDelta>(this->shim().Delta());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::ManipulationDelta>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::ManipulationDelta>(this->shim().Cumulative());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Velocities(struct struct_Windows_UI_Input_ManipulationVelocities* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::ManipulationVelocities>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::ManipulationVelocities>(this->shim().Velocities());
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
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Complete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs>
    {
        int32_t __stdcall get_Container(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().Container());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpansionBehavior(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::InertiaExpansionBehavior>(this->shim().ExpansionBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExpansionBehavior(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExpansionBehavior(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::InertiaExpansionBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RotationBehavior(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::InertiaRotationBehavior>(this->shim().RotationBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RotationBehavior(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RotationBehavior(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::InertiaRotationBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TranslationBehavior(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::InertiaTranslationBehavior>(this->shim().TranslationBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TranslationBehavior(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TranslationBehavior(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::InertiaTranslationBehavior const*>(&value));
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
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Delta(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::ManipulationDelta>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::ManipulationDelta>(this->shim().Delta());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::ManipulationDelta>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::ManipulationDelta>(this->shim().Cumulative());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Velocities(struct struct_Windows_UI_Input_ManipulationVelocities* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::ManipulationVelocities>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::ManipulationVelocities>(this->shim().Velocities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IManipulationPivot> : produce_base<D, winrt::Windows::UI::Xaml::Input::IManipulationPivot>
    {
        int32_t __stdcall get_Center(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().Center());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Center(winrt::Windows::Foundation::Point value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Center(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Radius(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Radius());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Radius(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Radius(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IManipulationPivotFactory> : produce_base<D, winrt::Windows::UI::Xaml::Input::IManipulationPivotFactory>
    {
        int32_t __stdcall CreateInstanceWithCenterAndRadius(winrt::Windows::Foundation::Point center, double radius, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::ManipulationPivot>(this->shim().CreateInstanceWithCenterAndRadius(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&center), radius));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs>
    {
        int32_t __stdcall get_Container(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().Container());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().Position());
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
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::ManipulationDelta>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::ManipulationDelta>(this->shim().Cumulative());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Complete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory> : produce_base<D, winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs>
    {
        int32_t __stdcall get_Mode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::ManipulationModes>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Mode(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Mode(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::ManipulationModes const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Container(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().Container());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Container(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Container(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pivot(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::ManipulationPivot>(this->shim().Pivot());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Pivot(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Pivot(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::ManipulationPivot const*>(&value));
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
    struct produce<D, winrt::Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs>
    {
        int32_t __stdcall get_Direction(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::FocusNavigationDirection>(this->shim().Direction());
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
        int32_t __stdcall get_InputDevice(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::FocusInputDeviceKind>(this->shim().InputDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IPointer> : produce_base<D, winrt::Windows::UI::Xaml::Input::IPointer>
    {
        int32_t __stdcall get_PointerId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().PointerId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInContact(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInContact());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInRange(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs>
    {
        int32_t __stdcall get_Pointer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::Pointer>(this->shim().Pointer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyModifiers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKeyModifiers>(this->shim().KeyModifiers());
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
        int32_t __stdcall GetCurrentPoint(void* relativeTo, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::PointerPoint>(this->shim().GetCurrentPoint(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIntermediatePoints(void* relativeTo, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>>(this->shim().GetIntermediatePoints(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs2> : produce_base<D, winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs2>
    {
        int32_t __stdcall get_IsGenerated(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsGenerated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs>
    {
        int32_t __stdcall get_Key(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().Key());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Modifiers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKeyModifiers>(this->shim().Modifiers());
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
    struct produce<D, winrt::Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs>
    {
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
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
        int32_t __stdcall GetPosition(void* relativeTo, winrt::Windows::Foundation::Point* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Point>(this->shim().GetPosition(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IStandardUICommand> : produce_base<D, winrt::Windows::UI::Xaml::Input::IStandardUICommand>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::StandardUICommandKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IStandardUICommand2> : produce_base<D, winrt::Windows::UI::Xaml::Input::IStandardUICommand2>
    {
        int32_t __stdcall put_Kind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Kind(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::StandardUICommandKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IStandardUICommandFactory> : produce_base<D, winrt::Windows::UI::Xaml::Input::IStandardUICommandFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::StandardUICommand>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstanceWithKind(int32_t kind, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::StandardUICommand>(this->shim().CreateInstanceWithKind(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::StandardUICommandKind const*>(&kind), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IStandardUICommandStatics> : produce_base<D, winrt::Windows::UI::Xaml::Input::IStandardUICommandStatics>
    {
        int32_t __stdcall get_KindProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KindProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::ITappedRoutedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Input::ITappedRoutedEventArgs>
    {
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
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
        int32_t __stdcall GetPosition(void* relativeTo, winrt::Windows::Foundation::Point* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Point>(this->shim().GetPosition(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IXamlUICommand> : produce_base<D, winrt::Windows::UI::Xaml::Input::IXamlUICommand>
    {
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
        int32_t __stdcall get_IconSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::IconSource>(this->shim().IconSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IconSource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IconSource(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::IconSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyboardAccelerators(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator>>(this->shim().KeyboardAccelerators());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccessKey(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AccessKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AccessKey(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccessKey(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Description(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Command(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::ICommand>(this->shim().Command());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Command(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Command(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::ICommand const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ExecuteRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ExecuteRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Input::XamlUICommand, winrt::Windows::UI::Xaml::Input::ExecuteRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ExecuteRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExecuteRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CanExecuteRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CanExecuteRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Input::XamlUICommand, winrt::Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CanExecuteRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanExecuteRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall NotifyCanExecuteChanged() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyCanExecuteChanged();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IXamlUICommandFactory> : produce_base<D, winrt::Windows::UI::Xaml::Input::IXamlUICommandFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XamlUICommand>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Input::IXamlUICommandStatics> : produce_base<D, winrt::Windows::UI::Xaml::Input::IXamlUICommandStatics>
    {
        int32_t __stdcall get_LabelProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().LabelProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IconSourceProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IconSourceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyboardAcceleratorsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyboardAcceleratorsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccessKeyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AccessKeyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DescriptionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DescriptionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CommandProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CommandProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Input
{
    constexpr auto operator|(ManipulationModes const left, ManipulationModes const right) noexcept
    {
        return static_cast<ManipulationModes>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(ManipulationModes& left, ManipulationModes const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(ManipulationModes const left, ManipulationModes const right) noexcept
    {
        return static_cast<ManipulationModes>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(ManipulationModes& left, ManipulationModes const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(ManipulationModes const value) noexcept
    {
        return static_cast<ManipulationModes>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(ManipulationModes const left, ManipulationModes const right) noexcept
    {
        return static_cast<ManipulationModes>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(ManipulationModes& left, ManipulationModes const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline AccessKeyDisplayDismissedEventArgs::AccessKeyDisplayDismissedEventArgs() :
        AccessKeyDisplayDismissedEventArgs(impl::call_factory_cast<AccessKeyDisplayDismissedEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), AccessKeyDisplayDismissedEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AccessKeyDisplayDismissedEventArgs>(); }))
    {
    }
    inline AccessKeyDisplayRequestedEventArgs::AccessKeyDisplayRequestedEventArgs() :
        AccessKeyDisplayRequestedEventArgs(impl::call_factory_cast<AccessKeyDisplayRequestedEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), AccessKeyDisplayRequestedEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AccessKeyDisplayRequestedEventArgs>(); }))
    {
    }
    inline AccessKeyInvokedEventArgs::AccessKeyInvokedEventArgs() :
        AccessKeyInvokedEventArgs(impl::call_factory_cast<AccessKeyInvokedEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), AccessKeyInvokedEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AccessKeyInvokedEventArgs>(); }))
    {
    }
    inline auto AccessKeyManager::IsDisplayModeEnabled()
    {
        return impl::call_factory_cast<bool(*)(IAccessKeyManagerStatics const&), AccessKeyManager, IAccessKeyManagerStatics>([](IAccessKeyManagerStatics const& f) { return f.IsDisplayModeEnabled(); });
    }
    inline auto AccessKeyManager::IsDisplayModeEnabledChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<AccessKeyManager, IAccessKeyManagerStatics>([&](IAccessKeyManagerStatics const& f) { return f.IsDisplayModeEnabledChanged(handler); });
    }
    inline AccessKeyManager::IsDisplayModeEnabledChanged_revoker AccessKeyManager::IsDisplayModeEnabledChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<AccessKeyManager, winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics>();
        return { f, f.IsDisplayModeEnabledChanged(handler) };
    }
    inline auto AccessKeyManager::IsDisplayModeEnabledChanged(winrt::event_token const& token)
    {
        impl::call_factory<AccessKeyManager, IAccessKeyManagerStatics>([&](IAccessKeyManagerStatics const& f) { return f.IsDisplayModeEnabledChanged(token); });
    }
    inline auto AccessKeyManager::ExitDisplayMode()
    {
        impl::call_factory_cast<void(*)(IAccessKeyManagerStatics const&), AccessKeyManager, IAccessKeyManagerStatics>([](IAccessKeyManagerStatics const& f) { return f.ExitDisplayMode(); });
    }
    inline auto AccessKeyManager::AreKeyTipsEnabled()
    {
        return impl::call_factory_cast<bool(*)(IAccessKeyManagerStatics2 const&), AccessKeyManager, IAccessKeyManagerStatics2>([](IAccessKeyManagerStatics2 const& f) { return f.AreKeyTipsEnabled(); });
    }
    inline auto AccessKeyManager::AreKeyTipsEnabled(bool value)
    {
        impl::call_factory<AccessKeyManager, IAccessKeyManagerStatics2>([&](IAccessKeyManagerStatics2 const& f) { return f.AreKeyTipsEnabled(value); });
    }
    inline ContextRequestedEventArgs::ContextRequestedEventArgs() :
        ContextRequestedEventArgs(impl::call_factory_cast<ContextRequestedEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), ContextRequestedEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContextRequestedEventArgs>(); }))
    {
    }
    inline DoubleTappedRoutedEventArgs::DoubleTappedRoutedEventArgs() :
        DoubleTappedRoutedEventArgs(impl::call_factory_cast<DoubleTappedRoutedEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), DoubleTappedRoutedEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DoubleTappedRoutedEventArgs>(); }))
    {
    }
    inline FindNextElementOptions::FindNextElementOptions() :
        FindNextElementOptions(impl::call_factory_cast<FindNextElementOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), FindNextElementOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<FindNextElementOptions>(); }))
    {
    }
    inline auto FocusManager::GetFocusedElement()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IInspectable(*)(IFocusManagerStatics const&), FocusManager, IFocusManagerStatics>([](IFocusManagerStatics const& f) { return f.GetFocusedElement(); });
    }
    inline auto FocusManager::TryMoveFocus(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics2>([&](IFocusManagerStatics2 const& f) { return f.TryMoveFocus(focusNavigationDirection); });
    }
    inline auto FocusManager::FindNextFocusableElement(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics3>([&](IFocusManagerStatics3 const& f) { return f.FindNextFocusableElement(focusNavigationDirection); });
    }
    inline auto FocusManager::FindNextFocusableElement(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, winrt::Windows::Foundation::Rect const& hintRect)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics3>([&](IFocusManagerStatics3 const& f) { return f.FindNextFocusableElement(focusNavigationDirection, hintRect); });
    }
    inline auto FocusManager::TryMoveFocus(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, winrt::Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics4>([&](IFocusManagerStatics4 const& f) { return f.TryMoveFocus(focusNavigationDirection, focusNavigationOptions); });
    }
    inline auto FocusManager::FindNextElement(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics4>([&](IFocusManagerStatics4 const& f) { return f.FindNextElement(focusNavigationDirection); });
    }
    inline auto FocusManager::FindFirstFocusableElement(winrt::Windows::UI::Xaml::DependencyObject const& searchScope)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics4>([&](IFocusManagerStatics4 const& f) { return f.FindFirstFocusableElement(searchScope); });
    }
    inline auto FocusManager::FindLastFocusableElement(winrt::Windows::UI::Xaml::DependencyObject const& searchScope)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics4>([&](IFocusManagerStatics4 const& f) { return f.FindLastFocusableElement(searchScope); });
    }
    inline auto FocusManager::FindNextElement(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, winrt::Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics4>([&](IFocusManagerStatics4 const& f) { return f.FindNextElement(focusNavigationDirection, focusNavigationOptions); });
    }
    inline auto FocusManager::TryFocusAsync(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FocusState const& value)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics5>([&](IFocusManagerStatics5 const& f) { return f.TryFocusAsync(element, value); });
    }
    inline auto FocusManager::TryMoveFocusAsync(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics5>([&](IFocusManagerStatics5 const& f) { return f.TryMoveFocusAsync(focusNavigationDirection); });
    }
    inline auto FocusManager::TryMoveFocusAsync(winrt::Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, winrt::Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics5>([&](IFocusManagerStatics5 const& f) { return f.TryMoveFocusAsync(focusNavigationDirection, focusNavigationOptions); });
    }
    inline auto FocusManager::GotFocus(winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const& handler)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics6>([&](IFocusManagerStatics6 const& f) { return f.GotFocus(handler); });
    }
    inline FocusManager::GotFocus_revoker FocusManager::GotFocus(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const& handler)
    {
        auto f = get_activation_factory<FocusManager, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6>();
        return { f, f.GotFocus(handler) };
    }
    inline auto FocusManager::GotFocus(winrt::event_token const& token)
    {
        impl::call_factory<FocusManager, IFocusManagerStatics6>([&](IFocusManagerStatics6 const& f) { return f.GotFocus(token); });
    }
    inline auto FocusManager::LostFocus(winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const& handler)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics6>([&](IFocusManagerStatics6 const& f) { return f.LostFocus(handler); });
    }
    inline FocusManager::LostFocus_revoker FocusManager::LostFocus(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const& handler)
    {
        auto f = get_activation_factory<FocusManager, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6>();
        return { f, f.LostFocus(handler) };
    }
    inline auto FocusManager::LostFocus(winrt::event_token const& token)
    {
        impl::call_factory<FocusManager, IFocusManagerStatics6>([&](IFocusManagerStatics6 const& f) { return f.LostFocus(token); });
    }
    inline auto FocusManager::GettingFocus(winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics6>([&](IFocusManagerStatics6 const& f) { return f.GettingFocus(handler); });
    }
    inline FocusManager::GettingFocus_revoker FocusManager::GettingFocus(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler)
    {
        auto f = get_activation_factory<FocusManager, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6>();
        return { f, f.GettingFocus(handler) };
    }
    inline auto FocusManager::GettingFocus(winrt::event_token const& token)
    {
        impl::call_factory<FocusManager, IFocusManagerStatics6>([&](IFocusManagerStatics6 const& f) { return f.GettingFocus(token); });
    }
    inline auto FocusManager::LosingFocus(winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics6>([&](IFocusManagerStatics6 const& f) { return f.LosingFocus(handler); });
    }
    inline FocusManager::LosingFocus_revoker FocusManager::LosingFocus(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler)
    {
        auto f = get_activation_factory<FocusManager, winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6>();
        return { f, f.LosingFocus(handler) };
    }
    inline auto FocusManager::LosingFocus(winrt::event_token const& token)
    {
        impl::call_factory<FocusManager, IFocusManagerStatics6>([&](IFocusManagerStatics6 const& f) { return f.LosingFocus(token); });
    }
    inline auto FocusManager::GetFocusedElement(winrt::Windows::UI::Xaml::XamlRoot const& xamlRoot)
    {
        return impl::call_factory<FocusManager, IFocusManagerStatics7>([&](IFocusManagerStatics7 const& f) { return f.GetFocusedElement(xamlRoot); });
    }
    inline HoldingRoutedEventArgs::HoldingRoutedEventArgs() :
        HoldingRoutedEventArgs(impl::call_factory_cast<HoldingRoutedEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), HoldingRoutedEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<HoldingRoutedEventArgs>(); }))
    {
    }
    inline InputScope::InputScope() :
        InputScope(impl::call_factory_cast<InputScope(*)(winrt::Windows::Foundation::IActivationFactory const&), InputScope>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InputScope>(); }))
    {
    }
    inline InputScopeName::InputScopeName() :
        InputScopeName(impl::call_factory_cast<InputScopeName(*)(winrt::Windows::Foundation::IActivationFactory const&), InputScopeName>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InputScopeName>(); }))
    {
    }
    inline InputScopeName::InputScopeName(winrt::Windows::UI::Xaml::Input::InputScopeNameValue const& nameValue) :
        InputScopeName(impl::call_factory<InputScopeName, IInputScopeNameFactory>([&](IInputScopeNameFactory const& f) { return f.CreateInstance(nameValue); }))
    {
    }
    inline KeyboardAccelerator::KeyboardAccelerator()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<KeyboardAccelerator, IKeyboardAcceleratorFactory>([&](IKeyboardAcceleratorFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto KeyboardAccelerator::KeyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IKeyboardAcceleratorStatics const&), KeyboardAccelerator, IKeyboardAcceleratorStatics>([](IKeyboardAcceleratorStatics const& f) { return f.KeyProperty(); });
    }
    inline auto KeyboardAccelerator::ModifiersProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IKeyboardAcceleratorStatics const&), KeyboardAccelerator, IKeyboardAcceleratorStatics>([](IKeyboardAcceleratorStatics const& f) { return f.ModifiersProperty(); });
    }
    inline auto KeyboardAccelerator::IsEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IKeyboardAcceleratorStatics const&), KeyboardAccelerator, IKeyboardAcceleratorStatics>([](IKeyboardAcceleratorStatics const& f) { return f.IsEnabledProperty(); });
    }
    inline auto KeyboardAccelerator::ScopeOwnerProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IKeyboardAcceleratorStatics const&), KeyboardAccelerator, IKeyboardAcceleratorStatics>([](IKeyboardAcceleratorStatics const& f) { return f.ScopeOwnerProperty(); });
    }
    inline ManipulationCompletedRoutedEventArgs::ManipulationCompletedRoutedEventArgs() :
        ManipulationCompletedRoutedEventArgs(impl::call_factory_cast<ManipulationCompletedRoutedEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), ManipulationCompletedRoutedEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ManipulationCompletedRoutedEventArgs>(); }))
    {
    }
    inline ManipulationDeltaRoutedEventArgs::ManipulationDeltaRoutedEventArgs() :
        ManipulationDeltaRoutedEventArgs(impl::call_factory_cast<ManipulationDeltaRoutedEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), ManipulationDeltaRoutedEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ManipulationDeltaRoutedEventArgs>(); }))
    {
    }
    inline ManipulationInertiaStartingRoutedEventArgs::ManipulationInertiaStartingRoutedEventArgs() :
        ManipulationInertiaStartingRoutedEventArgs(impl::call_factory_cast<ManipulationInertiaStartingRoutedEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), ManipulationInertiaStartingRoutedEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ManipulationInertiaStartingRoutedEventArgs>(); }))
    {
    }
    inline ManipulationPivot::ManipulationPivot() :
        ManipulationPivot(impl::call_factory_cast<ManipulationPivot(*)(winrt::Windows::Foundation::IActivationFactory const&), ManipulationPivot>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ManipulationPivot>(); }))
    {
    }
    inline ManipulationPivot::ManipulationPivot(winrt::Windows::Foundation::Point const& center, double radius) :
        ManipulationPivot(impl::call_factory<ManipulationPivot, IManipulationPivotFactory>([&](IManipulationPivotFactory const& f) { return f.CreateInstanceWithCenterAndRadius(center, radius); }))
    {
    }
    inline ManipulationStartedRoutedEventArgs::ManipulationStartedRoutedEventArgs()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ManipulationStartedRoutedEventArgs, IManipulationStartedRoutedEventArgsFactory>([&](IManipulationStartedRoutedEventArgsFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline ManipulationStartingRoutedEventArgs::ManipulationStartingRoutedEventArgs() :
        ManipulationStartingRoutedEventArgs(impl::call_factory_cast<ManipulationStartingRoutedEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), ManipulationStartingRoutedEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ManipulationStartingRoutedEventArgs>(); }))
    {
    }
    inline RightTappedRoutedEventArgs::RightTappedRoutedEventArgs() :
        RightTappedRoutedEventArgs(impl::call_factory_cast<RightTappedRoutedEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), RightTappedRoutedEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<RightTappedRoutedEventArgs>(); }))
    {
    }
    inline StandardUICommand::StandardUICommand()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<StandardUICommand, IStandardUICommandFactory>([&](IStandardUICommandFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline StandardUICommand::StandardUICommand(winrt::Windows::UI::Xaml::Input::StandardUICommandKind const& kind)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<StandardUICommand, IStandardUICommandFactory>([&](IStandardUICommandFactory const& f) { return f.CreateInstanceWithKind(kind, baseInterface, innerInterface); });
    }
    inline auto StandardUICommand::KindProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IStandardUICommandStatics const&), StandardUICommand, IStandardUICommandStatics>([](IStandardUICommandStatics const& f) { return f.KindProperty(); });
    }
    inline TappedRoutedEventArgs::TappedRoutedEventArgs() :
        TappedRoutedEventArgs(impl::call_factory_cast<TappedRoutedEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), TappedRoutedEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<TappedRoutedEventArgs>(); }))
    {
    }
    inline XamlUICommand::XamlUICommand()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<XamlUICommand, IXamlUICommandFactory>([&](IXamlUICommandFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto XamlUICommand::LabelProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IXamlUICommandStatics const&), XamlUICommand, IXamlUICommandStatics>([](IXamlUICommandStatics const& f) { return f.LabelProperty(); });
    }
    inline auto XamlUICommand::IconSourceProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IXamlUICommandStatics const&), XamlUICommand, IXamlUICommandStatics>([](IXamlUICommandStatics const& f) { return f.IconSourceProperty(); });
    }
    inline auto XamlUICommand::KeyboardAcceleratorsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IXamlUICommandStatics const&), XamlUICommand, IXamlUICommandStatics>([](IXamlUICommandStatics const& f) { return f.KeyboardAcceleratorsProperty(); });
    }
    inline auto XamlUICommand::AccessKeyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IXamlUICommandStatics const&), XamlUICommand, IXamlUICommandStatics>([](IXamlUICommandStatics const& f) { return f.AccessKeyProperty(); });
    }
    inline auto XamlUICommand::DescriptionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IXamlUICommandStatics const&), XamlUICommand, IXamlUICommandStatics>([](IXamlUICommandStatics const& f) { return f.DescriptionProperty(); });
    }
    inline auto XamlUICommand::CommandProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IXamlUICommandStatics const&), XamlUICommand, IXamlUICommandStatics>([](IXamlUICommandStatics const& f) { return f.CommandProperty(); });
    }
    template <typename L> DoubleTappedEventHandler::DoubleTappedEventHandler(L handler) :
        DoubleTappedEventHandler(impl::make_delegate<DoubleTappedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> DoubleTappedEventHandler::DoubleTappedEventHandler(F* handler) :
        DoubleTappedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DoubleTappedEventHandler::DoubleTappedEventHandler(O* object, M method) :
        DoubleTappedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DoubleTappedEventHandler::DoubleTappedEventHandler(com_ptr<O>&& object, M method) :
        DoubleTappedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DoubleTappedEventHandler::DoubleTappedEventHandler(weak_ref<O>&& object, M method) :
        DoubleTappedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DoubleTappedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Input::DoubleTappedRoutedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<DoubleTappedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> HoldingEventHandler::HoldingEventHandler(L handler) :
        HoldingEventHandler(impl::make_delegate<HoldingEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> HoldingEventHandler::HoldingEventHandler(F* handler) :
        HoldingEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> HoldingEventHandler::HoldingEventHandler(O* object, M method) :
        HoldingEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> HoldingEventHandler::HoldingEventHandler(com_ptr<O>&& object, M method) :
        HoldingEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> HoldingEventHandler::HoldingEventHandler(weak_ref<O>&& object, M method) :
        HoldingEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto HoldingEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Input::HoldingRoutedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<HoldingEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> KeyEventHandler::KeyEventHandler(L handler) :
        KeyEventHandler(impl::make_delegate<KeyEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> KeyEventHandler::KeyEventHandler(F* handler) :
        KeyEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> KeyEventHandler::KeyEventHandler(O* object, M method) :
        KeyEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> KeyEventHandler::KeyEventHandler(com_ptr<O>&& object, M method) :
        KeyEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> KeyEventHandler::KeyEventHandler(weak_ref<O>&& object, M method) :
        KeyEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto KeyEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Input::KeyRoutedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<KeyEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> ManipulationCompletedEventHandler::ManipulationCompletedEventHandler(L handler) :
        ManipulationCompletedEventHandler(impl::make_delegate<ManipulationCompletedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> ManipulationCompletedEventHandler::ManipulationCompletedEventHandler(F* handler) :
        ManipulationCompletedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> ManipulationCompletedEventHandler::ManipulationCompletedEventHandler(O* object, M method) :
        ManipulationCompletedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> ManipulationCompletedEventHandler::ManipulationCompletedEventHandler(com_ptr<O>&& object, M method) :
        ManipulationCompletedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> ManipulationCompletedEventHandler::ManipulationCompletedEventHandler(weak_ref<O>&& object, M method) :
        ManipulationCompletedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto ManipulationCompletedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<ManipulationCompletedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> ManipulationDeltaEventHandler::ManipulationDeltaEventHandler(L handler) :
        ManipulationDeltaEventHandler(impl::make_delegate<ManipulationDeltaEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> ManipulationDeltaEventHandler::ManipulationDeltaEventHandler(F* handler) :
        ManipulationDeltaEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> ManipulationDeltaEventHandler::ManipulationDeltaEventHandler(O* object, M method) :
        ManipulationDeltaEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> ManipulationDeltaEventHandler::ManipulationDeltaEventHandler(com_ptr<O>&& object, M method) :
        ManipulationDeltaEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> ManipulationDeltaEventHandler::ManipulationDeltaEventHandler(weak_ref<O>&& object, M method) :
        ManipulationDeltaEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto ManipulationDeltaEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Input::ManipulationDeltaRoutedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<ManipulationDeltaEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> ManipulationInertiaStartingEventHandler::ManipulationInertiaStartingEventHandler(L handler) :
        ManipulationInertiaStartingEventHandler(impl::make_delegate<ManipulationInertiaStartingEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> ManipulationInertiaStartingEventHandler::ManipulationInertiaStartingEventHandler(F* handler) :
        ManipulationInertiaStartingEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> ManipulationInertiaStartingEventHandler::ManipulationInertiaStartingEventHandler(O* object, M method) :
        ManipulationInertiaStartingEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> ManipulationInertiaStartingEventHandler::ManipulationInertiaStartingEventHandler(com_ptr<O>&& object, M method) :
        ManipulationInertiaStartingEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> ManipulationInertiaStartingEventHandler::ManipulationInertiaStartingEventHandler(weak_ref<O>&& object, M method) :
        ManipulationInertiaStartingEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto ManipulationInertiaStartingEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Input::ManipulationInertiaStartingRoutedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<ManipulationInertiaStartingEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> ManipulationStartedEventHandler::ManipulationStartedEventHandler(L handler) :
        ManipulationStartedEventHandler(impl::make_delegate<ManipulationStartedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> ManipulationStartedEventHandler::ManipulationStartedEventHandler(F* handler) :
        ManipulationStartedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> ManipulationStartedEventHandler::ManipulationStartedEventHandler(O* object, M method) :
        ManipulationStartedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> ManipulationStartedEventHandler::ManipulationStartedEventHandler(com_ptr<O>&& object, M method) :
        ManipulationStartedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> ManipulationStartedEventHandler::ManipulationStartedEventHandler(weak_ref<O>&& object, M method) :
        ManipulationStartedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto ManipulationStartedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<ManipulationStartedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> ManipulationStartingEventHandler::ManipulationStartingEventHandler(L handler) :
        ManipulationStartingEventHandler(impl::make_delegate<ManipulationStartingEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> ManipulationStartingEventHandler::ManipulationStartingEventHandler(F* handler) :
        ManipulationStartingEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> ManipulationStartingEventHandler::ManipulationStartingEventHandler(O* object, M method) :
        ManipulationStartingEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> ManipulationStartingEventHandler::ManipulationStartingEventHandler(com_ptr<O>&& object, M method) :
        ManipulationStartingEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> ManipulationStartingEventHandler::ManipulationStartingEventHandler(weak_ref<O>&& object, M method) :
        ManipulationStartingEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto ManipulationStartingEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<ManipulationStartingEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> PointerEventHandler::PointerEventHandler(L handler) :
        PointerEventHandler(impl::make_delegate<PointerEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> PointerEventHandler::PointerEventHandler(F* handler) :
        PointerEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> PointerEventHandler::PointerEventHandler(O* object, M method) :
        PointerEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> PointerEventHandler::PointerEventHandler(com_ptr<O>&& object, M method) :
        PointerEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> PointerEventHandler::PointerEventHandler(weak_ref<O>&& object, M method) :
        PointerEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto PointerEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Input::PointerRoutedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<PointerEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> RightTappedEventHandler::RightTappedEventHandler(L handler) :
        RightTappedEventHandler(impl::make_delegate<RightTappedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> RightTappedEventHandler::RightTappedEventHandler(F* handler) :
        RightTappedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> RightTappedEventHandler::RightTappedEventHandler(O* object, M method) :
        RightTappedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> RightTappedEventHandler::RightTappedEventHandler(com_ptr<O>&& object, M method) :
        RightTappedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> RightTappedEventHandler::RightTappedEventHandler(weak_ref<O>&& object, M method) :
        RightTappedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto RightTappedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Input::RightTappedRoutedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<RightTappedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> TappedEventHandler::TappedEventHandler(L handler) :
        TappedEventHandler(impl::make_delegate<TappedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> TappedEventHandler::TappedEventHandler(F* handler) :
        TappedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> TappedEventHandler::TappedEventHandler(O* object, M method) :
        TappedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> TappedEventHandler::TappedEventHandler(com_ptr<O>&& object, M method) :
        TappedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> TappedEventHandler::TappedEventHandler(weak_ref<O>&& object, M method) :
        TappedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto TappedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Input::TappedRoutedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<TappedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename D, typename... Interfaces>
    struct KeyboardAcceleratorT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, KeyboardAccelerator, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = KeyboardAccelerator;
    protected:
        KeyboardAcceleratorT()
        {
            impl::call_factory<KeyboardAccelerator, IKeyboardAcceleratorFactory>([&](IKeyboardAcceleratorFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ManipulationStartedRoutedEventArgsT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs, winrt::Windows::UI::Xaml::IRoutedEventArgs>,
        impl::base<D, ManipulationStartedRoutedEventArgs, winrt::Windows::UI::Xaml::RoutedEventArgs>
    {
        using composable = ManipulationStartedRoutedEventArgs;
    protected:
        ManipulationStartedRoutedEventArgsT()
        {
            impl::call_factory<ManipulationStartedRoutedEventArgs, IManipulationStartedRoutedEventArgsFactory>([&](IManipulationStartedRoutedEventArgsFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct StandardUICommandT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Input::IStandardUICommand, winrt::Windows::UI::Xaml::Input::IStandardUICommand2, winrt::Windows::UI::Xaml::Input::IXamlUICommand, winrt::Windows::UI::Xaml::Input::ICommand, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, StandardUICommand, winrt::Windows::UI::Xaml::Input::XamlUICommand, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = StandardUICommand;
    protected:
        StandardUICommandT()
        {
            impl::call_factory<StandardUICommand, IStandardUICommandFactory>([&](IStandardUICommandFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
        StandardUICommandT(winrt::Windows::UI::Xaml::Input::StandardUICommandKind const& kind)
        {
            impl::call_factory<StandardUICommand, IStandardUICommandFactory>([&](IStandardUICommandFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithKind(kind, *this, this->m_inner); });
        }
        using impl::consume_t<D, winrt::Windows::UI::Xaml::Input::IStandardUICommand>::Kind;
        using impl::consume_t<D, winrt::Windows::UI::Xaml::Input::IStandardUICommand2>::Kind;
    };
    template <typename D, typename... Interfaces>
    struct XamlUICommandT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Input::IXamlUICommand, winrt::Windows::UI::Xaml::Input::ICommand, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, XamlUICommand, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = XamlUICommand;
    protected:
        XamlUICommandT()
        {
            impl::call_factory<XamlUICommand, IXamlUICommandFactory>([&](IXamlUICommandFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IAccessKeyManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ICommand> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IContextRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IExecuteRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IFindNextElementOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics7> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusMovementResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IHoldingRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IInertiaExpansionBehavior> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IInertiaRotationBehavior> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IInertiaTranslationBehavior> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IInputScope> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IInputScopeName> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IInputScopeNameFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationPivot> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationPivotFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IPointer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IStandardUICommand> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IStandardUICommand2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IStandardUICommandFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IStandardUICommandStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ITappedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IXamlUICommand> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IXamlUICommandFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::IXamlUICommandStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::AccessKeyManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::CharacterReceivedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ContextRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::DoubleTappedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ExecuteRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::FindNextElementOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::FocusManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::FocusMovementResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::GettingFocusEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::HoldingRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::InertiaExpansionBehavior> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::InertiaRotationBehavior> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::InertiaTranslationBehavior> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::InputScope> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::InputScopeName> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::KeyRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::LosingFocusEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ManipulationDeltaRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ManipulationInertiaStartingRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ManipulationPivot> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::NoFocusCandidateFoundEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::Pointer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::PointerRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::RightTappedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::StandardUICommand> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::TappedRoutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Input::XamlUICommand> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
