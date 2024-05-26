// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Documents_H
#define WINRT_Windows_UI_Xaml_Documents_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Xaml.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Text.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Input.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.2.h"
#include "winrt/impl/Windows.UI.Xaml.Documents.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::TextAlignment) consume_Windows_UI_Xaml_Documents_IBlock<D>::TextAlignment() const
    {
        winrt::Windows::UI::Xaml::TextAlignment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlock)->get_TextAlignment(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IBlock<D>::TextAlignment(winrt::Windows::UI::Xaml::TextAlignment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlock)->put_TextAlignment(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Documents_IBlock<D>::LineHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlock)->get_LineHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IBlock<D>::LineHeight(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlock)->put_LineHeight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::LineStackingStrategy) consume_Windows_UI_Xaml_Documents_IBlock<D>::LineStackingStrategy() const
    {
        winrt::Windows::UI::Xaml::LineStackingStrategy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlock)->get_LineStackingStrategy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IBlock<D>::LineStackingStrategy(winrt::Windows::UI::Xaml::LineStackingStrategy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlock)->put_LineStackingStrategy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Documents_IBlock<D>::Margin() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlock)->get_Margin(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IBlock<D>::Margin(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlock)->put_Margin(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::TextAlignment) consume_Windows_UI_Xaml_Documents_IBlock2<D>::HorizontalTextAlignment() const
    {
        winrt::Windows::UI::Xaml::TextAlignment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlock2)->get_HorizontalTextAlignment(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IBlock2<D>::HorizontalTextAlignment(winrt::Windows::UI::Xaml::TextAlignment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlock2)->put_HorizontalTextAlignment(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::Block) consume_Windows_UI_Xaml_Documents_IBlockFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlockFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Documents::Block{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IBlockStatics<D>::TextAlignmentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlockStatics)->get_TextAlignmentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IBlockStatics<D>::LineHeightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlockStatics)->get_LineHeightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IBlockStatics<D>::LineStackingStrategyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlockStatics)->get_LineStackingStrategyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IBlockStatics<D>::MarginProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlockStatics)->get_MarginProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IBlockStatics2<D>::HorizontalTextAlignmentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IBlockStatics2)->get_HorizontalTextAlignmentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Text::ContentLinkInfo) consume_Windows_UI_Xaml_Documents_IContentLink<D>::Info() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_Info(&value));
        return winrt::Windows::UI::Text::ContentLinkInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::Info(winrt::Windows::UI::Text::ContentLinkInfo const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_Info(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Documents_IContentLink<D>::Background() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_Background(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::Background(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_Background(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreCursorType) consume_Windows_UI_Xaml_Documents_IContentLink<D>::Cursor() const
    {
        winrt::Windows::UI::Core::CoreCursorType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_Cursor(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::Cursor(winrt::Windows::UI::Core::CoreCursorType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_Cursor(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusLeft() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusLeft(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusLeft(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusLeft(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusRight() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusRight(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusRight(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusRight(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusUp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusUp(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusUp(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusUp(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusDown() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusDown(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusDown(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusDown(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ElementSoundMode) consume_Windows_UI_Xaml_Documents_IContentLink<D>::ElementSoundMode() const
    {
        winrt::Windows::UI::Xaml::ElementSoundMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_ElementSoundMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::ElementSoundMode(winrt::Windows::UI::Xaml::ElementSoundMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_ElementSoundMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FocusState) consume_Windows_UI_Xaml_Documents_IContentLink<D>::FocusState() const
    {
        winrt::Windows::UI::Xaml::FocusState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_FocusState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusUpNavigationStrategy() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusUpNavigationStrategy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusUpNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusUpNavigationStrategy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusDownNavigationStrategy() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusDownNavigationStrategy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusDownNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusDownNavigationStrategy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusLeftNavigationStrategy() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusLeftNavigationStrategy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusLeftNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusLeftNavigationStrategy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusRightNavigationStrategy() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusRightNavigationStrategy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusRightNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusRightNavigationStrategy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_IContentLink<D>::IsTabStop() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_IsTabStop(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::IsTabStop(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_IsTabStop(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Documents_IContentLink<D>::TabIndex() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->get_TabIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::TabIndex(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->put_TabIndex(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Documents_IContentLink<D>::Invoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::ContentLink, winrt::Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->add_Invoked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Documents_IContentLink<D>::Invoked_revoker consume_Windows_UI_Xaml_Documents_IContentLink<D>::Invoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::ContentLink, winrt::Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Invoked_revoker>(this, Invoked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::Invoked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->remove_Invoked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Documents_IContentLink<D>::GotFocus(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->add_GotFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Documents_IContentLink<D>::GotFocus_revoker consume_Windows_UI_Xaml_Documents_IContentLink<D>::GotFocus(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::GotFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->remove_GotFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Documents_IContentLink<D>::LostFocus(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->add_LostFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Documents_IContentLink<D>::LostFocus_revoker consume_Windows_UI_Xaml_Documents_IContentLink<D>::LostFocus(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, LostFocus_revoker>(this, LostFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLink<D>::LostFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->remove_LostFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_IContentLink<D>::Focus(winrt::Windows::UI::Xaml::FocusState const& value) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLink)->Focus(static_cast<int32_t>(value), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Text::ContentLinkInfo) consume_Windows_UI_Xaml_Documents_IContentLinkInvokedEventArgs<D>::ContentLinkInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs)->get_ContentLinkInfo(&value));
        return winrt::Windows::UI::Text::ContentLinkInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_IContentLinkInvokedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IContentLinkInvokedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::ContentLinkProvider) consume_Windows_UI_Xaml_Documents_IContentLinkProviderFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkProviderFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Documents::ContentLinkProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::BackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_BackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::CursorProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_CursorProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusLeftProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusLeftProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusRightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusRightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusUpProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusUpProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusDownProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusDownProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::ElementSoundModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_ElementSoundModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::FocusStateProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_FocusStateProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusUpNavigationStrategyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusUpNavigationStrategyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusDownNavigationStrategyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusDownNavigationStrategyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusLeftNavigationStrategyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusLeftNavigationStrategyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusRightNavigationStrategyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusRightNavigationStrategyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::IsTabStopProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_IsTabStopProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::TabIndexProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IContentLinkStatics)->get_TabIndexProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::UnicodeString() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->get_UnicodeString(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::UnicodeString(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->put_UnicodeString(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::Indices() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->get_Indices(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::Indices(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->put_Indices(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::FontUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->get_FontUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::FontUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->put_FontUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::StyleSimulations) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::StyleSimulations() const
    {
        winrt::Windows::UI::Xaml::Media::StyleSimulations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->get_StyleSimulations(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::StyleSimulations(winrt::Windows::UI::Xaml::Media::StyleSimulations const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->put_StyleSimulations(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::FontRenderingEmSize() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->get_FontRenderingEmSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::FontRenderingEmSize(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->put_FontRenderingEmSize(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::OriginX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->get_OriginX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::OriginX(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->put_OriginX(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::OriginY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->get_OriginY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::OriginY(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->put_OriginY(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::Fill() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->get_Fill(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IGlyphs<D>::Fill(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs)->put_Fill(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_IGlyphs2<D>::IsColorFontEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs2)->get_IsColorFontEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IGlyphs2<D>::IsColorFontEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs2)->put_IsColorFontEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Documents_IGlyphs2<D>::ColorFontPaletteIndex() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs2)->get_ColorFontPaletteIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IGlyphs2<D>::ColorFontPaletteIndex(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphs2)->put_ColorFontPaletteIndex(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::UnicodeStringProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphsStatics)->get_UnicodeStringProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::IndicesProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphsStatics)->get_IndicesProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::FontUriProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphsStatics)->get_FontUriProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::StyleSimulationsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphsStatics)->get_StyleSimulationsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::FontRenderingEmSizeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphsStatics)->get_FontRenderingEmSizeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::OriginXProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphsStatics)->get_OriginXProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::OriginYProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphsStatics)->get_OriginYProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::FillProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphsStatics)->get_FillProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IGlyphsStatics2<D>::IsColorFontEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphsStatics2)->get_IsColorFontEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IGlyphsStatics2<D>::ColorFontPaletteIndexProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IGlyphsStatics2)->get_ColorFontPaletteIndexProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_UI_Xaml_Documents_IHyperlink<D>::NavigateUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink)->get_NavigateUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink<D>::NavigateUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink)->put_NavigateUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Documents_IHyperlink<D>::Click(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::Hyperlink, winrt::Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink)->add_Click(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Documents_IHyperlink<D>::Click_revoker consume_Windows_UI_Xaml_Documents_IHyperlink<D>::Click(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::Hyperlink, winrt::Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Click_revoker>(this, Click(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink<D>::Click(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink)->remove_Click(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::UnderlineStyle) consume_Windows_UI_Xaml_Documents_IHyperlink2<D>::UnderlineStyle() const
    {
        winrt::Windows::UI::Xaml::Documents::UnderlineStyle value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink2)->get_UnderlineStyle(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink2<D>::UnderlineStyle(winrt::Windows::UI::Xaml::Documents::UnderlineStyle const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink2)->put_UnderlineStyle(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusLeft() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink3)->get_XYFocusLeft(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusLeft(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink3)->put_XYFocusLeft(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusRight() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink3)->get_XYFocusRight(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusRight(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink3)->put_XYFocusRight(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusUp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink3)->get_XYFocusUp(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusUp(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink3)->put_XYFocusUp(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusDown() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink3)->get_XYFocusDown(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusDown(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink3)->put_XYFocusDown(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ElementSoundMode) consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::ElementSoundMode() const
    {
        winrt::Windows::UI::Xaml::ElementSoundMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink3)->get_ElementSoundMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::ElementSoundMode(winrt::Windows::UI::Xaml::ElementSoundMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink3)->put_ElementSoundMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FocusState) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::FocusState() const
    {
        winrt::Windows::UI::Xaml::FocusState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->get_FocusState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusUpNavigationStrategy() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->get_XYFocusUpNavigationStrategy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusUpNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->put_XYFocusUpNavigationStrategy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusDownNavigationStrategy() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->get_XYFocusDownNavigationStrategy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusDownNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->put_XYFocusDownNavigationStrategy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusLeftNavigationStrategy() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->get_XYFocusLeftNavigationStrategy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusLeftNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->put_XYFocusLeftNavigationStrategy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusRightNavigationStrategy() const
    {
        winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->get_XYFocusRightNavigationStrategy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusRightNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->put_XYFocusRightNavigationStrategy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::GotFocus(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->add_GotFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::GotFocus_revoker consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::GotFocus(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::GotFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->remove_GotFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::LostFocus(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->add_LostFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::LostFocus_revoker consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::LostFocus(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, LostFocus_revoker>(this, LostFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::LostFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->remove_LostFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::Focus(winrt::Windows::UI::Xaml::FocusState const& value) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink4)->Focus(static_cast<int32_t>(value), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_IHyperlink5<D>::IsTabStop() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink5)->get_IsTabStop(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink5<D>::IsTabStop(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink5)->put_IsTabStop(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Documents_IHyperlink5<D>::TabIndex() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink5)->get_TabIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IHyperlink5<D>::TabIndex(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlink5)->put_TabIndex(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics<D>::NavigateUriProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics)->get_NavigateUriProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics2<D>::UnderlineStyleProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics2)->get_UnderlineStyleProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3<D>::XYFocusLeftProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3)->get_XYFocusLeftProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3<D>::XYFocusRightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3)->get_XYFocusRightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3<D>::XYFocusUpProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3)->get_XYFocusUpProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3<D>::XYFocusDownProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3)->get_XYFocusDownProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3<D>::ElementSoundModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3)->get_ElementSoundModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4<D>::FocusStateProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4)->get_FocusStateProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4<D>::XYFocusUpNavigationStrategyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4)->get_XYFocusUpNavigationStrategyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4<D>::XYFocusDownNavigationStrategyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4)->get_XYFocusDownNavigationStrategyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4<D>::XYFocusLeftNavigationStrategyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4)->get_XYFocusLeftNavigationStrategyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4<D>::XYFocusRightNavigationStrategyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4)->get_XYFocusRightNavigationStrategyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics5<D>::IsTabStopProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics5)->get_IsTabStopProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IHyperlinkStatics5<D>::TabIndexProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics5)->get_TabIndexProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::Inline) consume_Windows_UI_Xaml_Documents_IInlineFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IInlineFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Documents::Inline{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Documents_IInlineUIContainer<D>::Child() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IInlineUIContainer)->get_Child(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IInlineUIContainer<D>::Child(winrt::Windows::UI::Xaml::UIElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IInlineUIContainer)->put_Child(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::InlineCollection) consume_Windows_UI_Xaml_Documents_IParagraph<D>::Inlines() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IParagraph)->get_Inlines(&value));
        return winrt::Windows::UI::Xaml::Documents::InlineCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Documents_IParagraph<D>::TextIndent() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IParagraph)->get_TextIndent(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IParagraph<D>::TextIndent(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IParagraph)->put_TextIndent(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IParagraphStatics<D>::TextIndentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IParagraphStatics)->get_TextIndentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Documents_IRun<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IRun)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IRun<D>::Text(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IRun)->put_Text(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FlowDirection) consume_Windows_UI_Xaml_Documents_IRun<D>::FlowDirection() const
    {
        winrt::Windows::UI::Xaml::FlowDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IRun)->get_FlowDirection(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_IRun<D>::FlowDirection(winrt::Windows::UI::Xaml::FlowDirection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IRun)->put_FlowDirection(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_IRunStatics<D>::FlowDirectionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::IRunStatics)->get_FlowDirectionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::InlineCollection) consume_Windows_UI_Xaml_Documents_ISpan<D>::Inlines() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ISpan)->get_Inlines(&value));
        return winrt::Windows::UI::Xaml::Documents::InlineCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ISpan<D>::Inlines(winrt::Windows::UI::Xaml::Documents::InlineCollection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ISpan)->put_Inlines(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::Span) consume_Windows_UI_Xaml_Documents_ISpanFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ISpanFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Documents::Span{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Documents_ITextElement<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontSize() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->get_FontSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontSize(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->put_FontSize(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::FontFamily) consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontFamily() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->get_FontFamily(&value));
        return winrt::Windows::UI::Xaml::Media::FontFamily{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontFamily(winrt::Windows::UI::Xaml::Media::FontFamily const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->put_FontFamily(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Text::FontWeight) consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontWeight() const
    {
        winrt::Windows::UI::Text::FontWeight value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->get_FontWeight(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontWeight(winrt::Windows::UI::Text::FontWeight const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->put_FontWeight(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Text::FontStyle) consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontStyle() const
    {
        winrt::Windows::UI::Text::FontStyle value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->get_FontStyle(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontStyle(winrt::Windows::UI::Text::FontStyle const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->put_FontStyle(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Text::FontStretch) consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontStretch() const
    {
        winrt::Windows::UI::Text::FontStretch value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->get_FontStretch(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontStretch(winrt::Windows::UI::Text::FontStretch const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->put_FontStretch(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Documents_ITextElement<D>::CharacterSpacing() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->get_CharacterSpacing(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement<D>::CharacterSpacing(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->put_CharacterSpacing(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Documents_ITextElement<D>::Foreground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->get_Foreground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement<D>::Foreground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->put_Foreground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Documents_ITextElement<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement<D>::Language(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->put_Language(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::TextPointer) consume_Windows_UI_Xaml_Documents_ITextElement<D>::ContentStart() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->get_ContentStart(&value));
        return winrt::Windows::UI::Xaml::Documents::TextPointer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::TextPointer) consume_Windows_UI_Xaml_Documents_ITextElement<D>::ContentEnd() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->get_ContentEnd(&value));
        return winrt::Windows::UI::Xaml::Documents::TextPointer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::TextPointer) consume_Windows_UI_Xaml_Documents_ITextElement<D>::ElementStart() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->get_ElementStart(&value));
        return winrt::Windows::UI::Xaml::Documents::TextPointer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::TextPointer) consume_Windows_UI_Xaml_Documents_ITextElement<D>::ElementEnd() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->get_ElementEnd(&value));
        return winrt::Windows::UI::Xaml::Documents::TextPointer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Documents_ITextElement<D>::FindName(param::hstring const& name) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement)->FindName(*(void**)(&name), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITextElement2<D>::IsTextScaleFactorEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement2)->get_IsTextScaleFactorEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement2<D>::IsTextScaleFactorEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement2)->put_IsTextScaleFactorEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITextElement3<D>::AllowFocusOnInteraction() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement3)->get_AllowFocusOnInteraction(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement3<D>::AllowFocusOnInteraction(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement3)->put_AllowFocusOnInteraction(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Documents_ITextElement3<D>::AccessKey() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement3)->get_AccessKey(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement3<D>::AccessKey(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement3)->put_AccessKey(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITextElement3<D>::ExitDisplayModeOnAccessKeyInvoked() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement3)->get_ExitDisplayModeOnAccessKeyInvoked(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement3<D>::ExitDisplayModeOnAccessKeyInvoked(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement3)->put_ExitDisplayModeOnAccessKeyInvoked(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Text::TextDecorations) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::TextDecorations() const
    {
        winrt::Windows::UI::Text::TextDecorations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->get_TextDecorations(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::TextDecorations(winrt::Windows::UI::Text::TextDecorations const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->put_TextDecorations(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::IsAccessKeyScope() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->get_IsAccessKeyScope(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::IsAccessKeyScope(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->put_IsAccessKeyScope(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyScopeOwner() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->get_AccessKeyScopeOwner(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyScopeOwner(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->put_AccessKeyScopeOwner(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::KeyTipPlacementMode) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::KeyTipPlacementMode() const
    {
        winrt::Windows::UI::Xaml::Input::KeyTipPlacementMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->get_KeyTipPlacementMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::KeyTipPlacementMode(winrt::Windows::UI::Xaml::Input::KeyTipPlacementMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->put_KeyTipPlacementMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::KeyTipHorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->get_KeyTipHorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::KeyTipHorizontalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->put_KeyTipHorizontalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::KeyTipVerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->get_KeyTipVerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::KeyTipVerticalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->put_KeyTipVerticalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->add_AccessKeyDisplayRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayRequested_revoker consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AccessKeyDisplayRequested_revoker>(this, AccessKeyDisplayRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->remove_AccessKeyDisplayRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayDismissed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->add_AccessKeyDisplayDismissed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayDismissed_revoker consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayDismissed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AccessKeyDisplayDismissed_revoker>(this, AccessKeyDisplayDismissed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayDismissed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->remove_AccessKeyDisplayDismissed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyInvoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->add_AccessKeyInvoked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyInvoked_revoker consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyInvoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AccessKeyInvoked_revoker>(this, AccessKeyInvoked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyInvoked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement4)->remove_AccessKeyInvoked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::XamlRoot) consume_Windows_UI_Xaml_Documents_ITextElement5<D>::XamlRoot() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement5)->get_XamlRoot(&value));
        return winrt::Windows::UI::Xaml::XamlRoot{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElement5<D>::XamlRoot(winrt::Windows::UI::Xaml::XamlRoot const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElement5)->put_XamlRoot(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextElementOverrides<D>::OnDisconnectVisualChildren() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementOverrides)->OnDisconnectVisualChildren());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::FontSizeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics)->get_FontSizeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::FontFamilyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics)->get_FontFamilyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::FontWeightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics)->get_FontWeightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::FontStyleProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics)->get_FontStyleProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::FontStretchProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics)->get_FontStretchProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::CharacterSpacingProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics)->get_CharacterSpacingProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::ForegroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics)->get_ForegroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::LanguageProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics)->get_LanguageProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics2<D>::IsTextScaleFactorEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics2)->get_IsTextScaleFactorEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics3<D>::AllowFocusOnInteractionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics3)->get_AllowFocusOnInteractionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics3<D>::AccessKeyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics3)->get_AccessKeyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics3<D>::ExitDisplayModeOnAccessKeyInvokedProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics3)->get_ExitDisplayModeOnAccessKeyInvokedProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>::TextDecorationsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics4)->get_TextDecorationsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>::IsAccessKeyScopeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics4)->get_IsAccessKeyScopeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>::AccessKeyScopeOwnerProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics4)->get_AccessKeyScopeOwnerProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>::KeyTipPlacementModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics4)->get_KeyTipPlacementModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>::KeyTipHorizontalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics4)->get_KeyTipHorizontalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>::KeyTipVerticalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextElementStatics4)->get_KeyTipVerticalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Documents::TextRange>) consume_Windows_UI_Xaml_Documents_ITextHighlighter<D>::Ranges() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextHighlighter)->get_Ranges(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Documents::TextRange>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Documents_ITextHighlighter<D>::Foreground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextHighlighter)->get_Foreground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextHighlighter<D>::Foreground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextHighlighter)->put_Foreground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Documents_ITextHighlighter<D>::Background() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextHighlighter)->get_Background(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITextHighlighter<D>::Background(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextHighlighter)->put_Background(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::TextHighlighter) consume_Windows_UI_Xaml_Documents_ITextHighlighterFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextHighlighterFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Documents::TextHighlighter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextHighlighterStatics<D>::ForegroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextHighlighterStatics)->get_ForegroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITextHighlighterStatics<D>::BackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextHighlighterStatics)->get_BackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Documents_ITextPointer<D>::Parent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextPointer)->get_Parent(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FrameworkElement) consume_Windows_UI_Xaml_Documents_ITextPointer<D>::VisualParent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextPointer)->get_VisualParent(&value));
        return winrt::Windows::UI::Xaml::FrameworkElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::LogicalDirection) consume_Windows_UI_Xaml_Documents_ITextPointer<D>::LogicalDirection() const
    {
        winrt::Windows::UI::Xaml::Documents::LogicalDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextPointer)->get_LogicalDirection(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Documents_ITextPointer<D>::Offset() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextPointer)->get_Offset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Documents_ITextPointer<D>::GetCharacterRect(winrt::Windows::UI::Xaml::Documents::LogicalDirection const& direction) const
    {
        winrt::Windows::Foundation::Rect result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextPointer)->GetCharacterRect(static_cast<int32_t>(direction), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::TextPointer) consume_Windows_UI_Xaml_Documents_ITextPointer<D>::GetPositionAtOffset(int32_t offset, winrt::Windows::UI::Xaml::Documents::LogicalDirection const& direction) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITextPointer)->GetPositionAtOffset(offset, static_cast<int32_t>(direction), &result));
        return winrt::Windows::UI::Xaml::Documents::TextPointer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::AnnotationAlternatesProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_AnnotationAlternatesProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetAnnotationAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetAnnotationAlternates(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetAnnotationAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element, int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetAnnotationAlternates(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::EastAsianExpertFormsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_EastAsianExpertFormsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetEastAsianExpertForms(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetEastAsianExpertForms(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetEastAsianExpertForms(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetEastAsianExpertForms(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::EastAsianLanguageProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_EastAsianLanguageProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontEastAsianLanguage) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetEastAsianLanguage(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        winrt::Windows::UI::Xaml::FontEastAsianLanguage result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetEastAsianLanguage(*(void**)(&element), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetEastAsianLanguage(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontEastAsianLanguage const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetEastAsianLanguage(*(void**)(&element), static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::EastAsianWidthsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_EastAsianWidthsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontEastAsianWidths) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetEastAsianWidths(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        winrt::Windows::UI::Xaml::FontEastAsianWidths result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetEastAsianWidths(*(void**)(&element), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetEastAsianWidths(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontEastAsianWidths const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetEastAsianWidths(*(void**)(&element), static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StandardLigaturesProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StandardLigaturesProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStandardLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStandardLigatures(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStandardLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStandardLigatures(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::ContextualLigaturesProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_ContextualLigaturesProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetContextualLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetContextualLigatures(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetContextualLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetContextualLigatures(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::DiscretionaryLigaturesProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_DiscretionaryLigaturesProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetDiscretionaryLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetDiscretionaryLigatures(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetDiscretionaryLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetDiscretionaryLigatures(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::HistoricalLigaturesProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_HistoricalLigaturesProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetHistoricalLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetHistoricalLigatures(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetHistoricalLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetHistoricalLigatures(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StandardSwashesProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StandardSwashesProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStandardSwashes(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStandardSwashes(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStandardSwashes(winrt::Windows::UI::Xaml::DependencyObject const& element, int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStandardSwashes(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::ContextualSwashesProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_ContextualSwashesProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetContextualSwashes(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetContextualSwashes(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetContextualSwashes(winrt::Windows::UI::Xaml::DependencyObject const& element, int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetContextualSwashes(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::ContextualAlternatesProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_ContextualAlternatesProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetContextualAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetContextualAlternates(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetContextualAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetContextualAlternates(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticAlternatesProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticAlternatesProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticAlternates(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element, int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticAlternates(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet1Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet1Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet1(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet1(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet1(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet1(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet2Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet2Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet2(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet2(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet2(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet2(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet3Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet3Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet3(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet3(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet3(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet3(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet4Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet4Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet4(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet4(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet4(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet4(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet5Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet5Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet5(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet5(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet5(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet5(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet6Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet6Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet6(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet6(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet6(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet6(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet7Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet7Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet7(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet7(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet7(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet7(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet8Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet8Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet8(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet8(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet8(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet8(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet9Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet9Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet9(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet9(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet9(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet9(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet10Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet10Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet10(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet10(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet10(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet10(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet11Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet11Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet11(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet11(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet11(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet11(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet12Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet12Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet12(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet12(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet12(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet12(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet13Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet13Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet13(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet13(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet13(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet13(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet14Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet14Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet14(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet14(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet14(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet14(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet15Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet15Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet15(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet15(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet15(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet15(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet16Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet16Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet16(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet16(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet16(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet16(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet17Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet17Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet17(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet17(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet17(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet17(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet18Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet18Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet18(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet18(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet18(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet18(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet19Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet19Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet19(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet19(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet19(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet19(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet20Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet20Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet20(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet20(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet20(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet20(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::CapitalsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_CapitalsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontCapitals) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetCapitals(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        winrt::Windows::UI::Xaml::FontCapitals result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetCapitals(*(void**)(&element), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetCapitals(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontCapitals const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetCapitals(*(void**)(&element), static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::CapitalSpacingProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_CapitalSpacingProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetCapitalSpacing(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetCapitalSpacing(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetCapitalSpacing(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetCapitalSpacing(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::KerningProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_KerningProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetKerning(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetKerning(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetKerning(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetKerning(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::CaseSensitiveFormsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_CaseSensitiveFormsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetCaseSensitiveForms(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetCaseSensitiveForms(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetCaseSensitiveForms(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetCaseSensitiveForms(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::HistoricalFormsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_HistoricalFormsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetHistoricalForms(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetHistoricalForms(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetHistoricalForms(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetHistoricalForms(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::FractionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_FractionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontFraction) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetFraction(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        winrt::Windows::UI::Xaml::FontFraction result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetFraction(*(void**)(&element), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetFraction(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontFraction const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetFraction(*(void**)(&element), static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::NumeralStyleProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_NumeralStyleProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontNumeralStyle) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetNumeralStyle(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        winrt::Windows::UI::Xaml::FontNumeralStyle result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetNumeralStyle(*(void**)(&element), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetNumeralStyle(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontNumeralStyle const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetNumeralStyle(*(void**)(&element), static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::NumeralAlignmentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_NumeralAlignmentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontNumeralAlignment) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetNumeralAlignment(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        winrt::Windows::UI::Xaml::FontNumeralAlignment result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetNumeralAlignment(*(void**)(&element), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetNumeralAlignment(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontNumeralAlignment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetNumeralAlignment(*(void**)(&element), static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SlashedZeroProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_SlashedZeroProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetSlashedZero(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetSlashedZero(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetSlashedZero(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetSlashedZero(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::MathematicalGreekProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_MathematicalGreekProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetMathematicalGreek(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetMathematicalGreek(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetMathematicalGreek(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetMathematicalGreek(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::VariantsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->get_VariantsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontVariants) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetVariants(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        winrt::Windows::UI::Xaml::FontVariants result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->GetVariants(*(void**)(&element), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetVariants(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontVariants const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Documents::ITypographyStatics)->SetVariants(*(void**)(&element), static_cast<int32_t>(value)));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IBlock> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IBlock>
    {
        int32_t __stdcall get_TextAlignment(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::TextAlignment>(this->shim().TextAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TextAlignment(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TextAlignment(*reinterpret_cast<winrt::Windows::UI::Xaml::TextAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LineHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().LineHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LineHeight(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LineStackingStrategy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::LineStackingStrategy>(this->shim().LineStackingStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LineStackingStrategy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineStackingStrategy(*reinterpret_cast<winrt::Windows::UI::Xaml::LineStackingStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Margin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().Margin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Margin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Margin(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IBlock2> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IBlock2>
    {
        int32_t __stdcall get_HorizontalTextAlignment(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::TextAlignment>(this->shim().HorizontalTextAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HorizontalTextAlignment(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HorizontalTextAlignment(*reinterpret_cast<winrt::Windows::UI::Xaml::TextAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IBlockFactory> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IBlockFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Documents::Block>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IBlockStatics> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IBlockStatics>
    {
        int32_t __stdcall get_TextAlignmentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TextAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LineHeightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().LineHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LineStackingStrategyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().LineStackingStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MarginProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IBlockStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IBlockStatics2>
    {
        int32_t __stdcall get_HorizontalTextAlignmentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().HorizontalTextAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IBold> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IBold>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IContactContentLinkProvider> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IContactContentLinkProvider>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IContentLink> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IContentLink>
    {
        int32_t __stdcall get_Info(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Text::ContentLinkInfo>(this->shim().Info());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Info(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Info(*reinterpret_cast<winrt::Windows::UI::Text::ContentLinkInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Background(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().Background());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Background(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Background(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Cursor(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreCursorType>(this->shim().Cursor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Cursor(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cursor(*reinterpret_cast<winrt::Windows::UI::Core::CoreCursorType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusLeft(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusLeft());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusLeft(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusLeft(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusRight(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusRight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusRight(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusRight(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusUp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusUp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusUp(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusUp(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusDown(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusDown());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusDown(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusDown(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ElementSoundMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ElementSoundMode>(this->shim().ElementSoundMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ElementSoundMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ElementSoundMode(*reinterpret_cast<winrt::Windows::UI::Xaml::ElementSoundMode const*>(&value));
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
        int32_t __stdcall get_XYFocusUpNavigationStrategy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusUpNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusUpNavigationStrategy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusUpNavigationStrategy(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusDownNavigationStrategy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusDownNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusDownNavigationStrategy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusDownNavigationStrategy(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusLeftNavigationStrategy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusLeftNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusLeftNavigationStrategy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusLeftNavigationStrategy(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusRightNavigationStrategy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusRightNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusRightNavigationStrategy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusRightNavigationStrategy(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTabStop(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTabStop());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsTabStop(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsTabStop(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TabIndex(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().TabIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TabIndex(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TabIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Invoked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Invoked(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::ContentLink, winrt::Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Invoked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Invoked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_GotFocus(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
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
            *token = detach_from<winrt::event_token>(this->shim().LostFocus(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LostFocus(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LostFocus(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall Focus(int32_t value, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().Focus(*reinterpret_cast<winrt::Windows::UI::Xaml::FocusState const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs>
    {
        int32_t __stdcall get_ContentLinkInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Text::ContentLinkInfo>(this->shim().ContentLinkInfo());
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
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IContentLinkProvider> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IContentLinkProvider>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IContentLinkProviderCollection> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IContentLinkProviderCollection>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IContentLinkProviderFactory> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IContentLinkProviderFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Documents::ContentLinkProvider>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IContentLinkStatics> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IContentLinkStatics>
    {
        int32_t __stdcall get_BackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().BackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CursorProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CursorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusLeftProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusLeftProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusRightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusRightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusUpProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusUpProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusDownProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusDownProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ElementSoundModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ElementSoundModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusStateProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FocusStateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusUpNavigationStrategyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusUpNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusDownNavigationStrategyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusDownNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusLeftNavigationStrategyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusLeftNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusRightNavigationStrategyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusRightNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTabStopProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsTabStopProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TabIndexProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TabIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IGlyphs> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IGlyphs>
    {
        int32_t __stdcall get_UnicodeString(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UnicodeString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UnicodeString(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnicodeString(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Indices(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Indices());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Indices(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Indices(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().FontUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FontUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FontUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StyleSimulations(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::StyleSimulations>(this->shim().StyleSimulations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StyleSimulations(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StyleSimulations(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::StyleSimulations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontRenderingEmSize(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FontRenderingEmSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FontRenderingEmSize(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FontRenderingEmSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OriginX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OriginX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OriginX(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OriginX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OriginY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OriginY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OriginY(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OriginY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Fill(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().Fill());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Fill(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Fill(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IGlyphs2> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IGlyphs2>
    {
        int32_t __stdcall get_IsColorFontEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsColorFontEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsColorFontEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsColorFontEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ColorFontPaletteIndex(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ColorFontPaletteIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ColorFontPaletteIndex(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ColorFontPaletteIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IGlyphsStatics> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IGlyphsStatics>
    {
        int32_t __stdcall get_UnicodeStringProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().UnicodeStringProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IndicesProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IndicesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontUriProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FontUriProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StyleSimulationsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StyleSimulationsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontRenderingEmSizeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FontRenderingEmSizeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OriginXProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OriginXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OriginYProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OriginYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FillProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FillProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IGlyphsStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IGlyphsStatics2>
    {
        int32_t __stdcall get_IsColorFontEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsColorFontEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ColorFontPaletteIndexProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ColorFontPaletteIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IHyperlink> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IHyperlink>
    {
        int32_t __stdcall get_NavigateUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().NavigateUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NavigateUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NavigateUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Click(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Click(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::Hyperlink, winrt::Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Click(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Click(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IHyperlink2> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IHyperlink2>
    {
        int32_t __stdcall get_UnderlineStyle(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Documents::UnderlineStyle>(this->shim().UnderlineStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UnderlineStyle(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnderlineStyle(*reinterpret_cast<winrt::Windows::UI::Xaml::Documents::UnderlineStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IHyperlink3> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IHyperlink3>
    {
        int32_t __stdcall get_XYFocusLeft(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusLeft());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusLeft(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusLeft(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusRight(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusRight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusRight(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusRight(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusUp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusUp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusUp(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusUp(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusDown(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusDown());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusDown(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusDown(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ElementSoundMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::ElementSoundMode>(this->shim().ElementSoundMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ElementSoundMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ElementSoundMode(*reinterpret_cast<winrt::Windows::UI::Xaml::ElementSoundMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IHyperlink4> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IHyperlink4>
    {
        int32_t __stdcall get_FocusState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::FocusState>(this->shim().FocusState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusUpNavigationStrategy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusUpNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusUpNavigationStrategy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusUpNavigationStrategy(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusDownNavigationStrategy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusDownNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusDownNavigationStrategy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusDownNavigationStrategy(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusLeftNavigationStrategy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusLeftNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusLeftNavigationStrategy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusLeftNavigationStrategy(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusRightNavigationStrategy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusRightNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XYFocusRightNavigationStrategy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusRightNavigationStrategy(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_GotFocus(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
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
            *token = detach_from<winrt::event_token>(this->shim().LostFocus(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LostFocus(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LostFocus(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall Focus(int32_t value, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().Focus(*reinterpret_cast<winrt::Windows::UI::Xaml::FocusState const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IHyperlink5> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IHyperlink5>
    {
        int32_t __stdcall get_IsTabStop(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTabStop());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsTabStop(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsTabStop(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TabIndex(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().TabIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TabIndex(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TabIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics>
    {
        int32_t __stdcall get_NavigateUriProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().NavigateUriProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics2>
    {
        int32_t __stdcall get_UnderlineStyleProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().UnderlineStyleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3>
    {
        int32_t __stdcall get_XYFocusLeftProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusLeftProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusRightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusRightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusUpProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusUpProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusDownProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusDownProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ElementSoundModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ElementSoundModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4>
    {
        int32_t __stdcall get_FocusStateProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FocusStateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusUpNavigationStrategyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusUpNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusDownNavigationStrategyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusDownNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusLeftNavigationStrategyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusLeftNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XYFocusRightNavigationStrategyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusRightNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics5> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics5>
    {
        int32_t __stdcall get_IsTabStopProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsTabStopProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TabIndexProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TabIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IInline> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IInline>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IInlineFactory> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IInlineFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Documents::Inline>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IInlineUIContainer> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IInlineUIContainer>
    {
        int32_t __stdcall get_Child(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().Child());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Child(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Child(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IItalic> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IItalic>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ILineBreak> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ILineBreak>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IParagraph> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IParagraph>
    {
        int32_t __stdcall get_Inlines(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Documents::InlineCollection>(this->shim().Inlines());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TextIndent(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().TextIndent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TextIndent(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TextIndent(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IParagraphStatics> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IParagraphStatics>
    {
        int32_t __stdcall get_TextIndentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TextIndentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IPlaceContentLinkProvider> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IPlaceContentLinkProvider>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IRun> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IRun>
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
        int32_t __stdcall get_FlowDirection(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::FlowDirection>(this->shim().FlowDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FlowDirection(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FlowDirection(*reinterpret_cast<winrt::Windows::UI::Xaml::FlowDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IRunStatics> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IRunStatics>
    {
        int32_t __stdcall get_FlowDirectionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FlowDirectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ISpan> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ISpan>
    {
        int32_t __stdcall get_Inlines(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Documents::InlineCollection>(this->shim().Inlines());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Inlines(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Inlines(*reinterpret_cast<winrt::Windows::UI::Xaml::Documents::InlineCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ISpanFactory> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ISpanFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Documents::Span>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextElement> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextElement>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontSize(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FontSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FontSize(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FontSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontFamily(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::FontFamily>(this->shim().FontFamily());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FontFamily(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FontFamily(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::FontFamily const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontWeight(struct struct_Windows_UI_Text_FontWeight* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Text::FontWeight>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Text::FontWeight>(this->shim().FontWeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FontWeight(struct struct_Windows_UI_Text_FontWeight value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FontWeight(*reinterpret_cast<winrt::Windows::UI::Text::FontWeight const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontStyle(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Text::FontStyle>(this->shim().FontStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FontStyle(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FontStyle(*reinterpret_cast<winrt::Windows::UI::Text::FontStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontStretch(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Text::FontStretch>(this->shim().FontStretch());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FontStretch(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FontStretch(*reinterpret_cast<winrt::Windows::UI::Text::FontStretch const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CharacterSpacing(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().CharacterSpacing());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CharacterSpacing(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CharacterSpacing(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Foreground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().Foreground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Foreground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Foreground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Language(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Language(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Language(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentStart(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Documents::TextPointer>(this->shim().ContentStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentEnd(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Documents::TextPointer>(this->shim().ContentEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ElementStart(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Documents::TextPointer>(this->shim().ElementStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ElementEnd(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Documents::TextPointer>(this->shim().ElementEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindName(void* name, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().FindName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextElement2> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextElement2>
    {
        int32_t __stdcall get_IsTextScaleFactorEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTextScaleFactorEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsTextScaleFactorEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsTextScaleFactorEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextElement3> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextElement3>
    {
        int32_t __stdcall get_AllowFocusOnInteraction(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowFocusOnInteraction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowFocusOnInteraction(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowFocusOnInteraction(value);
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
        int32_t __stdcall get_ExitDisplayModeOnAccessKeyInvoked(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ExitDisplayModeOnAccessKeyInvoked());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExitDisplayModeOnAccessKeyInvoked(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExitDisplayModeOnAccessKeyInvoked(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextElement4> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextElement4>
    {
        int32_t __stdcall get_TextDecorations(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Text::TextDecorations>(this->shim().TextDecorations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TextDecorations(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TextDecorations(*reinterpret_cast<winrt::Windows::UI::Text::TextDecorations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAccessKeyScope(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAccessKeyScope());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAccessKeyScope(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAccessKeyScope(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccessKeyScopeOwner(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().AccessKeyScopeOwner());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AccessKeyScopeOwner(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccessKeyScopeOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTipPlacementMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Input::KeyTipPlacementMode>(this->shim().KeyTipPlacementMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyTipPlacementMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyTipPlacementMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::KeyTipPlacementMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTipHorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().KeyTipHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyTipHorizontalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyTipHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTipVerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().KeyTipVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyTipVerticalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyTipVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_AccessKeyDisplayRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AccessKeyDisplayRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AccessKeyDisplayRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccessKeyDisplayRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AccessKeyDisplayDismissed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AccessKeyDisplayDismissed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AccessKeyDisplayDismissed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccessKeyDisplayDismissed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AccessKeyInvoked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AccessKeyInvoked(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AccessKeyInvoked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccessKeyInvoked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextElement5> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextElement5>
    {
        int32_t __stdcall get_XamlRoot(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::XamlRoot>(this->shim().XamlRoot());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XamlRoot(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XamlRoot(*reinterpret_cast<winrt::Windows::UI::Xaml::XamlRoot const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextElementFactory> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextElementFactory>
    {
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextElementOverrides> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextElementOverrides>
    {
        int32_t __stdcall OnDisconnectVisualChildren() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnDisconnectVisualChildren();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextElementStatics> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextElementStatics>
    {
        int32_t __stdcall get_FontSizeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FontSizeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontFamilyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FontFamilyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontWeightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FontWeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontStyleProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FontStyleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontStretchProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FontStretchProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CharacterSpacingProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CharacterSpacingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ForegroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LanguageProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().LanguageProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextElementStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextElementStatics2>
    {
        int32_t __stdcall get_IsTextScaleFactorEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsTextScaleFactorEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextElementStatics3> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextElementStatics3>
    {
        int32_t __stdcall get_AllowFocusOnInteractionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AllowFocusOnInteractionProperty());
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
        int32_t __stdcall get_ExitDisplayModeOnAccessKeyInvokedProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ExitDisplayModeOnAccessKeyInvokedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextElementStatics4> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextElementStatics4>
    {
        int32_t __stdcall get_TextDecorationsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TextDecorationsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAccessKeyScopeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsAccessKeyScopeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccessKeyScopeOwnerProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AccessKeyScopeOwnerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTipPlacementModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipPlacementModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTipHorizontalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTipVerticalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextHighlighter> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextHighlighter>
    {
        int32_t __stdcall get_Ranges(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Documents::TextRange>>(this->shim().Ranges());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Foreground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().Foreground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Foreground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Foreground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Background(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().Background());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Background(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Background(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextHighlighterBase> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextHighlighterBase>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextHighlighterFactory> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextHighlighterFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Documents::TextHighlighter>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextHighlighterStatics> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextHighlighterStatics>
    {
        int32_t __stdcall get_ForegroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().BackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITextPointer> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITextPointer>
    {
        int32_t __stdcall get_Parent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().Parent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VisualParent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::FrameworkElement>(this->shim().VisualParent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LogicalDirection(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Documents::LogicalDirection>(this->shim().LogicalDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Offset(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCharacterRect(int32_t direction, winrt::Windows::Foundation::Rect* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Rect>(this->shim().GetCharacterRect(*reinterpret_cast<winrt::Windows::UI::Xaml::Documents::LogicalDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPositionAtOffset(int32_t offset, int32_t direction, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Documents::TextPointer>(this->shim().GetPositionAtOffset(offset, *reinterpret_cast<winrt::Windows::UI::Xaml::Documents::LogicalDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITypography> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITypography>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::ITypographyStatics> : produce_base<D, winrt::Windows::UI::Xaml::Documents::ITypographyStatics>
    {
        int32_t __stdcall get_AnnotationAlternatesProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AnnotationAlternatesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAnnotationAlternates(void* element, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().GetAnnotationAlternates(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetAnnotationAlternates(void* element, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetAnnotationAlternates(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EastAsianExpertFormsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EastAsianExpertFormsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetEastAsianExpertForms(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetEastAsianExpertForms(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetEastAsianExpertForms(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetEastAsianExpertForms(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EastAsianLanguageProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EastAsianLanguageProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetEastAsianLanguage(void* element, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::FontEastAsianLanguage>(this->shim().GetEastAsianLanguage(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetEastAsianLanguage(void* element, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetEastAsianLanguage(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<winrt::Windows::UI::Xaml::FontEastAsianLanguage const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EastAsianWidthsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EastAsianWidthsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetEastAsianWidths(void* element, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::FontEastAsianWidths>(this->shim().GetEastAsianWidths(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetEastAsianWidths(void* element, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetEastAsianWidths(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<winrt::Windows::UI::Xaml::FontEastAsianWidths const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StandardLigaturesProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StandardLigaturesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStandardLigatures(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStandardLigatures(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStandardLigatures(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStandardLigatures(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContextualLigaturesProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContextualLigaturesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetContextualLigatures(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetContextualLigatures(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetContextualLigatures(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetContextualLigatures(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DiscretionaryLigaturesProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DiscretionaryLigaturesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDiscretionaryLigatures(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetDiscretionaryLigatures(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDiscretionaryLigatures(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDiscretionaryLigatures(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HistoricalLigaturesProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().HistoricalLigaturesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetHistoricalLigatures(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetHistoricalLigatures(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetHistoricalLigatures(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetHistoricalLigatures(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StandardSwashesProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StandardSwashesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStandardSwashes(void* element, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().GetStandardSwashes(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStandardSwashes(void* element, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStandardSwashes(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContextualSwashesProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContextualSwashesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetContextualSwashes(void* element, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().GetContextualSwashes(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetContextualSwashes(void* element, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetContextualSwashes(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContextualAlternatesProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContextualAlternatesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetContextualAlternates(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetContextualAlternates(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetContextualAlternates(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetContextualAlternates(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticAlternatesProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticAlternatesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticAlternates(void* element, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().GetStylisticAlternates(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticAlternates(void* element, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticAlternates(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet1Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet1Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet1(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet1(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet1(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet1(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet2Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet2Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet2(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet2(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet2(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet2(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet3Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet3Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet3(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet3(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet3(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet3(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet4Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet4Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet4(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet4(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet4(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet4(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet5Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet5Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet5(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet5(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet5(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet5(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet6Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet6Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet6(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet6(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet6(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet6(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet7Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet7Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet7(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet7(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet7(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet7(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet8Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet8Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet8(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet8(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet8(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet8(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet9Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet9Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet9(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet9(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet9(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet9(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet10Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet10Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet10(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet10(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet10(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet10(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet11Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet11Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet11(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet11(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet11(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet11(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet12Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet12Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet12(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet12(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet12(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet12(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet13Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet13Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet13(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet13(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet13(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet13(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet14Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet14Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet14(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet14(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet14(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet14(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet15Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet15Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet15(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet15(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet15(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet15(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet16Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet16Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet16(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet16(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet16(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet16(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet17Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet17Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet17(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet17(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet17(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet17(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet18Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet18Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet18(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet18(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet18(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet18(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet19Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet19Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet19(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet19(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet19(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet19(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StylisticSet20Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet20Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStylisticSet20(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetStylisticSet20(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStylisticSet20(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStylisticSet20(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CapitalsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CapitalsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCapitals(void* element, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::FontCapitals>(this->shim().GetCapitals(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetCapitals(void* element, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetCapitals(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<winrt::Windows::UI::Xaml::FontCapitals const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CapitalSpacingProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CapitalSpacingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCapitalSpacing(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetCapitalSpacing(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetCapitalSpacing(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetCapitalSpacing(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KerningProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KerningProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetKerning(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetKerning(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetKerning(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetKerning(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CaseSensitiveFormsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CaseSensitiveFormsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCaseSensitiveForms(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetCaseSensitiveForms(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetCaseSensitiveForms(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetCaseSensitiveForms(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HistoricalFormsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().HistoricalFormsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetHistoricalForms(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetHistoricalForms(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetHistoricalForms(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetHistoricalForms(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FractionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FractionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFraction(void* element, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::FontFraction>(this->shim().GetFraction(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetFraction(void* element, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetFraction(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<winrt::Windows::UI::Xaml::FontFraction const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NumeralStyleProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().NumeralStyleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNumeralStyle(void* element, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::FontNumeralStyle>(this->shim().GetNumeralStyle(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetNumeralStyle(void* element, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetNumeralStyle(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<winrt::Windows::UI::Xaml::FontNumeralStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NumeralAlignmentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().NumeralAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNumeralAlignment(void* element, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::FontNumeralAlignment>(this->shim().GetNumeralAlignment(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetNumeralAlignment(void* element, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetNumeralAlignment(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<winrt::Windows::UI::Xaml::FontNumeralAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SlashedZeroProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SlashedZeroProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSlashedZero(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetSlashedZero(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetSlashedZero(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSlashedZero(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MathematicalGreekProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MathematicalGreekProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMathematicalGreek(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetMathematicalGreek(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetMathematicalGreek(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetMathematicalGreek(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VariantsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().VariantsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetVariants(void* element, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::FontVariants>(this->shim().GetVariants(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetVariants(void* element, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetVariants(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<winrt::Windows::UI::Xaml::FontVariants const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Documents::IUnderline> : produce_base<D, winrt::Windows::UI::Xaml::Documents::IUnderline>
    {
    };
#endif
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Documents::ITextElementOverrides>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Documents::ITextElementOverrides>
{
    auto OnDisconnectVisualChildren()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnDisconnectVisualChildren();
        }

        return this->shim().OnDisconnectVisualChildren();
    }
};
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Documents
{
    inline auto Block::TextAlignmentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBlockStatics const&), Block, IBlockStatics>([](IBlockStatics const& f) { return f.TextAlignmentProperty(); });
    }
    inline auto Block::LineHeightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBlockStatics const&), Block, IBlockStatics>([](IBlockStatics const& f) { return f.LineHeightProperty(); });
    }
    inline auto Block::LineStackingStrategyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBlockStatics const&), Block, IBlockStatics>([](IBlockStatics const& f) { return f.LineStackingStrategyProperty(); });
    }
    inline auto Block::MarginProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBlockStatics const&), Block, IBlockStatics>([](IBlockStatics const& f) { return f.MarginProperty(); });
    }
    inline auto Block::HorizontalTextAlignmentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBlockStatics2 const&), Block, IBlockStatics2>([](IBlockStatics2 const& f) { return f.HorizontalTextAlignmentProperty(); });
    }
    inline Bold::Bold() :
        Bold(impl::call_factory_cast<Bold(*)(winrt::Windows::Foundation::IActivationFactory const&), Bold>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Bold>(); }))
    {
    }
    inline ContactContentLinkProvider::ContactContentLinkProvider() :
        ContactContentLinkProvider(impl::call_factory_cast<ContactContentLinkProvider(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactContentLinkProvider>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactContentLinkProvider>(); }))
    {
    }
    inline ContentLink::ContentLink() :
        ContentLink(impl::call_factory_cast<ContentLink(*)(winrt::Windows::Foundation::IActivationFactory const&), ContentLink>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContentLink>(); }))
    {
    }
    inline auto ContentLink::BackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.BackgroundProperty(); });
    }
    inline auto ContentLink::CursorProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.CursorProperty(); });
    }
    inline auto ContentLink::XYFocusLeftProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.XYFocusLeftProperty(); });
    }
    inline auto ContentLink::XYFocusRightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.XYFocusRightProperty(); });
    }
    inline auto ContentLink::XYFocusUpProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.XYFocusUpProperty(); });
    }
    inline auto ContentLink::XYFocusDownProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.XYFocusDownProperty(); });
    }
    inline auto ContentLink::ElementSoundModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.ElementSoundModeProperty(); });
    }
    inline auto ContentLink::FocusStateProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.FocusStateProperty(); });
    }
    inline auto ContentLink::XYFocusUpNavigationStrategyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.XYFocusUpNavigationStrategyProperty(); });
    }
    inline auto ContentLink::XYFocusDownNavigationStrategyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.XYFocusDownNavigationStrategyProperty(); });
    }
    inline auto ContentLink::XYFocusLeftNavigationStrategyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.XYFocusLeftNavigationStrategyProperty(); });
    }
    inline auto ContentLink::XYFocusRightNavigationStrategyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.XYFocusRightNavigationStrategyProperty(); });
    }
    inline auto ContentLink::IsTabStopProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.IsTabStopProperty(); });
    }
    inline auto ContentLink::TabIndexProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentLinkStatics const&), ContentLink, IContentLinkStatics>([](IContentLinkStatics const& f) { return f.TabIndexProperty(); });
    }
    inline ContentLinkProviderCollection::ContentLinkProviderCollection() :
        ContentLinkProviderCollection(impl::call_factory_cast<ContentLinkProviderCollection(*)(winrt::Windows::Foundation::IActivationFactory const&), ContentLinkProviderCollection>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContentLinkProviderCollection>(); }))
    {
    }
    inline Glyphs::Glyphs() :
        Glyphs(impl::call_factory_cast<Glyphs(*)(winrt::Windows::Foundation::IActivationFactory const&), Glyphs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Glyphs>(); }))
    {
    }
    inline auto Glyphs::UnicodeStringProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGlyphsStatics const&), Glyphs, IGlyphsStatics>([](IGlyphsStatics const& f) { return f.UnicodeStringProperty(); });
    }
    inline auto Glyphs::IndicesProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGlyphsStatics const&), Glyphs, IGlyphsStatics>([](IGlyphsStatics const& f) { return f.IndicesProperty(); });
    }
    inline auto Glyphs::FontUriProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGlyphsStatics const&), Glyphs, IGlyphsStatics>([](IGlyphsStatics const& f) { return f.FontUriProperty(); });
    }
    inline auto Glyphs::StyleSimulationsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGlyphsStatics const&), Glyphs, IGlyphsStatics>([](IGlyphsStatics const& f) { return f.StyleSimulationsProperty(); });
    }
    inline auto Glyphs::FontRenderingEmSizeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGlyphsStatics const&), Glyphs, IGlyphsStatics>([](IGlyphsStatics const& f) { return f.FontRenderingEmSizeProperty(); });
    }
    inline auto Glyphs::OriginXProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGlyphsStatics const&), Glyphs, IGlyphsStatics>([](IGlyphsStatics const& f) { return f.OriginXProperty(); });
    }
    inline auto Glyphs::OriginYProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGlyphsStatics const&), Glyphs, IGlyphsStatics>([](IGlyphsStatics const& f) { return f.OriginYProperty(); });
    }
    inline auto Glyphs::FillProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGlyphsStatics const&), Glyphs, IGlyphsStatics>([](IGlyphsStatics const& f) { return f.FillProperty(); });
    }
    inline auto Glyphs::IsColorFontEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGlyphsStatics2 const&), Glyphs, IGlyphsStatics2>([](IGlyphsStatics2 const& f) { return f.IsColorFontEnabledProperty(); });
    }
    inline auto Glyphs::ColorFontPaletteIndexProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGlyphsStatics2 const&), Glyphs, IGlyphsStatics2>([](IGlyphsStatics2 const& f) { return f.ColorFontPaletteIndexProperty(); });
    }
    inline Hyperlink::Hyperlink() :
        Hyperlink(impl::call_factory_cast<Hyperlink(*)(winrt::Windows::Foundation::IActivationFactory const&), Hyperlink>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Hyperlink>(); }))
    {
    }
    inline auto Hyperlink::NavigateUriProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics const&), Hyperlink, IHyperlinkStatics>([](IHyperlinkStatics const& f) { return f.NavigateUriProperty(); });
    }
    inline auto Hyperlink::UnderlineStyleProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics2 const&), Hyperlink, IHyperlinkStatics2>([](IHyperlinkStatics2 const& f) { return f.UnderlineStyleProperty(); });
    }
    inline auto Hyperlink::XYFocusLeftProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics3 const&), Hyperlink, IHyperlinkStatics3>([](IHyperlinkStatics3 const& f) { return f.XYFocusLeftProperty(); });
    }
    inline auto Hyperlink::XYFocusRightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics3 const&), Hyperlink, IHyperlinkStatics3>([](IHyperlinkStatics3 const& f) { return f.XYFocusRightProperty(); });
    }
    inline auto Hyperlink::XYFocusUpProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics3 const&), Hyperlink, IHyperlinkStatics3>([](IHyperlinkStatics3 const& f) { return f.XYFocusUpProperty(); });
    }
    inline auto Hyperlink::XYFocusDownProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics3 const&), Hyperlink, IHyperlinkStatics3>([](IHyperlinkStatics3 const& f) { return f.XYFocusDownProperty(); });
    }
    inline auto Hyperlink::ElementSoundModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics3 const&), Hyperlink, IHyperlinkStatics3>([](IHyperlinkStatics3 const& f) { return f.ElementSoundModeProperty(); });
    }
    inline auto Hyperlink::FocusStateProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics4 const&), Hyperlink, IHyperlinkStatics4>([](IHyperlinkStatics4 const& f) { return f.FocusStateProperty(); });
    }
    inline auto Hyperlink::XYFocusUpNavigationStrategyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics4 const&), Hyperlink, IHyperlinkStatics4>([](IHyperlinkStatics4 const& f) { return f.XYFocusUpNavigationStrategyProperty(); });
    }
    inline auto Hyperlink::XYFocusDownNavigationStrategyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics4 const&), Hyperlink, IHyperlinkStatics4>([](IHyperlinkStatics4 const& f) { return f.XYFocusDownNavigationStrategyProperty(); });
    }
    inline auto Hyperlink::XYFocusLeftNavigationStrategyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics4 const&), Hyperlink, IHyperlinkStatics4>([](IHyperlinkStatics4 const& f) { return f.XYFocusLeftNavigationStrategyProperty(); });
    }
    inline auto Hyperlink::XYFocusRightNavigationStrategyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics4 const&), Hyperlink, IHyperlinkStatics4>([](IHyperlinkStatics4 const& f) { return f.XYFocusRightNavigationStrategyProperty(); });
    }
    inline auto Hyperlink::IsTabStopProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics5 const&), Hyperlink, IHyperlinkStatics5>([](IHyperlinkStatics5 const& f) { return f.IsTabStopProperty(); });
    }
    inline auto Hyperlink::TabIndexProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IHyperlinkStatics5 const&), Hyperlink, IHyperlinkStatics5>([](IHyperlinkStatics5 const& f) { return f.TabIndexProperty(); });
    }
    inline InlineUIContainer::InlineUIContainer() :
        InlineUIContainer(impl::call_factory_cast<InlineUIContainer(*)(winrt::Windows::Foundation::IActivationFactory const&), InlineUIContainer>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InlineUIContainer>(); }))
    {
    }
    inline Italic::Italic() :
        Italic(impl::call_factory_cast<Italic(*)(winrt::Windows::Foundation::IActivationFactory const&), Italic>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Italic>(); }))
    {
    }
    inline LineBreak::LineBreak() :
        LineBreak(impl::call_factory_cast<LineBreak(*)(winrt::Windows::Foundation::IActivationFactory const&), LineBreak>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<LineBreak>(); }))
    {
    }
    inline Paragraph::Paragraph() :
        Paragraph(impl::call_factory_cast<Paragraph(*)(winrt::Windows::Foundation::IActivationFactory const&), Paragraph>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Paragraph>(); }))
    {
    }
    inline auto Paragraph::TextIndentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IParagraphStatics const&), Paragraph, IParagraphStatics>([](IParagraphStatics const& f) { return f.TextIndentProperty(); });
    }
    inline PlaceContentLinkProvider::PlaceContentLinkProvider() :
        PlaceContentLinkProvider(impl::call_factory_cast<PlaceContentLinkProvider(*)(winrt::Windows::Foundation::IActivationFactory const&), PlaceContentLinkProvider>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PlaceContentLinkProvider>(); }))
    {
    }
    inline Run::Run() :
        Run(impl::call_factory_cast<Run(*)(winrt::Windows::Foundation::IActivationFactory const&), Run>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Run>(); }))
    {
    }
    inline auto Run::FlowDirectionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRunStatics const&), Run, IRunStatics>([](IRunStatics const& f) { return f.FlowDirectionProperty(); });
    }
    inline Span::Span()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<Span, ISpanFactory>([&](ISpanFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto TextElement::FontSizeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics const&), TextElement, ITextElementStatics>([](ITextElementStatics const& f) { return f.FontSizeProperty(); });
    }
    inline auto TextElement::FontFamilyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics const&), TextElement, ITextElementStatics>([](ITextElementStatics const& f) { return f.FontFamilyProperty(); });
    }
    inline auto TextElement::FontWeightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics const&), TextElement, ITextElementStatics>([](ITextElementStatics const& f) { return f.FontWeightProperty(); });
    }
    inline auto TextElement::FontStyleProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics const&), TextElement, ITextElementStatics>([](ITextElementStatics const& f) { return f.FontStyleProperty(); });
    }
    inline auto TextElement::FontStretchProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics const&), TextElement, ITextElementStatics>([](ITextElementStatics const& f) { return f.FontStretchProperty(); });
    }
    inline auto TextElement::CharacterSpacingProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics const&), TextElement, ITextElementStatics>([](ITextElementStatics const& f) { return f.CharacterSpacingProperty(); });
    }
    inline auto TextElement::ForegroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics const&), TextElement, ITextElementStatics>([](ITextElementStatics const& f) { return f.ForegroundProperty(); });
    }
    inline auto TextElement::LanguageProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics const&), TextElement, ITextElementStatics>([](ITextElementStatics const& f) { return f.LanguageProperty(); });
    }
    inline auto TextElement::IsTextScaleFactorEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics2 const&), TextElement, ITextElementStatics2>([](ITextElementStatics2 const& f) { return f.IsTextScaleFactorEnabledProperty(); });
    }
    inline auto TextElement::AllowFocusOnInteractionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics3 const&), TextElement, ITextElementStatics3>([](ITextElementStatics3 const& f) { return f.AllowFocusOnInteractionProperty(); });
    }
    inline auto TextElement::AccessKeyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics3 const&), TextElement, ITextElementStatics3>([](ITextElementStatics3 const& f) { return f.AccessKeyProperty(); });
    }
    inline auto TextElement::ExitDisplayModeOnAccessKeyInvokedProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics3 const&), TextElement, ITextElementStatics3>([](ITextElementStatics3 const& f) { return f.ExitDisplayModeOnAccessKeyInvokedProperty(); });
    }
    inline auto TextElement::TextDecorationsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics4 const&), TextElement, ITextElementStatics4>([](ITextElementStatics4 const& f) { return f.TextDecorationsProperty(); });
    }
    inline auto TextElement::IsAccessKeyScopeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics4 const&), TextElement, ITextElementStatics4>([](ITextElementStatics4 const& f) { return f.IsAccessKeyScopeProperty(); });
    }
    inline auto TextElement::AccessKeyScopeOwnerProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics4 const&), TextElement, ITextElementStatics4>([](ITextElementStatics4 const& f) { return f.AccessKeyScopeOwnerProperty(); });
    }
    inline auto TextElement::KeyTipPlacementModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics4 const&), TextElement, ITextElementStatics4>([](ITextElementStatics4 const& f) { return f.KeyTipPlacementModeProperty(); });
    }
    inline auto TextElement::KeyTipHorizontalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics4 const&), TextElement, ITextElementStatics4>([](ITextElementStatics4 const& f) { return f.KeyTipHorizontalOffsetProperty(); });
    }
    inline auto TextElement::KeyTipVerticalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextElementStatics4 const&), TextElement, ITextElementStatics4>([](ITextElementStatics4 const& f) { return f.KeyTipVerticalOffsetProperty(); });
    }
    inline TextHighlighter::TextHighlighter()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<TextHighlighter, ITextHighlighterFactory>([&](ITextHighlighterFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto TextHighlighter::ForegroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextHighlighterStatics const&), TextHighlighter, ITextHighlighterStatics>([](ITextHighlighterStatics const& f) { return f.ForegroundProperty(); });
    }
    inline auto TextHighlighter::BackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITextHighlighterStatics const&), TextHighlighter, ITextHighlighterStatics>([](ITextHighlighterStatics const& f) { return f.BackgroundProperty(); });
    }
    inline auto Typography::AnnotationAlternatesProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.AnnotationAlternatesProperty(); });
    }
    inline auto Typography::GetAnnotationAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetAnnotationAlternates(element); });
    }
    inline auto Typography::SetAnnotationAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element, int32_t value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetAnnotationAlternates(element, value); });
    }
    inline auto Typography::EastAsianExpertFormsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.EastAsianExpertFormsProperty(); });
    }
    inline auto Typography::GetEastAsianExpertForms(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetEastAsianExpertForms(element); });
    }
    inline auto Typography::SetEastAsianExpertForms(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetEastAsianExpertForms(element, value); });
    }
    inline auto Typography::EastAsianLanguageProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.EastAsianLanguageProperty(); });
    }
    inline auto Typography::GetEastAsianLanguage(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetEastAsianLanguage(element); });
    }
    inline auto Typography::SetEastAsianLanguage(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontEastAsianLanguage const& value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetEastAsianLanguage(element, value); });
    }
    inline auto Typography::EastAsianWidthsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.EastAsianWidthsProperty(); });
    }
    inline auto Typography::GetEastAsianWidths(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetEastAsianWidths(element); });
    }
    inline auto Typography::SetEastAsianWidths(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontEastAsianWidths const& value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetEastAsianWidths(element, value); });
    }
    inline auto Typography::StandardLigaturesProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StandardLigaturesProperty(); });
    }
    inline auto Typography::GetStandardLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStandardLigatures(element); });
    }
    inline auto Typography::SetStandardLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStandardLigatures(element, value); });
    }
    inline auto Typography::ContextualLigaturesProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.ContextualLigaturesProperty(); });
    }
    inline auto Typography::GetContextualLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetContextualLigatures(element); });
    }
    inline auto Typography::SetContextualLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetContextualLigatures(element, value); });
    }
    inline auto Typography::DiscretionaryLigaturesProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.DiscretionaryLigaturesProperty(); });
    }
    inline auto Typography::GetDiscretionaryLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetDiscretionaryLigatures(element); });
    }
    inline auto Typography::SetDiscretionaryLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetDiscretionaryLigatures(element, value); });
    }
    inline auto Typography::HistoricalLigaturesProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.HistoricalLigaturesProperty(); });
    }
    inline auto Typography::GetHistoricalLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetHistoricalLigatures(element); });
    }
    inline auto Typography::SetHistoricalLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetHistoricalLigatures(element, value); });
    }
    inline auto Typography::StandardSwashesProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StandardSwashesProperty(); });
    }
    inline auto Typography::GetStandardSwashes(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStandardSwashes(element); });
    }
    inline auto Typography::SetStandardSwashes(winrt::Windows::UI::Xaml::DependencyObject const& element, int32_t value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStandardSwashes(element, value); });
    }
    inline auto Typography::ContextualSwashesProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.ContextualSwashesProperty(); });
    }
    inline auto Typography::GetContextualSwashes(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetContextualSwashes(element); });
    }
    inline auto Typography::SetContextualSwashes(winrt::Windows::UI::Xaml::DependencyObject const& element, int32_t value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetContextualSwashes(element, value); });
    }
    inline auto Typography::ContextualAlternatesProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.ContextualAlternatesProperty(); });
    }
    inline auto Typography::GetContextualAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetContextualAlternates(element); });
    }
    inline auto Typography::SetContextualAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetContextualAlternates(element, value); });
    }
    inline auto Typography::StylisticAlternatesProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticAlternatesProperty(); });
    }
    inline auto Typography::GetStylisticAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticAlternates(element); });
    }
    inline auto Typography::SetStylisticAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element, int32_t value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticAlternates(element, value); });
    }
    inline auto Typography::StylisticSet1Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet1Property(); });
    }
    inline auto Typography::GetStylisticSet1(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet1(element); });
    }
    inline auto Typography::SetStylisticSet1(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet1(element, value); });
    }
    inline auto Typography::StylisticSet2Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet2Property(); });
    }
    inline auto Typography::GetStylisticSet2(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet2(element); });
    }
    inline auto Typography::SetStylisticSet2(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet2(element, value); });
    }
    inline auto Typography::StylisticSet3Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet3Property(); });
    }
    inline auto Typography::GetStylisticSet3(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet3(element); });
    }
    inline auto Typography::SetStylisticSet3(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet3(element, value); });
    }
    inline auto Typography::StylisticSet4Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet4Property(); });
    }
    inline auto Typography::GetStylisticSet4(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet4(element); });
    }
    inline auto Typography::SetStylisticSet4(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet4(element, value); });
    }
    inline auto Typography::StylisticSet5Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet5Property(); });
    }
    inline auto Typography::GetStylisticSet5(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet5(element); });
    }
    inline auto Typography::SetStylisticSet5(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet5(element, value); });
    }
    inline auto Typography::StylisticSet6Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet6Property(); });
    }
    inline auto Typography::GetStylisticSet6(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet6(element); });
    }
    inline auto Typography::SetStylisticSet6(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet6(element, value); });
    }
    inline auto Typography::StylisticSet7Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet7Property(); });
    }
    inline auto Typography::GetStylisticSet7(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet7(element); });
    }
    inline auto Typography::SetStylisticSet7(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet7(element, value); });
    }
    inline auto Typography::StylisticSet8Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet8Property(); });
    }
    inline auto Typography::GetStylisticSet8(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet8(element); });
    }
    inline auto Typography::SetStylisticSet8(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet8(element, value); });
    }
    inline auto Typography::StylisticSet9Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet9Property(); });
    }
    inline auto Typography::GetStylisticSet9(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet9(element); });
    }
    inline auto Typography::SetStylisticSet9(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet9(element, value); });
    }
    inline auto Typography::StylisticSet10Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet10Property(); });
    }
    inline auto Typography::GetStylisticSet10(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet10(element); });
    }
    inline auto Typography::SetStylisticSet10(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet10(element, value); });
    }
    inline auto Typography::StylisticSet11Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet11Property(); });
    }
    inline auto Typography::GetStylisticSet11(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet11(element); });
    }
    inline auto Typography::SetStylisticSet11(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet11(element, value); });
    }
    inline auto Typography::StylisticSet12Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet12Property(); });
    }
    inline auto Typography::GetStylisticSet12(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet12(element); });
    }
    inline auto Typography::SetStylisticSet12(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet12(element, value); });
    }
    inline auto Typography::StylisticSet13Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet13Property(); });
    }
    inline auto Typography::GetStylisticSet13(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet13(element); });
    }
    inline auto Typography::SetStylisticSet13(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet13(element, value); });
    }
    inline auto Typography::StylisticSet14Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet14Property(); });
    }
    inline auto Typography::GetStylisticSet14(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet14(element); });
    }
    inline auto Typography::SetStylisticSet14(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet14(element, value); });
    }
    inline auto Typography::StylisticSet15Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet15Property(); });
    }
    inline auto Typography::GetStylisticSet15(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet15(element); });
    }
    inline auto Typography::SetStylisticSet15(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet15(element, value); });
    }
    inline auto Typography::StylisticSet16Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet16Property(); });
    }
    inline auto Typography::GetStylisticSet16(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet16(element); });
    }
    inline auto Typography::SetStylisticSet16(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet16(element, value); });
    }
    inline auto Typography::StylisticSet17Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet17Property(); });
    }
    inline auto Typography::GetStylisticSet17(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet17(element); });
    }
    inline auto Typography::SetStylisticSet17(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet17(element, value); });
    }
    inline auto Typography::StylisticSet18Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet18Property(); });
    }
    inline auto Typography::GetStylisticSet18(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet18(element); });
    }
    inline auto Typography::SetStylisticSet18(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet18(element, value); });
    }
    inline auto Typography::StylisticSet19Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet19Property(); });
    }
    inline auto Typography::GetStylisticSet19(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet19(element); });
    }
    inline auto Typography::SetStylisticSet19(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet19(element, value); });
    }
    inline auto Typography::StylisticSet20Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.StylisticSet20Property(); });
    }
    inline auto Typography::GetStylisticSet20(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetStylisticSet20(element); });
    }
    inline auto Typography::SetStylisticSet20(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetStylisticSet20(element, value); });
    }
    inline auto Typography::CapitalsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.CapitalsProperty(); });
    }
    inline auto Typography::GetCapitals(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetCapitals(element); });
    }
    inline auto Typography::SetCapitals(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontCapitals const& value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetCapitals(element, value); });
    }
    inline auto Typography::CapitalSpacingProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.CapitalSpacingProperty(); });
    }
    inline auto Typography::GetCapitalSpacing(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetCapitalSpacing(element); });
    }
    inline auto Typography::SetCapitalSpacing(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetCapitalSpacing(element, value); });
    }
    inline auto Typography::KerningProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.KerningProperty(); });
    }
    inline auto Typography::GetKerning(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetKerning(element); });
    }
    inline auto Typography::SetKerning(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetKerning(element, value); });
    }
    inline auto Typography::CaseSensitiveFormsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.CaseSensitiveFormsProperty(); });
    }
    inline auto Typography::GetCaseSensitiveForms(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetCaseSensitiveForms(element); });
    }
    inline auto Typography::SetCaseSensitiveForms(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetCaseSensitiveForms(element, value); });
    }
    inline auto Typography::HistoricalFormsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.HistoricalFormsProperty(); });
    }
    inline auto Typography::GetHistoricalForms(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetHistoricalForms(element); });
    }
    inline auto Typography::SetHistoricalForms(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetHistoricalForms(element, value); });
    }
    inline auto Typography::FractionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.FractionProperty(); });
    }
    inline auto Typography::GetFraction(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetFraction(element); });
    }
    inline auto Typography::SetFraction(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontFraction const& value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetFraction(element, value); });
    }
    inline auto Typography::NumeralStyleProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.NumeralStyleProperty(); });
    }
    inline auto Typography::GetNumeralStyle(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetNumeralStyle(element); });
    }
    inline auto Typography::SetNumeralStyle(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontNumeralStyle const& value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetNumeralStyle(element, value); });
    }
    inline auto Typography::NumeralAlignmentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.NumeralAlignmentProperty(); });
    }
    inline auto Typography::GetNumeralAlignment(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetNumeralAlignment(element); });
    }
    inline auto Typography::SetNumeralAlignment(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontNumeralAlignment const& value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetNumeralAlignment(element, value); });
    }
    inline auto Typography::SlashedZeroProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.SlashedZeroProperty(); });
    }
    inline auto Typography::GetSlashedZero(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetSlashedZero(element); });
    }
    inline auto Typography::SetSlashedZero(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetSlashedZero(element, value); });
    }
    inline auto Typography::MathematicalGreekProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.MathematicalGreekProperty(); });
    }
    inline auto Typography::GetMathematicalGreek(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetMathematicalGreek(element); });
    }
    inline auto Typography::SetMathematicalGreek(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetMathematicalGreek(element, value); });
    }
    inline auto Typography::VariantsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITypographyStatics const&), Typography, ITypographyStatics>([](ITypographyStatics const& f) { return f.VariantsProperty(); });
    }
    inline auto Typography::GetVariants(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.GetVariants(element); });
    }
    inline auto Typography::SetVariants(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontVariants const& value)
    {
        impl::call_factory<Typography, ITypographyStatics>([&](ITypographyStatics const& f) { return f.SetVariants(element, value); });
    }
    inline Underline::Underline() :
        Underline(impl::call_factory_cast<Underline(*)(winrt::Windows::Foundation::IActivationFactory const&), Underline>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Underline>(); }))
    {
    }
    template <typename D> WINRT_IMPL_AUTO(void) ITextElementOverridesT<D>::OnDisconnectVisualChildren() const
    {
        return shim().template try_as<ITextElementOverrides>().OnDisconnectVisualChildren();
    }
    template <typename D, typename... Interfaces>
    struct BlockT :
        implements<D, winrt::Windows::UI::Xaml::Documents::ITextElementOverrides, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Documents::IBlock, winrt::Windows::UI::Xaml::Documents::IBlock2, winrt::Windows::UI::Xaml::Documents::ITextElement, winrt::Windows::UI::Xaml::Documents::ITextElement2, winrt::Windows::UI::Xaml::Documents::ITextElement3, winrt::Windows::UI::Xaml::Documents::ITextElement4, winrt::Windows::UI::Xaml::Documents::ITextElement5, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, Block, winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Documents::ITextElementOverridesT<D>
    {
        using composable = Block;
    protected:
        BlockT()
        {
            impl::call_factory<Block, IBlockFactory>([&](IBlockFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ContentLinkProviderT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Documents::IContentLinkProvider, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ContentLinkProvider, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = ContentLinkProvider;
    protected:
        ContentLinkProviderT()
        {
            impl::call_factory<ContentLinkProvider, IContentLinkProviderFactory>([&](IContentLinkProviderFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct InlineT :
        implements<D, winrt::Windows::UI::Xaml::Documents::ITextElementOverrides, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Documents::IInline, winrt::Windows::UI::Xaml::Documents::ITextElement, winrt::Windows::UI::Xaml::Documents::ITextElement2, winrt::Windows::UI::Xaml::Documents::ITextElement3, winrt::Windows::UI::Xaml::Documents::ITextElement4, winrt::Windows::UI::Xaml::Documents::ITextElement5, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, Inline, winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Documents::ITextElementOverridesT<D>
    {
        using composable = Inline;
    protected:
        InlineT()
        {
            impl::call_factory<Inline, IInlineFactory>([&](IInlineFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct SpanT :
        implements<D, winrt::Windows::UI::Xaml::Documents::ITextElementOverrides, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Documents::ISpan, winrt::Windows::UI::Xaml::Documents::IInline, winrt::Windows::UI::Xaml::Documents::ITextElement, winrt::Windows::UI::Xaml::Documents::ITextElement2, winrt::Windows::UI::Xaml::Documents::ITextElement3, winrt::Windows::UI::Xaml::Documents::ITextElement4, winrt::Windows::UI::Xaml::Documents::ITextElement5, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, Span, winrt::Windows::UI::Xaml::Documents::Inline, winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Documents::ITextElementOverridesT<D>
    {
        using composable = Span;
    protected:
        SpanT()
        {
            impl::call_factory<Span, ISpanFactory>([&](ISpanFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct TextHighlighterT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Documents::ITextHighlighter>,
        impl::base<D, TextHighlighter>
    {
        using composable = TextHighlighter;
    protected:
        TextHighlighterT()
        {
            impl::call_factory<TextHighlighter, ITextHighlighterFactory>([&](ITextHighlighterFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IBlock> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IBlock2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IBlockFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IBlockStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IBlockStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IBold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContactContentLinkProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContentLink> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContentLinkProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContentLinkStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IGlyphs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IGlyphs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlink> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlink2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlink3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlink4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlink5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IInline> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IInlineFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IInlineUIContainer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IItalic> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ILineBreak> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IParagraph> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IParagraphStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IPlaceContentLinkProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IRun> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IRunStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ISpan> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ISpanFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElement2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElement3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElement4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElement5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElementFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElementOverrides> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElementStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElementStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElementStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElementStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextHighlighter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextHighlighterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextHighlighterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextPointer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITypography> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITypographyStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::IUnderline> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::Block> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::BlockCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::Bold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ContactContentLinkProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ContentLink> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ContentLinkProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::ContentLinkProviderCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::Glyphs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::Hyperlink> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::Inline> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::InlineCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::InlineUIContainer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::Italic> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::LineBreak> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::Paragraph> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::PlaceContentLinkProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::Run> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::Span> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::TextElement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::TextHighlighter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::TextHighlighterBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::TextPointer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::Typography> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Documents::Underline> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
