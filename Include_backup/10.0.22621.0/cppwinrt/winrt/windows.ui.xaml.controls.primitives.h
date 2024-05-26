// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Controls_Primitives_H
#define WINRT_Windows_UI_Xaml_Controls_Primitives_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Xaml.Controls.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.2.h"
#include "winrt/impl/Windows.UI.Xaml.Data.2.h"
#include "winrt/impl/Windows.UI.Xaml.Input.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Animation.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Primitives.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IAppBarButtonTemplateSettings<D>::KeyboardAcceleratorTextMinWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarButtonTemplateSettings)->get_KeyboardAcceleratorTextMinWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::ClipRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_ClipRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::CompactVerticalDelta() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_CompactVerticalDelta(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::CompactRootMargin() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_CompactRootMargin(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::MinimalVerticalDelta() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_MinimalVerticalDelta(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::MinimalRootMargin() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_MinimalRootMargin(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::HiddenVerticalDelta() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_HiddenVerticalDelta(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings<D>::HiddenRootMargin() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings)->get_HiddenRootMargin(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings2<D>::NegativeCompactVerticalDelta() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings2)->get_NegativeCompactVerticalDelta(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings2<D>::NegativeMinimalVerticalDelta() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings2)->get_NegativeMinimalVerticalDelta(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IAppBarTemplateSettings2<D>::NegativeHiddenVerticalDelta() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings2)->get_NegativeHiddenVerticalDelta(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IAppBarToggleButtonTemplateSettings<D>::KeyboardAcceleratorTextMinWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarToggleButtonTemplateSettings)->get_KeyboardAcceleratorTextMinWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::ClickMode) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::ClickMode() const
    {
        winrt::Windows::UI::Xaml::Controls::ClickMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase)->get_ClickMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::ClickMode(winrt::Windows::UI::Xaml::Controls::ClickMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase)->put_ClickMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::IsPointerOver() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase)->get_IsPointerOver(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::IsPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase)->get_IsPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::ICommand) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::Command() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase)->get_Command(&value));
        return winrt::Windows::UI::Xaml::Input::ICommand{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::Command(winrt::Windows::UI::Xaml::Input::ICommand const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase)->put_Command(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::CommandParameter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase)->get_CommandParameter(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::CommandParameter(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase)->put_CommandParameter(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::Click(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase)->add_Click(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::Click_revoker consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::Click(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, Click_revoker>(this, Click(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBase<D>::Click(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase)->remove_Click(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::ButtonBase) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBaseFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::ButtonBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBaseStatics<D>::ClickModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics)->get_ClickModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBaseStatics<D>::IsPointerOverProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics)->get_IsPointerOverProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBaseStatics<D>::IsPressedProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics)->get_IsPressedProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBaseStatics<D>::CommandProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics)->get_CommandProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IButtonBaseStatics<D>::CommandParameterProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics)->get_CommandParameterProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::MinViewWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_MinViewWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::HeaderText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_HeaderText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay1() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay1(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay2() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay2(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay3() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay3(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay4() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay4(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay5() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay5(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay6() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay6(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::WeekDay7() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_WeekDay7(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::HasMoreContentAfter() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_HasMoreContentAfter(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::HasMoreContentBefore() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_HasMoreContentBefore(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::HasMoreViews() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_HasMoreViews(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::ClipRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_ClipRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::CenterX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_CenterX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICalendarViewTemplateSettings<D>::CenterY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings)->get_CenterY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::CanVerticallyScroll() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_CanVerticallyScroll(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::CanVerticallyScroll(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->put_CanVerticallyScroll(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::CanHorizontallyScroll() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_CanHorizontallyScroll(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::CanHorizontallyScroll(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->put_CanHorizontallyScroll(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::ExtentWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_ExtentWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::ExtentHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_ExtentHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::ViewportWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_ViewportWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::ViewportHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_ViewportHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::HorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_HorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::VerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_VerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::ScrollOwner() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->get_ScrollOwner(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::ScrollOwner(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->put_ScrollOwner(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::LineUp() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->LineUp());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::LineDown() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->LineDown());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::LineLeft() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->LineLeft());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::LineRight() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->LineRight());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::PageUp() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->PageUp());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::PageDown() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->PageDown());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::PageLeft() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->PageLeft());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::PageRight() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->PageRight());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::MouseWheelUp() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->MouseWheelUp());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::MouseWheelDown() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->MouseWheelDown());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::MouseWheelLeft() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->MouseWheelLeft());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::MouseWheelRight() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->MouseWheelRight());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::SetHorizontalOffset(double offset) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->SetHorizontalOffset(offset));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::SetVerticalOffset(double offset) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->SetVerticalOffset(offset));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanel<D>::MakeVisible(winrt::Windows::UI::Xaml::UIElement const& visual, winrt::Windows::Foundation::Rect const& rectangle) const
    {
        winrt::Windows::Foundation::Rect result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel)->MakeVisible(*(void**)(&visual), impl::bind_in(rectangle), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::CarouselPanel) consume_Windows_UI_Xaml_Controls_Primitives_ICarouselPanelFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanelFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::CarouselPanel{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::ColorPickerHsvChannel) consume_Windows_UI_Xaml_Controls_Primitives_IColorPickerSlider<D>::ColorChannel() const
    {
        winrt::Windows::UI::Xaml::Controls::ColorPickerHsvChannel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSlider)->get_ColorChannel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IColorPickerSlider<D>::ColorChannel(winrt::Windows::UI::Xaml::Controls::ColorPickerHsvChannel const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSlider)->put_ColorChannel(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider) consume_Windows_UI_Xaml_Controls_Primitives_IColorPickerSliderFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IColorPickerSliderStatics<D>::ColorChannelProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderStatics)->get_ColorChannelProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::Color() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_Color(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::Color(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_Color(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float4) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::HsvColor() const
    {
        winrt::Windows::Foundation::Numerics::float4 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_HsvColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::HsvColor(winrt::Windows::Foundation::Numerics::float4 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_HsvColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MinHue() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_MinHue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MinHue(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_MinHue(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MaxHue() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_MaxHue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MaxHue(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_MaxHue(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MinSaturation() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_MinSaturation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MinSaturation(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_MinSaturation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MaxSaturation() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_MaxSaturation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MaxSaturation(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_MaxSaturation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MinValue() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_MinValue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MinValue(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_MinValue(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MaxValue() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_MaxValue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::MaxValue(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_MaxValue(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::ColorSpectrumShape) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::Shape() const
    {
        winrt::Windows::UI::Xaml::Controls::ColorSpectrumShape value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_Shape(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::Shape(winrt::Windows::UI::Xaml::Controls::ColorSpectrumShape const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_Shape(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::ColorSpectrumComponents) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::Components() const
    {
        winrt::Windows::UI::Xaml::Controls::ColorSpectrumComponents value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->get_Components(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::Components(winrt::Windows::UI::Xaml::Controls::ColorSpectrumComponents const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->put_Components(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::ColorChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Controls::Primitives::ColorSpectrum, winrt::Windows::UI::Xaml::Controls::ColorChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->add_ColorChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::ColorChanged_revoker consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::ColorChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Controls::Primitives::ColorSpectrum, winrt::Windows::UI::Xaml::Controls::ColorChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ColorChanged_revoker>(this, ColorChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrum<D>::ColorChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum)->remove_ColorChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::ColorSpectrum) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::ColorSpectrum{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::ColorProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_ColorProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::HsvColorProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_HsvColorProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::MinHueProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_MinHueProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::MaxHueProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_MaxHueProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::MinSaturationProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_MinSaturationProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::MaxSaturationProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_MaxSaturationProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::MinValueProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_MinValueProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::MaxValueProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_MaxValueProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::ShapeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_ShapeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IColorSpectrumStatics<D>::ComponentsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics)->get_ComponentsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IComboBoxTemplateSettings<D>::DropDownOpenedHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings)->get_DropDownOpenedHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IComboBoxTemplateSettings<D>::DropDownClosedHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings)->get_DropDownClosedHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IComboBoxTemplateSettings<D>::DropDownOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings)->get_DropDownOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection) consume_Windows_UI_Xaml_Controls_Primitives_IComboBoxTemplateSettings<D>::SelectedItemDirection() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings)->get_SelectedItemDirection(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IComboBoxTemplateSettings2<D>::DropDownContentMinWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings2)->get_DropDownContentMinWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBarTemplateSettings) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBar<D>::FlyoutTemplateSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBar)->get_FlyoutTemplateSettings(&value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBarTemplateSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBar) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBar{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::OpenAnimationStartPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_OpenAnimationStartPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::OpenAnimationEndPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_OpenAnimationEndPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::CloseAnimationEndPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_CloseAnimationEndPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::CurrentWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_CurrentWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandedWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandedWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::WidthExpansionDelta() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_WidthExpansionDelta(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::WidthExpansionAnimationStartPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_WidthExpansionAnimationStartPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::WidthExpansionAnimationEndPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_WidthExpansionAnimationEndPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::WidthExpansionMoreButtonAnimationStartPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_WidthExpansionMoreButtonAnimationStartPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::WidthExpansionMoreButtonAnimationEndPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_WidthExpansionMoreButtonAnimationEndPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandUpOverflowVerticalPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandUpOverflowVerticalPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandDownOverflowVerticalPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandDownOverflowVerticalPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandUpAnimationStartPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandUpAnimationStartPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandUpAnimationEndPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandUpAnimationEndPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandUpAnimationHoldPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandUpAnimationHoldPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandDownAnimationStartPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandDownAnimationStartPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandDownAnimationEndPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandDownAnimationEndPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ExpandDownAnimationHoldPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ExpandDownAnimationHoldPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::ContentClipRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_ContentClipRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarFlyoutCommandBarTemplateSettings<D>::OverflowContentClipRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings)->get_OverflowContentClipRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::ContentHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_ContentHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::OverflowContentClipRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_OverflowContentClipRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::OverflowContentMinWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_OverflowContentMinWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::OverflowContentMaxHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_OverflowContentMaxHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::OverflowContentHorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_OverflowContentHorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::OverflowContentHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_OverflowContentHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings<D>::NegativeOverflowContentHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings)->get_NegativeOverflowContentHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings2<D>::OverflowContentMaxWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings2)->get_OverflowContentMaxWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Visibility) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings3<D>::EffectiveOverflowButtonVisibility() const
    {
        winrt::Windows::UI::Xaml::Visibility value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings3)->get_EffectiveOverflowButtonVisibility(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings4<D>::OverflowContentCompactYTranslation() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings4)->get_OverflowContentCompactYTranslation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings4<D>::OverflowContentMinimalYTranslation() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings4)->get_OverflowContentMinimalYTranslation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ICommandBarTemplateSettings4<D>::OverflowContentHiddenYTranslation() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings4)->get_OverflowContentHiddenYTranslation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IDragCompletedEventArgs<D>::HorizontalChange() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs)->get_HorizontalChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IDragCompletedEventArgs<D>::VerticalChange() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs)->get_VerticalChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IDragCompletedEventArgs<D>::Canceled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs)->get_Canceled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs) consume_Windows_UI_Xaml_Controls_Primitives_IDragCompletedEventArgsFactory<D>::CreateInstanceWithHorizontalChangeVerticalChangeAndCanceled(double horizontalChange, double verticalChange, bool canceled, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgsFactory)->CreateInstanceWithHorizontalChangeVerticalChangeAndCanceled(horizontalChange, verticalChange, canceled, *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IDragDeltaEventArgs<D>::HorizontalChange() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgs)->get_HorizontalChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IDragDeltaEventArgs<D>::VerticalChange() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgs)->get_VerticalChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs) consume_Windows_UI_Xaml_Controls_Primitives_IDragDeltaEventArgsFactory<D>::CreateInstanceWithHorizontalChangeAndVerticalChange(double horizontalChange, double verticalChange, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgsFactory)->CreateInstanceWithHorizontalChangeAndVerticalChange(horizontalChange, verticalChange, *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IDragStartedEventArgs<D>::HorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgs)->get_HorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IDragStartedEventArgs<D>::VerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgs)->get_VerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs) consume_Windows_UI_Xaml_Controls_Primitives_IDragStartedEventArgsFactory<D>::CreateInstanceWithHorizontalOffsetAndVerticalOffset(double horizontalOffset, double verticalOffset, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgsFactory)->CreateInstanceWithHorizontalOffsetAndVerticalOffset(horizontalOffset, verticalOffset, *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Placement() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->get_Placement(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Placement(winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->put_Placement(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opened(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->add_Opened(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opened_revoker consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opened(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Opened_revoker>(this, Opened(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opened(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->remove_Opened(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Closed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->add_Closed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Closed_revoker consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opening(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->add_Opening(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opening_revoker consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opening(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Opening_revoker>(this, Opening(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Opening(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->remove_Opening(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::ShowAt(winrt::Windows::UI::Xaml::FrameworkElement const& placementTarget) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->ShowAt(*(void**)(&placementTarget)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase<D>::Hide() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase)->Hide());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FrameworkElement) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::Target() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->get_Target(&value));
        return winrt::Windows::UI::Xaml::FrameworkElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::AllowFocusOnInteraction() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->get_AllowFocusOnInteraction(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::AllowFocusOnInteraction(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->put_AllowFocusOnInteraction(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::LightDismissOverlayMode) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::LightDismissOverlayMode() const
    {
        winrt::Windows::UI::Xaml::Controls::LightDismissOverlayMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->get_LightDismissOverlayMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::LightDismissOverlayMode(winrt::Windows::UI::Xaml::Controls::LightDismissOverlayMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->put_LightDismissOverlayMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::AllowFocusWhenDisabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->get_AllowFocusWhenDisabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::AllowFocusWhenDisabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->put_AllowFocusWhenDisabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ElementSoundMode) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::ElementSoundMode() const
    {
        winrt::Windows::UI::Xaml::ElementSoundMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->get_ElementSoundMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::ElementSoundMode(winrt::Windows::UI::Xaml::ElementSoundMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->put_ElementSoundMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::Closing(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBaseClosingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->add_Closing(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::Closing_revoker consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::Closing(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBaseClosingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Closing_revoker>(this, Closing(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase2<D>::Closing(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2)->remove_Closing(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase3<D>::OverlayInputPassThroughElement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3)->get_OverlayInputPassThroughElement(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase3<D>::OverlayInputPassThroughElement(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3)->put_OverlayInputPassThroughElement(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase4<D>::TryInvokeKeyboardAccelerator(winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase4)->TryInvokeKeyboardAccelerator(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::ShowMode() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->get_ShowMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::ShowMode(winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->put_ShowMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::InputDevicePrefersPrimaryCommands() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->get_InputDevicePrefersPrimaryCommands(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::AreOpenCloseAnimationsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->get_AreOpenCloseAnimationsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::AreOpenCloseAnimationsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->put_AreOpenCloseAnimationsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::IsOpen() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->get_IsOpen(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase5<D>::ShowAt(winrt::Windows::UI::Xaml::DependencyObject const& placementTarget, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions const& showOptions) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5)->ShowAt(*(void**)(&placementTarget), *(void**)(&showOptions)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase6<D>::ShouldConstrainToRootBounds() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6)->get_ShouldConstrainToRootBounds(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase6<D>::ShouldConstrainToRootBounds(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6)->put_ShouldConstrainToRootBounds(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase6<D>::IsConstrainedToRootBounds() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6)->get_IsConstrainedToRootBounds(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::XamlRoot) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase6<D>::XamlRoot() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6)->get_XamlRoot(&value));
        return winrt::Windows::UI::Xaml::XamlRoot{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBase6<D>::XamlRoot(winrt::Windows::UI::Xaml::XamlRoot const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6)->put_XamlRoot(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseClosingEventArgs<D>::Cancel() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseClosingEventArgs)->get_Cancel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseClosingEventArgs<D>::Cancel(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseClosingEventArgs)->put_Cancel(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Control) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseOverrides<D>::CreatePresenter() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides)->CreatePresenter(&result));
        return winrt::Windows::UI::Xaml::Controls::Control{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseOverrides4<D>::OnProcessKeyboardAccelerators(winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4)->OnProcessKeyboardAccelerators(*(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics<D>::PlacementProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics)->get_PlacementProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics<D>::AttachedFlyoutProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics)->get_AttachedFlyoutProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics<D>::GetAttachedFlyout(winrt::Windows::UI::Xaml::FrameworkElement const& element) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics)->GetAttachedFlyout(*(void**)(&element), &result));
        return winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics<D>::SetAttachedFlyout(winrt::Windows::UI::Xaml::FrameworkElement const& element, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics)->SetAttachedFlyout(*(void**)(&element), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics<D>::ShowAttachedFlyout(winrt::Windows::UI::Xaml::FrameworkElement const& flyoutOwner) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics)->ShowAttachedFlyout(*(void**)(&flyoutOwner)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics2<D>::AllowFocusOnInteractionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2)->get_AllowFocusOnInteractionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics2<D>::LightDismissOverlayModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2)->get_LightDismissOverlayModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics2<D>::AllowFocusWhenDisabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2)->get_AllowFocusWhenDisabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics2<D>::ElementSoundModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2)->get_ElementSoundModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics3<D>::OverlayInputPassThroughElementProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics3)->get_OverlayInputPassThroughElementProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics5<D>::TargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5)->get_TargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics5<D>::ShowModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5)->get_ShowModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics5<D>::InputDevicePrefersPrimaryCommandsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5)->get_InputDevicePrefersPrimaryCommandsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics5<D>::AreOpenCloseAnimationsEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5)->get_AreOpenCloseAnimationsEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics5<D>::IsOpenProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5)->get_IsOpenProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutBaseStatics6<D>::ShouldConstrainToRootBoundsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics6)->get_ShouldConstrainToRootBoundsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::Position() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->get_Position(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::Position(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->put_Position(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::ExclusionRect() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->get_ExclusionRect(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::ExclusionRect(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->put_ExclusionRect(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::ShowMode() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->get_ShowMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::ShowMode(winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->put_ShowMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::Placement() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->get_Placement(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptions<D>::Placement(winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions)->put_Placement(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions) consume_Windows_UI_Xaml_Controls_Primitives_IFlyoutShowOptionsFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptionsFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPosition) consume_Windows_UI_Xaml_Controls_Primitives_IGeneratorPositionHelperStatics<D>::FromIndexAndOffset(int32_t index, int32_t offset) const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPosition result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelperStatics)->FromIndexAndOffset(index, offset, put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectionCheckMarkVisualEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_SelectionCheckMarkVisualEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectionCheckMarkVisualEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_SelectionCheckMarkVisualEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::CheckHintBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_CheckHintBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::CheckHintBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_CheckHintBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::CheckSelectingBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_CheckSelectingBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::CheckSelectingBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_CheckSelectingBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::CheckBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_CheckBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::CheckBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_CheckBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DragBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_DragBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DragBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_DragBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DragForeground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_DragForeground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DragForeground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_DragForeground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::FocusBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_FocusBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::FocusBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_FocusBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::PlaceholderBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_PlaceholderBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::PlaceholderBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_PlaceholderBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::PointerOverBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_PointerOverBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::PointerOverBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_PointerOverBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_SelectedBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_SelectedBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedForeground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_SelectedForeground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedForeground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_SelectedForeground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedPointerOverBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_SelectedPointerOverBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedPointerOverBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_SelectedPointerOverBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedPointerOverBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_SelectedPointerOverBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedPointerOverBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_SelectedPointerOverBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedBorderThickness() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_SelectedBorderThickness(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::SelectedBorderThickness(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_SelectedBorderThickness(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DisabledOpacity() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_DisabledOpacity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DisabledOpacity(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_DisabledOpacity(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DragOpacity() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_DragOpacity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::DragOpacity(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_DragOpacity(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::ReorderHintOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_ReorderHintOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::ReorderHintOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_ReorderHintOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::HorizontalAlignment) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::GridViewItemPresenterHorizontalContentAlignment() const
    {
        winrt::Windows::UI::Xaml::HorizontalAlignment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_GridViewItemPresenterHorizontalContentAlignment(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::GridViewItemPresenterHorizontalContentAlignment(winrt::Windows::UI::Xaml::HorizontalAlignment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_GridViewItemPresenterHorizontalContentAlignment(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::VerticalAlignment) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::GridViewItemPresenterVerticalContentAlignment() const
    {
        winrt::Windows::UI::Xaml::VerticalAlignment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_GridViewItemPresenterVerticalContentAlignment(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::GridViewItemPresenterVerticalContentAlignment(winrt::Windows::UI::Xaml::VerticalAlignment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_GridViewItemPresenterVerticalContentAlignment(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::GridViewItemPresenterPadding() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_GridViewItemPresenterPadding(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::GridViewItemPresenterPadding(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_GridViewItemPresenterPadding(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::PointerOverBackgroundMargin() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_PointerOverBackgroundMargin(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::PointerOverBackgroundMargin(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_PointerOverBackgroundMargin(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::ContentMargin() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->get_ContentMargin(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenter<D>::ContentMargin(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter)->put_ContentMargin(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::GridViewItemPresenter) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::GridViewItemPresenter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::SelectionCheckMarkVisualEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_SelectionCheckMarkVisualEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::CheckHintBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_CheckHintBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::CheckSelectingBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_CheckSelectingBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::CheckBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_CheckBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::DragBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_DragBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::DragForegroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_DragForegroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::FocusBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_FocusBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::PlaceholderBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_PlaceholderBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::PointerOverBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_PointerOverBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::SelectedBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_SelectedBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::SelectedForegroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_SelectedForegroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::SelectedPointerOverBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_SelectedPointerOverBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::SelectedPointerOverBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_SelectedPointerOverBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::SelectedBorderThicknessProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_SelectedBorderThicknessProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::DisabledOpacityProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_DisabledOpacityProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::DragOpacityProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_DragOpacityProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::ReorderHintOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_ReorderHintOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::GridViewItemPresenterHorizontalContentAlignmentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_GridViewItemPresenterHorizontalContentAlignmentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::GridViewItemPresenterVerticalContentAlignmentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_GridViewItemPresenterVerticalContentAlignmentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::GridViewItemPresenterPaddingProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_GridViewItemPresenterPaddingProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::PointerOverBackgroundMarginProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_PointerOverBackgroundMarginProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemPresenterStatics<D>::ContentMarginProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics)->get_ContentMarginProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_IGridViewItemTemplateSettings<D>::DragItemsCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemTemplateSettings)->get_DragItemsCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_IItemsChangedEventArgs<D>::Action() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs)->get_Action(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPosition) consume_Windows_UI_Xaml_Controls_Primitives_IItemsChangedEventArgs<D>::Position() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPosition value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPosition) consume_Windows_UI_Xaml_Controls_Primitives_IItemsChangedEventArgs<D>::OldPosition() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPosition value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs)->get_OldPosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_IItemsChangedEventArgs<D>::ItemCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs)->get_ItemCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_IItemsChangedEventArgs<D>::ItemUICount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs)->get_ItemUICount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemBackgroundConverter<D>::Enabled() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter)->get_Enabled(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemBackgroundConverter<D>::Enabled(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter)->put_Enabled(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemBackgroundConverter<D>::Disabled() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter)->get_Disabled(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemBackgroundConverter<D>::Disabled(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter)->put_Disabled(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemBackgroundConverterStatics<D>::EnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverterStatics)->get_EnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemBackgroundConverterStatics<D>::DisabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverterStatics)->get_DisabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemForegroundConverter<D>::Enabled() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter)->get_Enabled(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemForegroundConverter<D>::Enabled(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter)->put_Enabled(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemForegroundConverter<D>::Disabled() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter)->get_Disabled(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemForegroundConverter<D>::Disabled(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter)->put_Disabled(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemForegroundConverterStatics<D>::EnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverterStatics)->get_EnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IJumpListItemForegroundConverterStatics<D>::DisabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverterStatics)->get_DisabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Controls_Primitives_ILayoutInformationStatics<D>::GetLayoutExceptionElement(winrt::Windows::Foundation::IInspectable const& dispatcher) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics)->GetLayoutExceptionElement(*(void**)(&dispatcher), &result));
        return winrt::Windows::UI::Xaml::UIElement{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Controls_Primitives_ILayoutInformationStatics<D>::GetLayoutSlot(winrt::Windows::UI::Xaml::FrameworkElement const& element) const
    {
        winrt::Windows::Foundation::Rect result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics)->GetLayoutSlot(*(void**)(&element), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Xaml_Controls_Primitives_ILayoutInformationStatics2<D>::GetAvailableSize(winrt::Windows::UI::Xaml::UIElement const& element) const
    {
        winrt::Windows::Foundation::Size result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics2)->GetAvailableSize(*(void**)(&element), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectionCheckMarkVisualEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_SelectionCheckMarkVisualEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectionCheckMarkVisualEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_SelectionCheckMarkVisualEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::CheckHintBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_CheckHintBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::CheckHintBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_CheckHintBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::CheckSelectingBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_CheckSelectingBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::CheckSelectingBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_CheckSelectingBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::CheckBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_CheckBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::CheckBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_CheckBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DragBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_DragBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DragBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_DragBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DragForeground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_DragForeground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DragForeground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_DragForeground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::FocusBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_FocusBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::FocusBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_FocusBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::PlaceholderBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_PlaceholderBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::PlaceholderBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_PlaceholderBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::PointerOverBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_PointerOverBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::PointerOverBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_PointerOverBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_SelectedBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_SelectedBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedForeground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_SelectedForeground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedForeground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_SelectedForeground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedPointerOverBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_SelectedPointerOverBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedPointerOverBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_SelectedPointerOverBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedPointerOverBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_SelectedPointerOverBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedPointerOverBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_SelectedPointerOverBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedBorderThickness() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_SelectedBorderThickness(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::SelectedBorderThickness(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_SelectedBorderThickness(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DisabledOpacity() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_DisabledOpacity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DisabledOpacity(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_DisabledOpacity(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DragOpacity() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_DragOpacity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::DragOpacity(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_DragOpacity(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ReorderHintOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_ReorderHintOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ReorderHintOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_ReorderHintOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::HorizontalAlignment) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ListViewItemPresenterHorizontalContentAlignment() const
    {
        winrt::Windows::UI::Xaml::HorizontalAlignment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_ListViewItemPresenterHorizontalContentAlignment(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ListViewItemPresenterHorizontalContentAlignment(winrt::Windows::UI::Xaml::HorizontalAlignment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_ListViewItemPresenterHorizontalContentAlignment(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::VerticalAlignment) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ListViewItemPresenterVerticalContentAlignment() const
    {
        winrt::Windows::UI::Xaml::VerticalAlignment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_ListViewItemPresenterVerticalContentAlignment(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ListViewItemPresenterVerticalContentAlignment(winrt::Windows::UI::Xaml::VerticalAlignment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_ListViewItemPresenterVerticalContentAlignment(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ListViewItemPresenterPadding() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_ListViewItemPresenterPadding(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ListViewItemPresenterPadding(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_ListViewItemPresenterPadding(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::PointerOverBackgroundMargin() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_PointerOverBackgroundMargin(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::PointerOverBackgroundMargin(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_PointerOverBackgroundMargin(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ContentMargin() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->get_ContentMargin(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter<D>::ContentMargin(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter)->put_ContentMargin(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::SelectedPressedBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->get_SelectedPressedBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::SelectedPressedBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->put_SelectedPressedBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::PressedBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->get_PressedBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::PressedBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->put_PressedBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::CheckBoxBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->get_CheckBoxBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::CheckBoxBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->put_CheckBoxBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::FocusSecondaryBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->get_FocusSecondaryBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::FocusSecondaryBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->put_FocusSecondaryBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::CheckMode() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->get_CheckMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::CheckMode(winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->put_CheckMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::PointerOverForeground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->get_PointerOverForeground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter2<D>::PointerOverForeground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2)->put_PointerOverForeground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->get_RevealBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->put_RevealBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->get_RevealBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->put_RevealBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBorderThickness() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->get_RevealBorderThickness(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBorderThickness(winrt::Windows::UI::Xaml::Thickness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->put_RevealBorderThickness(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBackgroundShowsAboveContent() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->get_RevealBackgroundShowsAboveContent(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter3<D>::RevealBackgroundShowsAboveContent(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3)->put_RevealBackgroundShowsAboveContent(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectedDisabledBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_SelectedDisabledBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectedDisabledBackground(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_SelectedDisabledBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckPressedBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckPressedBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckPressedBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckPressedBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckDisabledBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckDisabledBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckDisabledBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckDisabledBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxPointerOverBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckBoxPointerOverBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxPointerOverBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckBoxPointerOverBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxPressedBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckBoxPressedBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxPressedBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckBoxPressedBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxDisabledBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckBoxDisabledBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxDisabledBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckBoxDisabledBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxSelectedBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckBoxSelectedBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxSelectedBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckBoxSelectedBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxSelectedPointerOverBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckBoxSelectedPointerOverBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxSelectedPointerOverBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckBoxSelectedPointerOverBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxSelectedPressedBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckBoxSelectedPressedBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxSelectedPressedBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckBoxSelectedPressedBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxSelectedDisabledBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckBoxSelectedDisabledBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxSelectedDisabledBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckBoxSelectedDisabledBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckBoxBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckBoxBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxPointerOverBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckBoxPointerOverBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxPointerOverBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckBoxPointerOverBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxPressedBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckBoxPressedBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxPressedBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckBoxPressedBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxDisabledBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckBoxDisabledBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxDisabledBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckBoxDisabledBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::CornerRadius) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxCornerRadius() const
    {
        winrt::Windows::UI::Xaml::CornerRadius value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_CheckBoxCornerRadius(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::CheckBoxCornerRadius(winrt::Windows::UI::Xaml::CornerRadius const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_CheckBoxCornerRadius(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::CornerRadius) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorCornerRadius() const
    {
        winrt::Windows::UI::Xaml::CornerRadius value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_SelectionIndicatorCornerRadius(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorCornerRadius(winrt::Windows::UI::Xaml::CornerRadius const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_SelectionIndicatorCornerRadius(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorVisualEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_SelectionIndicatorVisualEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorVisualEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_SelectionIndicatorVisualEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterSelectionIndicatorMode) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorMode() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterSelectionIndicatorMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_SelectionIndicatorMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorMode(winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterSelectionIndicatorMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_SelectionIndicatorMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_SelectionIndicatorBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_SelectionIndicatorBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorPointerOverBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_SelectionIndicatorPointerOverBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorPointerOverBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_SelectionIndicatorPointerOverBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorPressedBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_SelectionIndicatorPressedBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorPressedBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_SelectionIndicatorPressedBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorDisabledBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_SelectionIndicatorDisabledBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectionIndicatorDisabledBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_SelectionIndicatorDisabledBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectedBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_SelectedBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectedBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_SelectedBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectedPressedBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_SelectedPressedBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectedPressedBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_SelectedPressedBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectedDisabledBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_SelectedDisabledBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectedDisabledBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_SelectedDisabledBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectedInnerBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_SelectedInnerBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::SelectedInnerBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_SelectedInnerBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::PointerOverBorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->get_PointerOverBorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenter4<D>::PointerOverBorderBrush(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4)->put_PointerOverBorderBrush(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenter) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::SelectionCheckMarkVisualEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_SelectionCheckMarkVisualEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::CheckHintBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_CheckHintBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::CheckSelectingBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_CheckSelectingBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::CheckBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_CheckBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::DragBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_DragBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::DragForegroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_DragForegroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::FocusBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_FocusBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::PlaceholderBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_PlaceholderBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::PointerOverBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_PointerOverBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::SelectedBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_SelectedBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::SelectedForegroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_SelectedForegroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::SelectedPointerOverBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_SelectedPointerOverBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::SelectedPointerOverBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_SelectedPointerOverBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::SelectedBorderThicknessProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_SelectedBorderThicknessProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::DisabledOpacityProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_DisabledOpacityProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::DragOpacityProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_DragOpacityProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::ReorderHintOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_ReorderHintOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::ListViewItemPresenterHorizontalContentAlignmentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_ListViewItemPresenterHorizontalContentAlignmentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::ListViewItemPresenterVerticalContentAlignmentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_ListViewItemPresenterVerticalContentAlignmentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::ListViewItemPresenterPaddingProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_ListViewItemPresenterPaddingProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::PointerOverBackgroundMarginProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_PointerOverBackgroundMarginProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics<D>::ContentMarginProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics)->get_ContentMarginProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics2<D>::SelectedPressedBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2)->get_SelectedPressedBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics2<D>::PressedBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2)->get_PressedBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics2<D>::CheckBoxBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2)->get_CheckBoxBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics2<D>::FocusSecondaryBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2)->get_FocusSecondaryBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics2<D>::CheckModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2)->get_CheckModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics2<D>::PointerOverForegroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2)->get_PointerOverForegroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics3<D>::RevealBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3)->get_RevealBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics3<D>::RevealBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3)->get_RevealBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics3<D>::RevealBorderThicknessProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3)->get_RevealBorderThicknessProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics3<D>::RevealBackgroundShowsAboveContentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3)->get_RevealBackgroundShowsAboveContentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::SelectedDisabledBackgroundProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_SelectedDisabledBackgroundProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckPressedBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckPressedBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckDisabledBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckDisabledBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckBoxPointerOverBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckBoxPointerOverBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckBoxPressedBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckBoxPressedBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckBoxDisabledBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckBoxDisabledBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckBoxSelectedBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckBoxSelectedBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckBoxSelectedPointerOverBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckBoxSelectedPointerOverBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckBoxSelectedPressedBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckBoxSelectedPressedBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckBoxSelectedDisabledBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckBoxSelectedDisabledBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckBoxBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckBoxBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckBoxPointerOverBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckBoxPointerOverBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckBoxPressedBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckBoxPressedBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckBoxDisabledBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckBoxDisabledBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::CheckBoxCornerRadiusProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_CheckBoxCornerRadiusProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::SelectionIndicatorCornerRadiusProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_SelectionIndicatorCornerRadiusProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::SelectionIndicatorVisualEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_SelectionIndicatorVisualEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::SelectionIndicatorModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_SelectionIndicatorModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::SelectionIndicatorBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_SelectionIndicatorBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::SelectionIndicatorPointerOverBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_SelectionIndicatorPointerOverBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::SelectionIndicatorPressedBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_SelectionIndicatorPressedBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::SelectionIndicatorDisabledBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_SelectionIndicatorDisabledBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::SelectedBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_SelectedBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::SelectedPressedBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_SelectedPressedBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::SelectedDisabledBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_SelectedDisabledBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::SelectedInnerBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_SelectedInnerBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemPresenterStatics4<D>::PointerOverBorderBrushProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4)->get_PointerOverBorderBrushProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_IListViewItemTemplateSettings<D>::DragItemsCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemTemplateSettings)->get_DragItemsCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ShouldLoop() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_ShouldLoop(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ShouldLoop(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_ShouldLoop(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::IInspectable>) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::Items() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_Items(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::Items(param::vector<winrt::Windows::Foundation::IInspectable> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_Items(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectedIndex() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_SelectedIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectedIndex(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_SelectedIndex(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectedItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_SelectedItem(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectedItem(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_SelectedItem(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ItemWidth() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_ItemWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ItemWidth(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_ItemWidth(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ItemHeight() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_ItemHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ItemHeight(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_ItemHeight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DataTemplate) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ItemTemplate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->get_ItemTemplate(&value));
        return winrt::Windows::UI::Xaml::DataTemplate{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::ItemTemplate(winrt::Windows::UI::Xaml::DataTemplate const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->put_ItemTemplate(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectionChanged(winrt::Windows::UI::Xaml::Controls::SelectionChangedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->add_SelectionChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectionChanged_revoker consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectionChanged(auto_revoke_t, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, SelectionChanged_revoker>(this, SelectionChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelector<D>::SelectionChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector)->remove_SelectionChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::ShouldLoopProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_ShouldLoopProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::ItemsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_ItemsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::SelectedIndexProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_SelectedIndexProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::SelectedItemProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_SelectedItemProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::ItemWidthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_ItemWidthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::ItemHeightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_ItemHeightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ILoopingSelectorStatics<D>::ItemTemplateProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics)->get_ItemTemplateProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IMenuFlyoutItemTemplateSettings<D>::KeyboardAcceleratorTextMinWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutItemTemplateSettings)->get_KeyboardAcceleratorTextMinWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IMenuFlyoutPresenterTemplateSettings<D>::FlyoutContentMinWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutPresenterTemplateSettings)->get_FlyoutContentMinWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::IconElement) consume_Windows_UI_Xaml_Controls_Primitives_INavigationViewItemPresenter<D>::Icon() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenter)->get_Icon(&value));
        return winrt::Windows::UI::Xaml::Controls::IconElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_INavigationViewItemPresenter<D>::Icon(winrt::Windows::UI::Xaml::Controls::IconElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenter)->put_Icon(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::NavigationViewItemPresenter) consume_Windows_UI_Xaml_Controls_Primitives_INavigationViewItemPresenterFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::NavigationViewItemPresenter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_INavigationViewItemPresenterStatics<D>::IconProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterStatics)->get_IconProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::CanVerticallyScroll() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_CanVerticallyScroll(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::CanVerticallyScroll(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->put_CanVerticallyScroll(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::CanHorizontallyScroll() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_CanHorizontallyScroll(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::CanHorizontallyScroll(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->put_CanHorizontallyScroll(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::ExtentWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_ExtentWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::ExtentHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_ExtentHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::ViewportWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_ViewportWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::ViewportHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_ViewportHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::HorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_HorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::VerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_VerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::ScrollOwner() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->get_ScrollOwner(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::ScrollOwner(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->put_ScrollOwner(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::LineUp() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->LineUp());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::LineDown() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->LineDown());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::LineLeft() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->LineLeft());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::LineRight() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->LineRight());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::PageUp() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->PageUp());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::PageDown() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->PageDown());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::PageLeft() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->PageLeft());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::PageRight() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->PageRight());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::MouseWheelUp() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->MouseWheelUp());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::MouseWheelDown() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->MouseWheelDown());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::MouseWheelLeft() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->MouseWheelLeft());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::MouseWheelRight() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->MouseWheelRight());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::SetHorizontalOffset(double offset) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->SetHorizontalOffset(offset));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::SetVerticalOffset(double offset) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->SetVerticalOffset(offset));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Controls_Primitives_IOrientedVirtualizingPanel<D>::MakeVisible(winrt::Windows::UI::Xaml::UIElement const& visual, winrt::Windows::Foundation::Rect const& rectangle) const
    {
        winrt::Windows::Foundation::Rect result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel)->MakeVisible(*(void**)(&visual), impl::bind_in(rectangle), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::PickerFlyoutBase) consume_Windows_UI_Xaml_Controls_Primitives_IPickerFlyoutBaseFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::PickerFlyoutBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPickerFlyoutBaseOverrides<D>::OnConfirmed() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides)->OnConfirmed());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IPickerFlyoutBaseOverrides<D>::ShouldShowConfirmationButtons() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides)->ShouldShowConfirmationButtons(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IPickerFlyoutBaseStatics<D>::TitleProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics)->get_TitleProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Controls_Primitives_IPickerFlyoutBaseStatics<D>::GetTitle(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics)->GetTitle(*(void**)(&element), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPickerFlyoutBaseStatics<D>::SetTitle(winrt::Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics)->SetTitle(*(void**)(&element), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::PivotHeaderItem) consume_Windows_UI_Xaml_Controls_Primitives_IPivotHeaderItemFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItemFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::PivotHeaderItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Child() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->get_Child(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Child(winrt::Windows::UI::Xaml::UIElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->put_Child(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::IsOpen() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->get_IsOpen(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::IsOpen(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->put_IsOpen(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::HorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->get_HorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::HorizontalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->put_HorizontalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::VerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->get_VerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::VerticalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->put_VerticalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::ChildTransitions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->get_ChildTransitions(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::ChildTransitions(winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->put_ChildTransitions(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::IsLightDismissEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->get_IsLightDismissEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::IsLightDismissEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->put_IsLightDismissEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Opened(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->add_Opened(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Opened_revoker consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Opened(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Opened_revoker>(this, Opened(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Opened(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->remove_Opened(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Closed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->add_Closed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Closed_revoker consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPopup<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::LightDismissOverlayMode) consume_Windows_UI_Xaml_Controls_Primitives_IPopup2<D>::LightDismissOverlayMode() const
    {
        winrt::Windows::UI::Xaml::Controls::LightDismissOverlayMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup2)->get_LightDismissOverlayMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPopup2<D>::LightDismissOverlayMode(winrt::Windows::UI::Xaml::Controls::LightDismissOverlayMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup2)->put_LightDismissOverlayMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IPopup3<D>::ShouldConstrainToRootBounds() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup3)->get_ShouldConstrainToRootBounds(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPopup3<D>::ShouldConstrainToRootBounds(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup3)->put_ShouldConstrainToRootBounds(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IPopup3<D>::IsConstrainedToRootBounds() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup3)->get_IsConstrainedToRootBounds(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FrameworkElement) consume_Windows_UI_Xaml_Controls_Primitives_IPopup4<D>::PlacementTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup4)->get_PlacementTarget(&value));
        return winrt::Windows::UI::Xaml::FrameworkElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPopup4<D>::PlacementTarget(winrt::Windows::UI::Xaml::FrameworkElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup4)->put_PlacementTarget(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::PopupPlacementMode) consume_Windows_UI_Xaml_Controls_Primitives_IPopup4<D>::DesiredPlacement() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::PopupPlacementMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup4)->get_DesiredPlacement(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPopup4<D>::DesiredPlacement(winrt::Windows::UI::Xaml::Controls::Primitives::PopupPlacementMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup4)->put_DesiredPlacement(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::PopupPlacementMode) consume_Windows_UI_Xaml_Controls_Primitives_IPopup4<D>::ActualPlacement() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::PopupPlacementMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup4)->get_ActualPlacement(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IPopup4<D>::ActualPlacementChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup4)->add_ActualPlacementChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IPopup4<D>::ActualPlacementChanged_revoker consume_Windows_UI_Xaml_Controls_Primitives_IPopup4<D>::ActualPlacementChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ActualPlacementChanged_revoker>(this, ActualPlacementChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IPopup4<D>::ActualPlacementChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopup4)->remove_ActualPlacementChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics<D>::ChildProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics)->get_ChildProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics<D>::IsOpenProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics)->get_IsOpenProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics<D>::HorizontalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics)->get_HorizontalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics<D>::VerticalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics)->get_VerticalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics<D>::ChildTransitionsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics)->get_ChildTransitionsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics<D>::IsLightDismissEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics)->get_IsLightDismissEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics2<D>::LightDismissOverlayModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics2)->get_LightDismissOverlayModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics3<D>::ShouldConstrainToRootBoundsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics3)->get_ShouldConstrainToRootBoundsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics4<D>::PlacementTargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics4)->get_PlacementTargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IPopupStatics4<D>::DesiredPlacementProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics4)->get_DesiredPlacementProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::EllipseDiameter() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_EllipseDiameter(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::EllipseOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_EllipseOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::EllipseAnimationWellPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_EllipseAnimationWellPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::EllipseAnimationEndPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_EllipseAnimationEndPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::ContainerAnimationStartPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_ContainerAnimationStartPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::ContainerAnimationEndPosition() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_ContainerAnimationEndPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IProgressBarTemplateSettings<D>::IndicatorLengthDelta() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings)->get_IndicatorLengthDelta(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IProgressRingTemplateSettings<D>::EllipseDiameter() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IProgressRingTemplateSettings)->get_EllipseDiameter(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_IProgressRingTemplateSettings<D>::EllipseOffset() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IProgressRingTemplateSettings)->get_EllipseOffset(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IProgressRingTemplateSettings<D>::MaxSideLength() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IProgressRingTemplateSettings)->get_MaxSideLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::Minimum() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase)->get_Minimum(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::Minimum(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase)->put_Minimum(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::Maximum() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase)->get_Maximum(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::Maximum(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase)->put_Maximum(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::SmallChange() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase)->get_SmallChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::SmallChange(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase)->put_SmallChange(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::LargeChange() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase)->get_LargeChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::LargeChange(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase)->put_LargeChange(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::Value() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase)->get_Value(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::Value(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase)->put_Value(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::ValueChanged(winrt::Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase)->add_ValueChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::ValueChanged_revoker consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::ValueChanged(auto_revoke_t, winrt::Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, ValueChanged_revoker>(this, ValueChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBase<D>::ValueChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase)->remove_ValueChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::RangeBase) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::RangeBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseOverrides<D>::OnMinimumChanged(double oldMinimum, double newMinimum) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides)->OnMinimumChanged(oldMinimum, newMinimum));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseOverrides<D>::OnMaximumChanged(double oldMaximum, double newMaximum) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides)->OnMaximumChanged(oldMaximum, newMaximum));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseOverrides<D>::OnValueChanged(double oldValue, double newValue) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides)->OnValueChanged(oldValue, newValue));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseStatics<D>::MinimumProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics)->get_MinimumProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseStatics<D>::MaximumProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics)->get_MaximumProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseStatics<D>::SmallChangeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics)->get_SmallChangeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseStatics<D>::LargeChangeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics)->get_LargeChangeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseStatics<D>::ValueProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics)->get_ValueProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseValueChangedEventArgs<D>::OldValue() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseValueChangedEventArgs)->get_OldValue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IRangeBaseValueChangedEventArgs<D>::NewValue() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseValueChangedEventArgs)->get_NewValue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_IRepeatButton<D>::Delay() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButton)->get_Delay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IRepeatButton<D>::Delay(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButton)->put_Delay(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_IRepeatButton<D>::Interval() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButton)->get_Interval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IRepeatButton<D>::Interval(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButton)->put_Interval(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IRepeatButtonStatics<D>::DelayProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButtonStatics)->get_DelayProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IRepeatButtonStatics<D>::IntervalProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButtonStatics)->get_IntervalProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Orientation) consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::Orientation() const
    {
        winrt::Windows::UI::Xaml::Controls::Orientation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBar)->get_Orientation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::Orientation(winrt::Windows::UI::Xaml::Controls::Orientation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBar)->put_Orientation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::ViewportSize() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBar)->get_ViewportSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::ViewportSize(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBar)->put_ViewportSize(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode) consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::IndicatorMode() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBar)->get_IndicatorMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::IndicatorMode(winrt::Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBar)->put_IndicatorMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::Scroll(winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBar)->add_Scroll(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::Scroll_revoker consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::Scroll(auto_revoke_t, winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, Scroll_revoker>(this, Scroll(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IScrollBar<D>::Scroll(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBar)->remove_Scroll(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IScrollBarStatics<D>::OrientationProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics)->get_OrientationProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IScrollBarStatics<D>::ViewportSizeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics)->get_ViewportSizeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IScrollBarStatics<D>::IndicatorModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics)->get_IndicatorModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IScrollEventArgs<D>::NewValue() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollEventArgs)->get_NewValue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventType) consume_Windows_UI_Xaml_Controls_Primitives_IScrollEventArgs<D>::ScrollEventType() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollEventArgs)->get_ScrollEventType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::AreHorizontalSnapPointsRegular() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->get_AreHorizontalSnapPointsRegular(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::AreVerticalSnapPointsRegular() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->get_AreVerticalSnapPointsRegular(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::HorizontalSnapPointsChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->add_HorizontalSnapPointsChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::HorizontalSnapPointsChanged_revoker consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::HorizontalSnapPointsChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, HorizontalSnapPointsChanged_revoker>(this, HorizontalSnapPointsChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::HorizontalSnapPointsChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->remove_HorizontalSnapPointsChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::VerticalSnapPointsChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->add_VerticalSnapPointsChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::VerticalSnapPointsChanged_revoker consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::VerticalSnapPointsChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, VerticalSnapPointsChanged_revoker>(this, VerticalSnapPointsChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::VerticalSnapPointsChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->remove_VerticalSnapPointsChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<float>) consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::GetIrregularSnapPoints(winrt::Windows::UI::Xaml::Controls::Orientation const& orientation, winrt::Windows::UI::Xaml::Controls::Primitives::SnapPointsAlignment const& alignment) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->GetIrregularSnapPoints(static_cast<int32_t>(orientation), static_cast<int32_t>(alignment), &result));
        return winrt::Windows::Foundation::Collections::IVectorView<float>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Xaml_Controls_Primitives_IScrollSnapPointsInfo<D>::GetRegularSnapPoints(winrt::Windows::UI::Xaml::Controls::Orientation const& orientation, winrt::Windows::UI::Xaml::Controls::Primitives::SnapPointsAlignment const& alignment, float& offset) const
    {
        float returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo)->GetRegularSnapPoints(static_cast<int32_t>(orientation), static_cast<int32_t>(alignment), &offset, &returnValue));
        return returnValue;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedIndex() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelector)->get_SelectedIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedIndex(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelector)->put_SelectedIndex(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelector)->get_SelectedItem(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedItem(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelector)->put_SelectedItem(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedValue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelector)->get_SelectedValue(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedValue(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelector)->put_SelectedValue(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedValuePath() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelector)->get_SelectedValuePath(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectedValuePath(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelector)->put_SelectedValuePath(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<bool>) consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::IsSynchronizedWithCurrentItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelector)->get_IsSynchronizedWithCurrentItem(&value));
        return winrt::Windows::Foundation::IReference<bool>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::IsSynchronizedWithCurrentItem(winrt::Windows::Foundation::IReference<bool> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelector)->put_IsSynchronizedWithCurrentItem(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectionChanged(winrt::Windows::UI::Xaml::Controls::SelectionChangedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelector)->add_SelectionChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectionChanged_revoker consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectionChanged(auto_revoke_t, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, SelectionChanged_revoker>(this, SelectionChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ISelector<D>::SelectionChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelector)->remove_SelectionChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_ISelectorItem<D>::IsSelected() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItem)->get_IsSelected(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ISelectorItem<D>::IsSelected(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItem)->put_IsSelected(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::SelectorItem) consume_Windows_UI_Xaml_Controls_Primitives_ISelectorItemFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItemFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::SelectorItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ISelectorItemStatics<D>::IsSelectedProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItemStatics)->get_IsSelectedProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ISelectorStatics<D>::SelectedIndexProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorStatics)->get_SelectedIndexProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ISelectorStatics<D>::SelectedItemProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorStatics)->get_SelectedItemProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ISelectorStatics<D>::SelectedValueProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorStatics)->get_SelectedValueProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ISelectorStatics<D>::SelectedValuePathProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorStatics)->get_SelectedValuePathProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ISelectorStatics<D>::IsSynchronizedWithCurrentItemProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorStatics)->get_IsSynchronizedWithCurrentItemProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_ISelectorStatics<D>::GetIsSelectionActive(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorStatics)->GetIsSelectionActive(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_ISettingsFlyoutTemplateSettings<D>::HeaderBackground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings)->get_HeaderBackground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_ISettingsFlyoutTemplateSettings<D>::HeaderForeground() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings)->get_HeaderForeground(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_ISettingsFlyoutTemplateSettings<D>::BorderBrush() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings)->get_BorderBrush(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) consume_Windows_UI_Xaml_Controls_Primitives_ISettingsFlyoutTemplateSettings<D>::BorderThickness() const
    {
        winrt::Windows::UI::Xaml::Thickness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings)->get_BorderThickness(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::ImageSource) consume_Windows_UI_Xaml_Controls_Primitives_ISettingsFlyoutTemplateSettings<D>::IconSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings)->get_IconSource(&value));
        return winrt::Windows::UI::Xaml::Media::ImageSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection) consume_Windows_UI_Xaml_Controls_Primitives_ISettingsFlyoutTemplateSettings<D>::ContentTransitions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings)->get_ContentTransitions(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ISplitViewTemplateSettings<D>::OpenPaneLength() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings)->get_OpenPaneLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ISplitViewTemplateSettings<D>::NegativeOpenPaneLength() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings)->get_NegativeOpenPaneLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ISplitViewTemplateSettings<D>::OpenPaneLengthMinusCompactLength() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings)->get_OpenPaneLengthMinusCompactLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_ISplitViewTemplateSettings<D>::NegativeOpenPaneLengthMinusCompactLength() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings)->get_NegativeOpenPaneLengthMinusCompactLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::GridLength) consume_Windows_UI_Xaml_Controls_Primitives_ISplitViewTemplateSettings<D>::OpenPaneGridLength() const
    {
        winrt::Windows::UI::Xaml::GridLength value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings)->get_OpenPaneGridLength(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::GridLength) consume_Windows_UI_Xaml_Controls_Primitives_ISplitViewTemplateSettings<D>::CompactPaneGridLength() const
    {
        winrt::Windows::UI::Xaml::GridLength value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings)->get_CompactPaneGridLength(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::IsDragging() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IThumb)->get_IsDragging(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragStarted(winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IThumb)->add_DragStarted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragStarted_revoker consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragStarted(auto_revoke_t, winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, DragStarted_revoker>(this, DragStarted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragStarted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IThumb)->remove_DragStarted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragDelta(winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IThumb)->add_DragDelta(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragDelta_revoker consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragDelta(auto_revoke_t, winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, DragDelta_revoker>(this, DragDelta(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragDelta(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IThumb)->remove_DragDelta(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragCompleted(winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IThumb)->add_DragCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragCompleted_revoker consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragCompleted(auto_revoke_t, winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, DragCompleted_revoker>(this, DragCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::DragCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IThumb)->remove_DragCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IThumb<D>::CancelDrag() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IThumb)->CancelDrag());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IThumbStatics<D>::IsDraggingProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IThumbStatics)->get_IsDraggingProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Controls_Primitives_ITickBar<D>::Fill() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ITickBar)->get_Fill(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_ITickBar<D>::Fill(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ITickBar)->put_Fill(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_ITickBarStatics<D>::FillProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::ITickBarStatics)->get_FillProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<bool>) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::IsChecked() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton)->get_IsChecked(&value));
        return winrt::Windows::Foundation::IReference<bool>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::IsChecked(winrt::Windows::Foundation::IReference<bool> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton)->put_IsChecked(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::IsThreeState() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton)->get_IsThreeState(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::IsThreeState(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton)->put_IsThreeState(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Checked(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton)->add_Checked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Checked_revoker consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Checked(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, Checked_revoker>(this, Checked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Checked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton)->remove_Checked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Unchecked(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton)->add_Unchecked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Unchecked_revoker consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Unchecked(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, Unchecked_revoker>(this, Unchecked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Unchecked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton)->remove_Unchecked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Indeterminate(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton)->add_Indeterminate(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Indeterminate_revoker consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Indeterminate(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, Indeterminate_revoker>(this, Indeterminate(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButton<D>::Indeterminate(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton)->remove_Indeterminate(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::ToggleButton) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButtonFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Controls::Primitives::ToggleButton{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButtonOverrides<D>::OnToggle() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides)->OnToggle());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButtonStatics<D>::IsCheckedProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonStatics)->get_IsCheckedProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Controls_Primitives_IToggleButtonStatics<D>::IsThreeStateProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonStatics)->get_IsThreeStateProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::KnobCurrentToOnOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_KnobCurrentToOnOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::KnobCurrentToOffOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_KnobCurrentToOffOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::KnobOnToOffOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_KnobOnToOffOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::KnobOffToOnOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_KnobOffToOnOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::CurtainCurrentToOnOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_CurtainCurrentToOnOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::CurtainCurrentToOffOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_CurtainCurrentToOffOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::CurtainOnToOffOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_CurtainOnToOffOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IToggleSwitchTemplateSettings<D>::CurtainOffToOnOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings)->get_CurtainOffToOnOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IToolTipTemplateSettings<D>::FromHorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToolTipTemplateSettings)->get_FromHorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Controls_Primitives_IToolTipTemplateSettings<D>::FromVerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Controls::Primitives::IToolTipTemplateSettings)->get_FromVerticalOffset(&value));
        return value;
    }
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Controls::Primitives::ItemsChangedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Controls::Primitives::ItemsChangedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Controls::Primitives::ItemsChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::ItemsChangedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarButtonTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarButtonTemplateSettings>
    {
        int32_t __stdcall get_KeyboardAcceleratorTextMinWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().KeyboardAcceleratorTextMinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings>
    {
        int32_t __stdcall get_ClipRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().ClipRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CompactVerticalDelta(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CompactVerticalDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CompactRootMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().CompactRootMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinimalVerticalDelta(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MinimalVerticalDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinimalRootMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().MinimalRootMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HiddenVerticalDelta(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HiddenVerticalDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HiddenRootMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().HiddenRootMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings2> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings2>
    {
        int32_t __stdcall get_NegativeCompactVerticalDelta(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().NegativeCompactVerticalDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NegativeMinimalVerticalDelta(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().NegativeMinimalVerticalDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NegativeHiddenVerticalDelta(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().NegativeHiddenVerticalDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarToggleButtonTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarToggleButtonTemplateSettings>
    {
        int32_t __stdcall get_KeyboardAcceleratorTextMinWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().KeyboardAcceleratorTextMinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase>
    {
        int32_t __stdcall get_ClickMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::ClickMode>(this->shim().ClickMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClickMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClickMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ClickMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPointerOver(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPointerOver());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPressed());
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
        int32_t __stdcall get_CommandParameter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().CommandParameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CommandParameter(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CommandParameter(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Click(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Click(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
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
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::ButtonBase>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics>
    {
        int32_t __stdcall get_ClickModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ClickModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPointerOverProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsPointerOverProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPressedProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsPressedProperty());
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
        int32_t __stdcall get_CommandParameterProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CommandParameterProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarPanel> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarPanel>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings>
    {
        int32_t __stdcall get_MinViewWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MinViewWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeaderText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HeaderText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WeekDay1(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().WeekDay1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WeekDay2(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().WeekDay2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WeekDay3(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().WeekDay3());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WeekDay4(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().WeekDay4());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WeekDay5(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().WeekDay5());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WeekDay6(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().WeekDay6());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WeekDay7(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().WeekDay7());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasMoreContentAfter(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasMoreContentAfter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasMoreContentBefore(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasMoreContentBefore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasMoreViews(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasMoreViews());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClipRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().ClipRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CenterX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CenterX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CenterY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CenterY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel>
    {
        int32_t __stdcall get_CanVerticallyScroll(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanVerticallyScroll());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanVerticallyScroll(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanVerticallyScroll(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanHorizontallyScroll(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanHorizontallyScroll());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanHorizontallyScroll(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanHorizontallyScroll(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtentWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ExtentWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtentHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ExtentHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ViewportWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ViewportWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ViewportHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ViewportHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().VerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScrollOwner(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().ScrollOwner());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScrollOwner(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScrollOwner(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LineUp() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineUp();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LineDown() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineDown();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LineLeft() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineLeft();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LineRight() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineRight();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PageUp() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PageUp();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PageDown() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PageDown();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PageLeft() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PageLeft();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PageRight() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PageRight();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MouseWheelUp() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MouseWheelUp();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MouseWheelDown() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MouseWheelDown();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MouseWheelLeft() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MouseWheelLeft();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MouseWheelRight() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MouseWheelRight();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetHorizontalOffset(double offset) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetHorizontalOffset(offset);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetVerticalOffset(double offset) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetVerticalOffset(offset);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MakeVisible(void* visual, winrt::Windows::Foundation::Rect rectangle, winrt::Windows::Foundation::Rect* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Rect>(this->shim().MakeVisible(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&visual), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&rectangle)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanelFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanelFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::CarouselPanel>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSlider> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSlider>
    {
        int32_t __stdcall get_ColorChannel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::ColorPickerHsvChannel>(this->shim().ColorChannel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ColorChannel(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ColorChannel(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ColorPickerHsvChannel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderStatics>
    {
        int32_t __stdcall get_ColorChannelProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ColorChannelProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum>
    {
        int32_t __stdcall get_Color(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Color(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Color(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HsvColor(winrt::Windows::Foundation::Numerics::float4* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float4>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float4>(this->shim().HsvColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HsvColor(winrt::Windows::Foundation::Numerics::float4 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HsvColor(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float4 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinHue(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MinHue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MinHue(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MinHue(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxHue(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MaxHue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxHue(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxHue(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinSaturation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MinSaturation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MinSaturation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MinSaturation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxSaturation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MaxSaturation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxSaturation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxSaturation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinValue(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MinValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MinValue(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MinValue(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxValue(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MaxValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxValue(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxValue(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Shape(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::ColorSpectrumShape>(this->shim().Shape());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Shape(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Shape(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ColorSpectrumShape const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Components(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::ColorSpectrumComponents>(this->shim().Components());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Components(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Components(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ColorSpectrumComponents const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ColorChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ColorChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Controls::Primitives::ColorSpectrum, winrt::Windows::UI::Xaml::Controls::ColorChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ColorChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ColorChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::ColorSpectrum>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics>
    {
        int32_t __stdcall get_ColorProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ColorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HsvColorProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().HsvColorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinHueProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MinHueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxHueProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MaxHueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinSaturationProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MinSaturationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxSaturationProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MaxSaturationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinValueProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MinValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxValueProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MaxValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShapeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ShapeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ComponentsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ComponentsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings>
    {
        int32_t __stdcall get_DropDownOpenedHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DropDownOpenedHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DropDownClosedHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DropDownClosedHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DropDownOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DropDownOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedItemDirection(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection>(this->shim().SelectedItemDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings2> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings2>
    {
        int32_t __stdcall get_DropDownContentMinWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DropDownContentMinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBar> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBar>
    {
        int32_t __stdcall get_FlyoutTemplateSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBarTemplateSettings>(this->shim().FlyoutTemplateSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBar>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings>
    {
        int32_t __stdcall get_OpenAnimationStartPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OpenAnimationStartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OpenAnimationEndPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OpenAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CloseAnimationEndPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CloseAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CurrentWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpandedWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ExpandedWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WidthExpansionDelta(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().WidthExpansionDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WidthExpansionAnimationStartPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().WidthExpansionAnimationStartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WidthExpansionAnimationEndPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().WidthExpansionAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WidthExpansionMoreButtonAnimationStartPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().WidthExpansionMoreButtonAnimationStartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WidthExpansionMoreButtonAnimationEndPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().WidthExpansionMoreButtonAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpandUpOverflowVerticalPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ExpandUpOverflowVerticalPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpandDownOverflowVerticalPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ExpandDownOverflowVerticalPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpandUpAnimationStartPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ExpandUpAnimationStartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpandUpAnimationEndPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ExpandUpAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpandUpAnimationHoldPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ExpandUpAnimationHoldPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpandDownAnimationStartPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ExpandDownAnimationStartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpandDownAnimationEndPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ExpandDownAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpandDownAnimationHoldPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ExpandDownAnimationHoldPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentClipRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().ContentClipRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OverflowContentClipRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().OverflowContentClipRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings>
    {
        int32_t __stdcall get_ContentHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ContentHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OverflowContentClipRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().OverflowContentClipRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OverflowContentMinWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OverflowContentMinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OverflowContentMaxHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OverflowContentMaxHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OverflowContentHorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OverflowContentHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OverflowContentHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OverflowContentHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NegativeOverflowContentHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().NegativeOverflowContentHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings2> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings2>
    {
        int32_t __stdcall get_OverflowContentMaxWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OverflowContentMaxWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings3> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings3>
    {
        int32_t __stdcall get_EffectiveOverflowButtonVisibility(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Visibility>(this->shim().EffectiveOverflowButtonVisibility());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings4> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings4>
    {
        int32_t __stdcall get_OverflowContentCompactYTranslation(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OverflowContentCompactYTranslation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OverflowContentMinimalYTranslation(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OverflowContentMinimalYTranslation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OverflowContentHiddenYTranslation(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OverflowContentHiddenYTranslation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs>
    {
        int32_t __stdcall get_HorizontalChange(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalChange(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().VerticalChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Canceled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Canceled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgsFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgsFactory>
    {
        int32_t __stdcall CreateInstanceWithHorizontalChangeVerticalChangeAndCanceled(double horizontalChange, double verticalChange, bool canceled, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs>(this->shim().CreateInstanceWithHorizontalChangeVerticalChangeAndCanceled(horizontalChange, verticalChange, canceled, *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgs>
    {
        int32_t __stdcall get_HorizontalChange(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalChange(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().VerticalChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgsFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgsFactory>
    {
        int32_t __stdcall CreateInstanceWithHorizontalChangeAndVerticalChange(double horizontalChange, double verticalChange, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs>(this->shim().CreateInstanceWithHorizontalChangeAndVerticalChange(horizontalChange, verticalChange, *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgs>
    {
        int32_t __stdcall get_HorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().VerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgsFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgsFactory>
    {
        int32_t __stdcall CreateInstanceWithHorizontalOffsetAndVerticalOffset(double horizontalOffset, double verticalOffset, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs>(this->shim().CreateInstanceWithHorizontalOffsetAndVerticalOffset(horizontalOffset, verticalOffset, *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase>
    {
        int32_t __stdcall get_Placement(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode>(this->shim().Placement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Placement(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Placement(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Opened(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Opened(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Opened(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Opened(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Closed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Opening(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Opening(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Opening(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Opening(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall ShowAt(void* placementTarget) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowAt(*reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&placementTarget));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Hide() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Hide();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2>
    {
        int32_t __stdcall get_Target(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::FrameworkElement>(this->shim().Target());
            return 0;
        }
        catch (...) { return to_hresult(); }
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
        int32_t __stdcall get_LightDismissOverlayMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::LightDismissOverlayMode>(this->shim().LightDismissOverlayMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LightDismissOverlayMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LightDismissOverlayMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::LightDismissOverlayMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowFocusWhenDisabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowFocusWhenDisabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowFocusWhenDisabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowFocusWhenDisabled(value);
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
        int32_t __stdcall add_Closing(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closing(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBaseClosingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closing(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closing(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3>
    {
        int32_t __stdcall get_OverlayInputPassThroughElement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().OverlayInputPassThroughElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OverlayInputPassThroughElement(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OverlayInputPassThroughElement(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase4> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase4>
    {
        int32_t __stdcall TryInvokeKeyboardAccelerator(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TryInvokeKeyboardAccelerator(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5>
    {
        int32_t __stdcall get_ShowMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode>(this->shim().ShowMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShowMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InputDevicePrefersPrimaryCommands(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().InputDevicePrefersPrimaryCommands());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AreOpenCloseAnimationsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AreOpenCloseAnimationsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AreOpenCloseAnimationsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AreOpenCloseAnimationsEnabled(value);
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
        int32_t __stdcall ShowAt(void* placementTarget, void* showOptions) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowAt(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&placementTarget), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions const*>(&showOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6>
    {
        int32_t __stdcall get_ShouldConstrainToRootBounds(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShouldConstrainToRootBounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShouldConstrainToRootBounds(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShouldConstrainToRootBounds(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsConstrainedToRootBounds(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsConstrainedToRootBounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
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
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseClosingEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseClosingEventArgs>
    {
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
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides>
    {
        int32_t __stdcall CreatePresenter(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Controls::Control>(this->shim().CreatePresenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4>
    {
        int32_t __stdcall OnProcessKeyboardAccelerators(void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnProcessKeyboardAccelerators(*reinterpret_cast<winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics>
    {
        int32_t __stdcall get_PlacementProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PlacementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AttachedFlyoutProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AttachedFlyoutProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAttachedFlyout(void* element, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase>(this->shim().GetAttachedFlyout(*reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetAttachedFlyout(void* element, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetAttachedFlyout(*reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&element), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowAttachedFlyout(void* flyoutOwner) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowAttachedFlyout(*reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&flyoutOwner));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2>
    {
        int32_t __stdcall get_AllowFocusOnInteractionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AllowFocusOnInteractionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LightDismissOverlayModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().LightDismissOverlayModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowFocusWhenDisabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AllowFocusWhenDisabledProperty());
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
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics3> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics3>
    {
        int32_t __stdcall get_OverlayInputPassThroughElementProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OverlayInputPassThroughElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5>
    {
        int32_t __stdcall get_TargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShowModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ShowModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InputDevicePrefersPrimaryCommandsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().InputDevicePrefersPrimaryCommandsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AreOpenCloseAnimationsEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AreOpenCloseAnimationsEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOpenProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsOpenProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics6> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics6>
    {
        int32_t __stdcall get_ShouldConstrainToRootBoundsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ShouldConstrainToRootBoundsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions>
    {
        int32_t __stdcall get_Position(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Position(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Position(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExclusionRect(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>>(this->shim().ExclusionRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExclusionRect(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExclusionRect(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShowMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode>(this->shim().ShowMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShowMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Placement(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode>(this->shim().Placement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Placement(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Placement(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptionsFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptionsFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelper> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelper>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelperStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelperStatics>
    {
        int32_t __stdcall FromIndexAndOffset(int32_t index, int32_t offset, struct struct_Windows_UI_Xaml_Controls_Primitives_GeneratorPosition* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPosition>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPosition>(this->shim().FromIndexAndOffset(index, offset));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter>
    {
        int32_t __stdcall get_SelectionCheckMarkVisualEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SelectionCheckMarkVisualEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectionCheckMarkVisualEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionCheckMarkVisualEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckHintBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckHintBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckHintBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckHintBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckSelectingBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckSelectingBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckSelectingBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckSelectingBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().DragBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DragBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DragBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragForeground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().DragForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DragForeground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DragForeground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().FocusBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FocusBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FocusBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaceholderBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().PlaceholderBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PlaceholderBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaceholderBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerOverBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().PointerOverBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PointerOverBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerOverBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedForeground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedForeground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedForeground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedPointerOverBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedPointerOverBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedPointerOverBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedPointerOverBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedPointerOverBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedPointerOverBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedPointerOverBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedPointerOverBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedBorderThickness(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().SelectedBorderThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedBorderThickness(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedBorderThickness(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisabledOpacity(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DisabledOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisabledOpacity(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisabledOpacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragOpacity(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DragOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DragOpacity(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DragOpacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReorderHintOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ReorderHintOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReorderHintOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReorderHintOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GridViewItemPresenterHorizontalContentAlignment(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::HorizontalAlignment>(this->shim().GridViewItemPresenterHorizontalContentAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_GridViewItemPresenterHorizontalContentAlignment(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GridViewItemPresenterHorizontalContentAlignment(*reinterpret_cast<winrt::Windows::UI::Xaml::HorizontalAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GridViewItemPresenterVerticalContentAlignment(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::VerticalAlignment>(this->shim().GridViewItemPresenterVerticalContentAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_GridViewItemPresenterVerticalContentAlignment(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GridViewItemPresenterVerticalContentAlignment(*reinterpret_cast<winrt::Windows::UI::Xaml::VerticalAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GridViewItemPresenterPadding(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().GridViewItemPresenterPadding());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_GridViewItemPresenterPadding(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GridViewItemPresenterPadding(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerOverBackgroundMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().PointerOverBackgroundMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PointerOverBackgroundMargin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerOverBackgroundMargin(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().ContentMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentMargin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentMargin(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::GridViewItemPresenter>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics>
    {
        int32_t __stdcall get_SelectionCheckMarkVisualEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectionCheckMarkVisualEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckHintBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckHintBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckSelectingBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckSelectingBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DragBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragForegroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DragForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FocusBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaceholderBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PlaceholderBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerOverBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PointerOverBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedForegroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedPointerOverBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedPointerOverBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedPointerOverBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedPointerOverBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedBorderThicknessProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedBorderThicknessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisabledOpacityProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DisabledOpacityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragOpacityProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DragOpacityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReorderHintOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ReorderHintOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GridViewItemPresenterHorizontalContentAlignmentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().GridViewItemPresenterHorizontalContentAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GridViewItemPresenterVerticalContentAlignmentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().GridViewItemPresenterVerticalContentAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GridViewItemPresenterPaddingProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().GridViewItemPresenterPaddingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerOverBackgroundMarginProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PointerOverBackgroundMarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentMarginProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContentMarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemTemplateSettings>
    {
        int32_t __stdcall get_DragItemsCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().DragItemsCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs>
    {
        int32_t __stdcall get_Action(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Action());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(struct struct_Windows_UI_Xaml_Controls_Primitives_GeneratorPosition* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPosition>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPosition>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OldPosition(struct struct_Windows_UI_Xaml_Controls_Primitives_GeneratorPosition* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPosition>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPosition>(this->shim().OldPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ItemCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemUICount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ItemUICount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter>
    {
        int32_t __stdcall get_Enabled(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Enabled(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Enabled(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Disabled(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().Disabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Disabled(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Disabled(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverterStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverterStatics>
    {
        int32_t __stdcall get_EnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DisabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter>
    {
        int32_t __stdcall get_Enabled(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Enabled(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Enabled(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Disabled(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().Disabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Disabled(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Disabled(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverterStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverterStatics>
    {
        int32_t __stdcall get_EnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DisabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformation> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformation>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics>
    {
        int32_t __stdcall GetLayoutExceptionElement(void* dispatcher, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().GetLayoutExceptionElement(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dispatcher)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLayoutSlot(void* element, winrt::Windows::Foundation::Rect* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Rect>(this->shim().GetLayoutSlot(*reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics2>
    {
        int32_t __stdcall GetAvailableSize(void* element, winrt::Windows::Foundation::Size* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Size>(this->shim().GetAvailableSize(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter>
    {
        int32_t __stdcall get_SelectionCheckMarkVisualEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SelectionCheckMarkVisualEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectionCheckMarkVisualEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionCheckMarkVisualEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckHintBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckHintBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckHintBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckHintBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckSelectingBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckSelectingBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckSelectingBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckSelectingBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().DragBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DragBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DragBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragForeground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().DragForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DragForeground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DragForeground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().FocusBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FocusBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FocusBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaceholderBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().PlaceholderBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PlaceholderBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaceholderBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerOverBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().PointerOverBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PointerOverBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerOverBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedForeground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedForeground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedForeground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedPointerOverBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedPointerOverBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedPointerOverBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedPointerOverBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedPointerOverBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedPointerOverBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedPointerOverBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedPointerOverBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedBorderThickness(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().SelectedBorderThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedBorderThickness(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedBorderThickness(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisabledOpacity(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DisabledOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisabledOpacity(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisabledOpacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragOpacity(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DragOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DragOpacity(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DragOpacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReorderHintOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ReorderHintOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReorderHintOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReorderHintOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ListViewItemPresenterHorizontalContentAlignment(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::HorizontalAlignment>(this->shim().ListViewItemPresenterHorizontalContentAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ListViewItemPresenterHorizontalContentAlignment(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ListViewItemPresenterHorizontalContentAlignment(*reinterpret_cast<winrt::Windows::UI::Xaml::HorizontalAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ListViewItemPresenterVerticalContentAlignment(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::VerticalAlignment>(this->shim().ListViewItemPresenterVerticalContentAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ListViewItemPresenterVerticalContentAlignment(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ListViewItemPresenterVerticalContentAlignment(*reinterpret_cast<winrt::Windows::UI::Xaml::VerticalAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ListViewItemPresenterPadding(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().ListViewItemPresenterPadding());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ListViewItemPresenterPadding(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ListViewItemPresenterPadding(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerOverBackgroundMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().PointerOverBackgroundMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PointerOverBackgroundMargin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerOverBackgroundMargin(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().ContentMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentMargin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentMargin(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2>
    {
        int32_t __stdcall get_SelectedPressedBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedPressedBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedPressedBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedPressedBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PressedBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().PressedBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PressedBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PressedBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBoxBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBoxBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBoxBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusSecondaryBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().FocusSecondaryBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FocusSecondaryBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FocusSecondaryBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode>(this->shim().CheckMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterCheckMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerOverForeground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().PointerOverForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PointerOverForeground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerOverForeground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3>
    {
        int32_t __stdcall get_RevealBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().RevealBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RevealBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RevealBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RevealBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().RevealBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RevealBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RevealBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RevealBorderThickness(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().RevealBorderThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RevealBorderThickness(struct struct_Windows_UI_Xaml_Thickness value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RevealBorderThickness(*reinterpret_cast<winrt::Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RevealBackgroundShowsAboveContent(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().RevealBackgroundShowsAboveContent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RevealBackgroundShowsAboveContent(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RevealBackgroundShowsAboveContent(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4>
    {
        int32_t __stdcall get_SelectedDisabledBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedDisabledBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedDisabledBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedDisabledBackground(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckPressedBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckPressedBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckPressedBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckPressedBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckDisabledBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckDisabledBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckDisabledBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckDisabledBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxPointerOverBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBoxPointerOverBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBoxPointerOverBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBoxPointerOverBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxPressedBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBoxPressedBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBoxPressedBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBoxPressedBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxDisabledBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBoxDisabledBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBoxDisabledBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBoxDisabledBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxSelectedBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBoxSelectedBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBoxSelectedBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBoxSelectedBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxSelectedPointerOverBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBoxSelectedPointerOverBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBoxSelectedPointerOverBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBoxSelectedPointerOverBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxSelectedPressedBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBoxSelectedPressedBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBoxSelectedPressedBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBoxSelectedPressedBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxSelectedDisabledBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBoxSelectedDisabledBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBoxSelectedDisabledBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBoxSelectedDisabledBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBoxBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBoxBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBoxBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxPointerOverBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBoxPointerOverBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBoxPointerOverBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBoxPointerOverBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxPressedBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBoxPressedBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBoxPressedBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBoxPressedBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxDisabledBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().CheckBoxDisabledBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBoxDisabledBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBoxDisabledBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxCornerRadius(struct struct_Windows_UI_Xaml_CornerRadius* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::CornerRadius>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::CornerRadius>(this->shim().CheckBoxCornerRadius());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CheckBoxCornerRadius(struct struct_Windows_UI_Xaml_CornerRadius value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CheckBoxCornerRadius(*reinterpret_cast<winrt::Windows::UI::Xaml::CornerRadius const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorCornerRadius(struct struct_Windows_UI_Xaml_CornerRadius* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::CornerRadius>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::CornerRadius>(this->shim().SelectionIndicatorCornerRadius());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectionIndicatorCornerRadius(struct struct_Windows_UI_Xaml_CornerRadius value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionIndicatorCornerRadius(*reinterpret_cast<winrt::Windows::UI::Xaml::CornerRadius const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorVisualEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SelectionIndicatorVisualEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectionIndicatorVisualEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionIndicatorVisualEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterSelectionIndicatorMode>(this->shim().SelectionIndicatorMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectionIndicatorMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionIndicatorMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenterSelectionIndicatorMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectionIndicatorBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectionIndicatorBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionIndicatorBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorPointerOverBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectionIndicatorPointerOverBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectionIndicatorPointerOverBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionIndicatorPointerOverBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorPressedBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectionIndicatorPressedBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectionIndicatorPressedBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionIndicatorPressedBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorDisabledBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectionIndicatorDisabledBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectionIndicatorDisabledBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionIndicatorDisabledBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedPressedBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedPressedBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedPressedBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedPressedBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedDisabledBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedDisabledBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedDisabledBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedDisabledBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedInnerBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().SelectedInnerBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedInnerBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedInnerBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerOverBorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().PointerOverBorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PointerOverBorderBrush(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerOverBorderBrush(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenter>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics>
    {
        int32_t __stdcall get_SelectionCheckMarkVisualEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectionCheckMarkVisualEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckHintBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckHintBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckSelectingBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckSelectingBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DragBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragForegroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DragForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FocusBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaceholderBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PlaceholderBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerOverBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PointerOverBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedForegroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedPointerOverBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedPointerOverBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedPointerOverBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedPointerOverBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedBorderThicknessProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedBorderThicknessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisabledOpacityProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DisabledOpacityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DragOpacityProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DragOpacityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReorderHintOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ReorderHintOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ListViewItemPresenterHorizontalContentAlignmentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ListViewItemPresenterHorizontalContentAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ListViewItemPresenterVerticalContentAlignmentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ListViewItemPresenterVerticalContentAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ListViewItemPresenterPaddingProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ListViewItemPresenterPaddingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerOverBackgroundMarginProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PointerOverBackgroundMarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentMarginProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContentMarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2>
    {
        int32_t __stdcall get_SelectedPressedBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedPressedBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PressedBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PressedBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FocusSecondaryBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FocusSecondaryBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerOverForegroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PointerOverForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3>
    {
        int32_t __stdcall get_RevealBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RevealBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RevealBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RevealBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RevealBorderThicknessProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RevealBorderThicknessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RevealBackgroundShowsAboveContentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RevealBackgroundShowsAboveContentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4>
    {
        int32_t __stdcall get_SelectedDisabledBackgroundProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedDisabledBackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckPressedBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckPressedBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckDisabledBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckDisabledBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxPointerOverBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxPointerOverBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxPressedBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxPressedBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxDisabledBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxDisabledBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxSelectedBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxSelectedBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxSelectedPointerOverBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxSelectedPointerOverBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxSelectedPressedBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxSelectedPressedBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxSelectedDisabledBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxSelectedDisabledBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxPointerOverBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxPointerOverBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxPressedBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxPressedBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxDisabledBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxDisabledBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CheckBoxCornerRadiusProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CheckBoxCornerRadiusProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorCornerRadiusProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectionIndicatorCornerRadiusProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorVisualEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectionIndicatorVisualEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectionIndicatorModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectionIndicatorBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorPointerOverBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectionIndicatorPointerOverBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorPressedBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectionIndicatorPressedBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionIndicatorDisabledBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectionIndicatorDisabledBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedPressedBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedPressedBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedDisabledBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedDisabledBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedInnerBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedInnerBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerOverBorderBrushProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PointerOverBorderBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemTemplateSettings>
    {
        int32_t __stdcall get_DragItemsCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().DragItemsCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector>
    {
        int32_t __stdcall get_ShouldLoop(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShouldLoop());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShouldLoop(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShouldLoop(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Items(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::IInspectable>>(this->shim().Items());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Items(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Items(*reinterpret_cast<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::IInspectable> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedIndex(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().SelectedIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedIndex(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().SelectedItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedItem(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedItem(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemWidth(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ItemWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ItemWidth(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ItemWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemHeight(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ItemHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ItemHeight(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ItemHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemTemplate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DataTemplate>(this->shim().ItemTemplate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ItemTemplate(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ItemTemplate(*reinterpret_cast<winrt::Windows::UI::Xaml::DataTemplate const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SelectionChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SelectionChanged(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::SelectionChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SelectionChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorItem> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorItem>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorPanel> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorPanel>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics>
    {
        int32_t __stdcall get_ShouldLoopProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ShouldLoopProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ItemsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedIndexProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedItemProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedItemProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemWidthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ItemWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemHeightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ItemHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemTemplateProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ItemTemplateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutItemTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutItemTemplateSettings>
    {
        int32_t __stdcall get_KeyboardAcceleratorTextMinWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().KeyboardAcceleratorTextMinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutPresenterTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutPresenterTemplateSettings>
    {
        int32_t __stdcall get_FlyoutContentMinWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FlyoutContentMinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenter> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenter>
    {
        int32_t __stdcall get_Icon(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::IconElement>(this->shim().Icon());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Icon(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Icon(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::IconElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::NavigationViewItemPresenter>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterStatics>
    {
        int32_t __stdcall get_IconProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IconProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel>
    {
        int32_t __stdcall get_CanVerticallyScroll(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanVerticallyScroll());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanVerticallyScroll(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanVerticallyScroll(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanHorizontallyScroll(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanHorizontallyScroll());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanHorizontallyScroll(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanHorizontallyScroll(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtentWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ExtentWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtentHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ExtentHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ViewportWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ViewportWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ViewportHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ViewportHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().VerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScrollOwner(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().ScrollOwner());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScrollOwner(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScrollOwner(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LineUp() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineUp();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LineDown() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineDown();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LineLeft() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineLeft();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LineRight() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineRight();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PageUp() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PageUp();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PageDown() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PageDown();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PageLeft() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PageLeft();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PageRight() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PageRight();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MouseWheelUp() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MouseWheelUp();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MouseWheelDown() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MouseWheelDown();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MouseWheelLeft() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MouseWheelLeft();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MouseWheelRight() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MouseWheelRight();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetHorizontalOffset(double offset) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetHorizontalOffset(offset);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetVerticalOffset(double offset) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetVerticalOffset(offset);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MakeVisible(void* visual, winrt::Windows::Foundation::Rect rectangle, winrt::Windows::Foundation::Rect* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Rect>(this->shim().MakeVisible(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&visual), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&rectangle)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanelFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanelFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBase> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBase>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::PickerFlyoutBase>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides>
    {
        int32_t __stdcall OnConfirmed() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnConfirmed();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShouldShowConfirmationButtons(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().ShouldShowConfirmationButtons());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics>
    {
        int32_t __stdcall get_TitleProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TitleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTitle(void* element, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetTitle(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetTitle(void* element, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetTitle(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItem> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItem>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItemFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItemFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::PivotHeaderItem>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderPanel> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderPanel>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPivotPanel> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPivotPanel>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopup> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopup>
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
        int32_t __stdcall get_HorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HorizontalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().VerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VerticalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChildTransitions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection>(this->shim().ChildTransitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChildTransitions(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChildTransitions(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLightDismissEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLightDismissEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsLightDismissEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsLightDismissEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Opened(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Opened(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Opened(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Opened(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Closed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopup2> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopup2>
    {
        int32_t __stdcall get_LightDismissOverlayMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::LightDismissOverlayMode>(this->shim().LightDismissOverlayMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LightDismissOverlayMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LightDismissOverlayMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::LightDismissOverlayMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopup3> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopup3>
    {
        int32_t __stdcall get_ShouldConstrainToRootBounds(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShouldConstrainToRootBounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShouldConstrainToRootBounds(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShouldConstrainToRootBounds(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsConstrainedToRootBounds(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsConstrainedToRootBounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopup4> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopup4>
    {
        int32_t __stdcall get_PlacementTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::FrameworkElement>(this->shim().PlacementTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PlacementTarget(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlacementTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredPlacement(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::PopupPlacementMode>(this->shim().DesiredPlacement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredPlacement(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredPlacement(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::PopupPlacementMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActualPlacement(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::PopupPlacementMode>(this->shim().ActualPlacement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ActualPlacementChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ActualPlacementChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ActualPlacementChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ActualPlacementChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics>
    {
        int32_t __stdcall get_ChildProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ChildProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOpenProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsOpenProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HorizontalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().HorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().VerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChildTransitionsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ChildTransitionsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLightDismissEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsLightDismissEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics2>
    {
        int32_t __stdcall get_LightDismissOverlayModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().LightDismissOverlayModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics3> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics3>
    {
        int32_t __stdcall get_ShouldConstrainToRootBoundsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ShouldConstrainToRootBoundsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics4> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics4>
    {
        int32_t __stdcall get_PlacementTargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PlacementTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredPlacementProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DesiredPlacementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings>
    {
        int32_t __stdcall get_EllipseDiameter(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().EllipseDiameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EllipseOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().EllipseOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EllipseAnimationWellPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().EllipseAnimationWellPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EllipseAnimationEndPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().EllipseAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContainerAnimationStartPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ContainerAnimationStartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContainerAnimationEndPosition(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ContainerAnimationEndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IndicatorLengthDelta(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().IndicatorLengthDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IProgressRingTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IProgressRingTemplateSettings>
    {
        int32_t __stdcall get_EllipseDiameter(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().EllipseDiameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EllipseOffset(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().EllipseOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxSideLength(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MaxSideLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase>
    {
        int32_t __stdcall get_Minimum(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Minimum());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Minimum(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Minimum(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Maximum(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Maximum());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Maximum(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Maximum(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SmallChange(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().SmallChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SmallChange(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SmallChange(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LargeChange(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().LargeChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LargeChange(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LargeChange(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Value(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Value(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Value(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ValueChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ValueChanged(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ValueChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ValueChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::RangeBase>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides>
    {
        int32_t __stdcall OnMinimumChanged(double oldMinimum, double newMinimum) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnMinimumChanged(oldMinimum, newMinimum);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnMaximumChanged(double oldMaximum, double newMaximum) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnMaximumChanged(oldMaximum, newMaximum);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnValueChanged(double oldValue, double newValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnValueChanged(oldValue, newValue);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics>
    {
        int32_t __stdcall get_MinimumProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MinimumProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaximumProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().MaximumProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SmallChangeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SmallChangeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LargeChangeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().LargeChangeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ValueProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseValueChangedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseValueChangedEventArgs>
    {
        int32_t __stdcall get_OldValue(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OldValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NewValue(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().NewValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButton> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButton>
    {
        int32_t __stdcall get_Delay(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Delay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Delay(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Delay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Interval(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Interval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Interval(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Interval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButtonStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButtonStatics>
    {
        int32_t __stdcall get_DelayProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DelayProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IntervalProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IntervalProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBar> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBar>
    {
        int32_t __stdcall get_Orientation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Orientation>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Orientation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Orientation(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Orientation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ViewportSize(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ViewportSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ViewportSize(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ViewportSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IndicatorMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode>(this->shim().IndicatorMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IndicatorMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IndicatorMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollingIndicatorMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Scroll(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Scroll(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Scroll(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Scroll(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics>
    {
        int32_t __stdcall get_OrientationProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OrientationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ViewportSizeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ViewportSizeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IndicatorModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IndicatorModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IScrollEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IScrollEventArgs>
    {
        int32_t __stdcall get_NewValue(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().NewValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScrollEventType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventType>(this->shim().ScrollEventType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo>
    {
        int32_t __stdcall get_AreHorizontalSnapPointsRegular(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AreHorizontalSnapPointsRegular());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AreVerticalSnapPointsRegular(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AreVerticalSnapPointsRegular());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_HorizontalSnapPointsChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().HorizontalSnapPointsChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_HorizontalSnapPointsChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HorizontalSnapPointsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_VerticalSnapPointsChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().VerticalSnapPointsChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_VerticalSnapPointsChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VerticalSnapPointsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetIrregularSnapPoints(int32_t orientation, int32_t alignment, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<float>>(this->shim().GetIrregularSnapPoints(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Orientation const*>(&orientation), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::SnapPointsAlignment const*>(&alignment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRegularSnapPoints(int32_t orientation, int32_t alignment, float* offset, float* returnValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<float>(this->shim().GetRegularSnapPoints(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Orientation const*>(&orientation), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::SnapPointsAlignment const*>(&alignment), *offset));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISelector> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISelector>
    {
        int32_t __stdcall get_SelectedIndex(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().SelectedIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedIndex(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().SelectedItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedItem(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedItem(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedValue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().SelectedValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedValue(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedValue(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedValuePath(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SelectedValuePath());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedValuePath(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedValuePath(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSynchronizedWithCurrentItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<bool>>(this->shim().IsSynchronizedWithCurrentItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsSynchronizedWithCurrentItem(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsSynchronizedWithCurrentItem(*reinterpret_cast<winrt::Windows::Foundation::IReference<bool> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SelectionChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SelectionChanged(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::SelectionChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SelectionChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItem> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItem>
    {
        int32_t __stdcall get_IsSelected(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSelected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsSelected(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsSelected(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItemFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItemFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::SelectorItem>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItemStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItemStatics>
    {
        int32_t __stdcall get_IsSelectedProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsSelectedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorStatics>
    {
        int32_t __stdcall get_SelectedIndexProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedItemProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedItemProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedValueProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedValuePathProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SelectedValuePathProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSynchronizedWithCurrentItemProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsSynchronizedWithCurrentItemProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsSelectionActive(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetIsSelectionActive(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings>
    {
        int32_t __stdcall get_HeaderBackground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().HeaderBackground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeaderForeground(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().HeaderForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BorderBrush(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().BorderBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BorderThickness(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Thickness>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Thickness>(this->shim().BorderThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IconSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::ImageSource>(this->shim().IconSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTransitions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection>(this->shim().ContentTransitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings>
    {
        int32_t __stdcall get_OpenPaneLength(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OpenPaneLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NegativeOpenPaneLength(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().NegativeOpenPaneLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OpenPaneLengthMinusCompactLength(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OpenPaneLengthMinusCompactLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NegativeOpenPaneLengthMinusCompactLength(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().NegativeOpenPaneLengthMinusCompactLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OpenPaneGridLength(struct struct_Windows_UI_Xaml_GridLength* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::GridLength>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::GridLength>(this->shim().OpenPaneGridLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CompactPaneGridLength(struct struct_Windows_UI_Xaml_GridLength* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::GridLength>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::GridLength>(this->shim().CompactPaneGridLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IThumb> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IThumb>
    {
        int32_t __stdcall get_IsDragging(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDragging());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_DragStarted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DragStarted(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DragStarted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DragStarted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DragDelta(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DragDelta(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DragDelta(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DragDelta(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DragCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DragCompleted(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DragCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DragCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall CancelDrag() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CancelDrag();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IThumbStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IThumbStatics>
    {
        int32_t __stdcall get_IsDraggingProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsDraggingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ITickBar> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ITickBar>
    {
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
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::ITickBarStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::ITickBarStatics>
    {
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
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton>
    {
        int32_t __stdcall get_IsChecked(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<bool>>(this->shim().IsChecked());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsChecked(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsChecked(*reinterpret_cast<winrt::Windows::Foundation::IReference<bool> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsThreeState(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsThreeState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsThreeState(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsThreeState(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Checked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Checked(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Checked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Checked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Unchecked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Unchecked(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Unchecked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Unchecked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Indeterminate(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Indeterminate(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Indeterminate(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Indeterminate(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonFactory> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::ToggleButton>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides>
    {
        int32_t __stdcall OnToggle() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnToggle();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonStatics> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonStatics>
    {
        int32_t __stdcall get_IsCheckedProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsCheckedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsThreeStateProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsThreeStateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings>
    {
        int32_t __stdcall get_KnobCurrentToOnOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().KnobCurrentToOnOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KnobCurrentToOffOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().KnobCurrentToOffOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KnobOnToOffOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().KnobOnToOffOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KnobOffToOnOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().KnobOffToOnOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurtainCurrentToOnOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CurtainCurrentToOnOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurtainCurrentToOffOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CurtainCurrentToOffOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurtainOnToOffOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CurtainOnToOffOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurtainOffToOnOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CurtainOffToOnOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToolTipTemplateSettings> : produce_base<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToolTipTemplateSettings>
    {
        int32_t __stdcall get_FromHorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FromHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromVerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FromVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides>
{
    auto CreatePresenter()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.CreatePresenter();
        }

        return this->shim().CreatePresenter();
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4>
{
    auto OnProcessKeyboardAccelerators(winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnProcessKeyboardAccelerators(args);
        }

        return this->shim().OnProcessKeyboardAccelerators(args);
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides>
{
    auto OnConfirmed()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnConfirmed();
        }

        return this->shim().OnConfirmed();
    }
    auto ShouldShowConfirmationButtons()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.ShouldShowConfirmationButtons();
        }

        return this->shim().ShouldShowConfirmationButtons();
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides>
{
    auto OnMinimumChanged(double oldMinimum, double newMinimum)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnMinimumChanged(oldMinimum, newMinimum);
        }

        return this->shim().OnMinimumChanged(oldMinimum, newMinimum);
    }
    auto OnMaximumChanged(double oldMaximum, double newMaximum)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnMaximumChanged(oldMaximum, newMaximum);
        }

        return this->shim().OnMaximumChanged(oldMaximum, newMaximum);
    }
    auto OnValueChanged(double oldValue, double newValue)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnValueChanged(oldValue, newValue);
        }

        return this->shim().OnValueChanged(oldValue, newValue);
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides>
{
    auto OnToggle()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnToggle();
        }

        return this->shim().OnToggle();
    }
};
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Controls::Primitives
{
    inline auto ButtonBase::ClickModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IButtonBaseStatics const&), ButtonBase, IButtonBaseStatics>([](IButtonBaseStatics const& f) { return f.ClickModeProperty(); });
    }
    inline auto ButtonBase::IsPointerOverProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IButtonBaseStatics const&), ButtonBase, IButtonBaseStatics>([](IButtonBaseStatics const& f) { return f.IsPointerOverProperty(); });
    }
    inline auto ButtonBase::IsPressedProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IButtonBaseStatics const&), ButtonBase, IButtonBaseStatics>([](IButtonBaseStatics const& f) { return f.IsPressedProperty(); });
    }
    inline auto ButtonBase::CommandProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IButtonBaseStatics const&), ButtonBase, IButtonBaseStatics>([](IButtonBaseStatics const& f) { return f.CommandProperty(); });
    }
    inline auto ButtonBase::CommandParameterProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IButtonBaseStatics const&), ButtonBase, IButtonBaseStatics>([](IButtonBaseStatics const& f) { return f.CommandParameterProperty(); });
    }
    inline CalendarPanel::CalendarPanel() :
        CalendarPanel(impl::call_factory_cast<CalendarPanel(*)(winrt::Windows::Foundation::IActivationFactory const&), CalendarPanel>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CalendarPanel>(); }))
    {
    }
    inline CarouselPanel::CarouselPanel()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<CarouselPanel, ICarouselPanelFactory>([&](ICarouselPanelFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline ColorPickerSlider::ColorPickerSlider()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ColorPickerSlider, IColorPickerSliderFactory>([&](IColorPickerSliderFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto ColorPickerSlider::ColorChannelProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorPickerSliderStatics const&), ColorPickerSlider, IColorPickerSliderStatics>([](IColorPickerSliderStatics const& f) { return f.ColorChannelProperty(); });
    }
    inline ColorSpectrum::ColorSpectrum()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ColorSpectrum, IColorSpectrumFactory>([&](IColorSpectrumFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto ColorSpectrum::ColorProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorSpectrumStatics const&), ColorSpectrum, IColorSpectrumStatics>([](IColorSpectrumStatics const& f) { return f.ColorProperty(); });
    }
    inline auto ColorSpectrum::HsvColorProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorSpectrumStatics const&), ColorSpectrum, IColorSpectrumStatics>([](IColorSpectrumStatics const& f) { return f.HsvColorProperty(); });
    }
    inline auto ColorSpectrum::MinHueProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorSpectrumStatics const&), ColorSpectrum, IColorSpectrumStatics>([](IColorSpectrumStatics const& f) { return f.MinHueProperty(); });
    }
    inline auto ColorSpectrum::MaxHueProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorSpectrumStatics const&), ColorSpectrum, IColorSpectrumStatics>([](IColorSpectrumStatics const& f) { return f.MaxHueProperty(); });
    }
    inline auto ColorSpectrum::MinSaturationProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorSpectrumStatics const&), ColorSpectrum, IColorSpectrumStatics>([](IColorSpectrumStatics const& f) { return f.MinSaturationProperty(); });
    }
    inline auto ColorSpectrum::MaxSaturationProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorSpectrumStatics const&), ColorSpectrum, IColorSpectrumStatics>([](IColorSpectrumStatics const& f) { return f.MaxSaturationProperty(); });
    }
    inline auto ColorSpectrum::MinValueProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorSpectrumStatics const&), ColorSpectrum, IColorSpectrumStatics>([](IColorSpectrumStatics const& f) { return f.MinValueProperty(); });
    }
    inline auto ColorSpectrum::MaxValueProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorSpectrumStatics const&), ColorSpectrum, IColorSpectrumStatics>([](IColorSpectrumStatics const& f) { return f.MaxValueProperty(); });
    }
    inline auto ColorSpectrum::ShapeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorSpectrumStatics const&), ColorSpectrum, IColorSpectrumStatics>([](IColorSpectrumStatics const& f) { return f.ShapeProperty(); });
    }
    inline auto ColorSpectrum::ComponentsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorSpectrumStatics const&), ColorSpectrum, IColorSpectrumStatics>([](IColorSpectrumStatics const& f) { return f.ComponentsProperty(); });
    }
    inline CommandBarFlyoutCommandBar::CommandBarFlyoutCommandBar()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<CommandBarFlyoutCommandBar, ICommandBarFlyoutCommandBarFactory>([&](ICommandBarFlyoutCommandBarFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline DragCompletedEventArgs::DragCompletedEventArgs(double horizontalChange, double verticalChange, bool canceled)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<DragCompletedEventArgs, IDragCompletedEventArgsFactory>([&](IDragCompletedEventArgsFactory const& f) { return f.CreateInstanceWithHorizontalChangeVerticalChangeAndCanceled(horizontalChange, verticalChange, canceled, baseInterface, innerInterface); });
    }
    inline DragDeltaEventArgs::DragDeltaEventArgs(double horizontalChange, double verticalChange)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<DragDeltaEventArgs, IDragDeltaEventArgsFactory>([&](IDragDeltaEventArgsFactory const& f) { return f.CreateInstanceWithHorizontalChangeAndVerticalChange(horizontalChange, verticalChange, baseInterface, innerInterface); });
    }
    inline DragStartedEventArgs::DragStartedEventArgs(double horizontalOffset, double verticalOffset)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<DragStartedEventArgs, IDragStartedEventArgsFactory>([&](IDragStartedEventArgsFactory const& f) { return f.CreateInstanceWithHorizontalOffsetAndVerticalOffset(horizontalOffset, verticalOffset, baseInterface, innerInterface); });
    }
    inline auto FlyoutBase::PlacementProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFlyoutBaseStatics const&), FlyoutBase, IFlyoutBaseStatics>([](IFlyoutBaseStatics const& f) { return f.PlacementProperty(); });
    }
    inline auto FlyoutBase::AttachedFlyoutProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFlyoutBaseStatics const&), FlyoutBase, IFlyoutBaseStatics>([](IFlyoutBaseStatics const& f) { return f.AttachedFlyoutProperty(); });
    }
    inline auto FlyoutBase::GetAttachedFlyout(winrt::Windows::UI::Xaml::FrameworkElement const& element)
    {
        return impl::call_factory<FlyoutBase, IFlyoutBaseStatics>([&](IFlyoutBaseStatics const& f) { return f.GetAttachedFlyout(element); });
    }
    inline auto FlyoutBase::SetAttachedFlyout(winrt::Windows::UI::Xaml::FrameworkElement const& element, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase const& value)
    {
        impl::call_factory<FlyoutBase, IFlyoutBaseStatics>([&](IFlyoutBaseStatics const& f) { return f.SetAttachedFlyout(element, value); });
    }
    inline auto FlyoutBase::ShowAttachedFlyout(winrt::Windows::UI::Xaml::FrameworkElement const& flyoutOwner)
    {
        impl::call_factory<FlyoutBase, IFlyoutBaseStatics>([&](IFlyoutBaseStatics const& f) { return f.ShowAttachedFlyout(flyoutOwner); });
    }
    inline auto FlyoutBase::AllowFocusOnInteractionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFlyoutBaseStatics2 const&), FlyoutBase, IFlyoutBaseStatics2>([](IFlyoutBaseStatics2 const& f) { return f.AllowFocusOnInteractionProperty(); });
    }
    inline auto FlyoutBase::LightDismissOverlayModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFlyoutBaseStatics2 const&), FlyoutBase, IFlyoutBaseStatics2>([](IFlyoutBaseStatics2 const& f) { return f.LightDismissOverlayModeProperty(); });
    }
    inline auto FlyoutBase::AllowFocusWhenDisabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFlyoutBaseStatics2 const&), FlyoutBase, IFlyoutBaseStatics2>([](IFlyoutBaseStatics2 const& f) { return f.AllowFocusWhenDisabledProperty(); });
    }
    inline auto FlyoutBase::ElementSoundModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFlyoutBaseStatics2 const&), FlyoutBase, IFlyoutBaseStatics2>([](IFlyoutBaseStatics2 const& f) { return f.ElementSoundModeProperty(); });
    }
    inline auto FlyoutBase::OverlayInputPassThroughElementProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFlyoutBaseStatics3 const&), FlyoutBase, IFlyoutBaseStatics3>([](IFlyoutBaseStatics3 const& f) { return f.OverlayInputPassThroughElementProperty(); });
    }
    inline auto FlyoutBase::TargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFlyoutBaseStatics5 const&), FlyoutBase, IFlyoutBaseStatics5>([](IFlyoutBaseStatics5 const& f) { return f.TargetProperty(); });
    }
    inline auto FlyoutBase::ShowModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFlyoutBaseStatics5 const&), FlyoutBase, IFlyoutBaseStatics5>([](IFlyoutBaseStatics5 const& f) { return f.ShowModeProperty(); });
    }
    inline auto FlyoutBase::InputDevicePrefersPrimaryCommandsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFlyoutBaseStatics5 const&), FlyoutBase, IFlyoutBaseStatics5>([](IFlyoutBaseStatics5 const& f) { return f.InputDevicePrefersPrimaryCommandsProperty(); });
    }
    inline auto FlyoutBase::AreOpenCloseAnimationsEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFlyoutBaseStatics5 const&), FlyoutBase, IFlyoutBaseStatics5>([](IFlyoutBaseStatics5 const& f) { return f.AreOpenCloseAnimationsEnabledProperty(); });
    }
    inline auto FlyoutBase::IsOpenProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFlyoutBaseStatics5 const&), FlyoutBase, IFlyoutBaseStatics5>([](IFlyoutBaseStatics5 const& f) { return f.IsOpenProperty(); });
    }
    inline auto FlyoutBase::ShouldConstrainToRootBoundsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFlyoutBaseStatics6 const&), FlyoutBase, IFlyoutBaseStatics6>([](IFlyoutBaseStatics6 const& f) { return f.ShouldConstrainToRootBoundsProperty(); });
    }
    inline FlyoutShowOptions::FlyoutShowOptions()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<FlyoutShowOptions, IFlyoutShowOptionsFactory>([&](IFlyoutShowOptionsFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto GeneratorPositionHelper::FromIndexAndOffset(int32_t index, int32_t offset)
    {
        return impl::call_factory<GeneratorPositionHelper, IGeneratorPositionHelperStatics>([&](IGeneratorPositionHelperStatics const& f) { return f.FromIndexAndOffset(index, offset); });
    }
    inline GridViewItemPresenter::GridViewItemPresenter()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<GridViewItemPresenter, IGridViewItemPresenterFactory>([&](IGridViewItemPresenterFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto GridViewItemPresenter::SelectionCheckMarkVisualEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.SelectionCheckMarkVisualEnabledProperty(); });
    }
    inline auto GridViewItemPresenter::CheckHintBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.CheckHintBrushProperty(); });
    }
    inline auto GridViewItemPresenter::CheckSelectingBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.CheckSelectingBrushProperty(); });
    }
    inline auto GridViewItemPresenter::CheckBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.CheckBrushProperty(); });
    }
    inline auto GridViewItemPresenter::DragBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.DragBackgroundProperty(); });
    }
    inline auto GridViewItemPresenter::DragForegroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.DragForegroundProperty(); });
    }
    inline auto GridViewItemPresenter::FocusBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.FocusBorderBrushProperty(); });
    }
    inline auto GridViewItemPresenter::PlaceholderBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.PlaceholderBackgroundProperty(); });
    }
    inline auto GridViewItemPresenter::PointerOverBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.PointerOverBackgroundProperty(); });
    }
    inline auto GridViewItemPresenter::SelectedBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.SelectedBackgroundProperty(); });
    }
    inline auto GridViewItemPresenter::SelectedForegroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.SelectedForegroundProperty(); });
    }
    inline auto GridViewItemPresenter::SelectedPointerOverBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.SelectedPointerOverBackgroundProperty(); });
    }
    inline auto GridViewItemPresenter::SelectedPointerOverBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.SelectedPointerOverBorderBrushProperty(); });
    }
    inline auto GridViewItemPresenter::SelectedBorderThicknessProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.SelectedBorderThicknessProperty(); });
    }
    inline auto GridViewItemPresenter::DisabledOpacityProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.DisabledOpacityProperty(); });
    }
    inline auto GridViewItemPresenter::DragOpacityProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.DragOpacityProperty(); });
    }
    inline auto GridViewItemPresenter::ReorderHintOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.ReorderHintOffsetProperty(); });
    }
    inline auto GridViewItemPresenter::GridViewItemPresenterHorizontalContentAlignmentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.GridViewItemPresenterHorizontalContentAlignmentProperty(); });
    }
    inline auto GridViewItemPresenter::GridViewItemPresenterVerticalContentAlignmentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.GridViewItemPresenterVerticalContentAlignmentProperty(); });
    }
    inline auto GridViewItemPresenter::GridViewItemPresenterPaddingProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.GridViewItemPresenterPaddingProperty(); });
    }
    inline auto GridViewItemPresenter::PointerOverBackgroundMarginProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.PointerOverBackgroundMarginProperty(); });
    }
    inline auto GridViewItemPresenter::ContentMarginProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IGridViewItemPresenterStatics const&), GridViewItemPresenter, IGridViewItemPresenterStatics>([](IGridViewItemPresenterStatics const& f) { return f.ContentMarginProperty(); });
    }
    inline JumpListItemBackgroundConverter::JumpListItemBackgroundConverter() :
        JumpListItemBackgroundConverter(impl::call_factory_cast<JumpListItemBackgroundConverter(*)(winrt::Windows::Foundation::IActivationFactory const&), JumpListItemBackgroundConverter>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<JumpListItemBackgroundConverter>(); }))
    {
    }
    inline auto JumpListItemBackgroundConverter::EnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IJumpListItemBackgroundConverterStatics const&), JumpListItemBackgroundConverter, IJumpListItemBackgroundConverterStatics>([](IJumpListItemBackgroundConverterStatics const& f) { return f.EnabledProperty(); });
    }
    inline auto JumpListItemBackgroundConverter::DisabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IJumpListItemBackgroundConverterStatics const&), JumpListItemBackgroundConverter, IJumpListItemBackgroundConverterStatics>([](IJumpListItemBackgroundConverterStatics const& f) { return f.DisabledProperty(); });
    }
    inline JumpListItemForegroundConverter::JumpListItemForegroundConverter() :
        JumpListItemForegroundConverter(impl::call_factory_cast<JumpListItemForegroundConverter(*)(winrt::Windows::Foundation::IActivationFactory const&), JumpListItemForegroundConverter>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<JumpListItemForegroundConverter>(); }))
    {
    }
    inline auto JumpListItemForegroundConverter::EnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IJumpListItemForegroundConverterStatics const&), JumpListItemForegroundConverter, IJumpListItemForegroundConverterStatics>([](IJumpListItemForegroundConverterStatics const& f) { return f.EnabledProperty(); });
    }
    inline auto JumpListItemForegroundConverter::DisabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IJumpListItemForegroundConverterStatics const&), JumpListItemForegroundConverter, IJumpListItemForegroundConverterStatics>([](IJumpListItemForegroundConverterStatics const& f) { return f.DisabledProperty(); });
    }
    inline auto LayoutInformation::GetLayoutExceptionElement(winrt::Windows::Foundation::IInspectable const& dispatcher)
    {
        return impl::call_factory<LayoutInformation, ILayoutInformationStatics>([&](ILayoutInformationStatics const& f) { return f.GetLayoutExceptionElement(dispatcher); });
    }
    inline auto LayoutInformation::GetLayoutSlot(winrt::Windows::UI::Xaml::FrameworkElement const& element)
    {
        return impl::call_factory<LayoutInformation, ILayoutInformationStatics>([&](ILayoutInformationStatics const& f) { return f.GetLayoutSlot(element); });
    }
    inline auto LayoutInformation::GetAvailableSize(winrt::Windows::UI::Xaml::UIElement const& element)
    {
        return impl::call_factory<LayoutInformation, ILayoutInformationStatics2>([&](ILayoutInformationStatics2 const& f) { return f.GetAvailableSize(element); });
    }
    inline ListViewItemPresenter::ListViewItemPresenter()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ListViewItemPresenter, IListViewItemPresenterFactory>([&](IListViewItemPresenterFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto ListViewItemPresenter::SelectionCheckMarkVisualEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.SelectionCheckMarkVisualEnabledProperty(); });
    }
    inline auto ListViewItemPresenter::CheckHintBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.CheckHintBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckSelectingBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.CheckSelectingBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.CheckBrushProperty(); });
    }
    inline auto ListViewItemPresenter::DragBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.DragBackgroundProperty(); });
    }
    inline auto ListViewItemPresenter::DragForegroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.DragForegroundProperty(); });
    }
    inline auto ListViewItemPresenter::FocusBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.FocusBorderBrushProperty(); });
    }
    inline auto ListViewItemPresenter::PlaceholderBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.PlaceholderBackgroundProperty(); });
    }
    inline auto ListViewItemPresenter::PointerOverBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.PointerOverBackgroundProperty(); });
    }
    inline auto ListViewItemPresenter::SelectedBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.SelectedBackgroundProperty(); });
    }
    inline auto ListViewItemPresenter::SelectedForegroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.SelectedForegroundProperty(); });
    }
    inline auto ListViewItemPresenter::SelectedPointerOverBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.SelectedPointerOverBackgroundProperty(); });
    }
    inline auto ListViewItemPresenter::SelectedPointerOverBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.SelectedPointerOverBorderBrushProperty(); });
    }
    inline auto ListViewItemPresenter::SelectedBorderThicknessProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.SelectedBorderThicknessProperty(); });
    }
    inline auto ListViewItemPresenter::DisabledOpacityProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.DisabledOpacityProperty(); });
    }
    inline auto ListViewItemPresenter::DragOpacityProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.DragOpacityProperty(); });
    }
    inline auto ListViewItemPresenter::ReorderHintOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.ReorderHintOffsetProperty(); });
    }
    inline auto ListViewItemPresenter::ListViewItemPresenterHorizontalContentAlignmentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.ListViewItemPresenterHorizontalContentAlignmentProperty(); });
    }
    inline auto ListViewItemPresenter::ListViewItemPresenterVerticalContentAlignmentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.ListViewItemPresenterVerticalContentAlignmentProperty(); });
    }
    inline auto ListViewItemPresenter::ListViewItemPresenterPaddingProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.ListViewItemPresenterPaddingProperty(); });
    }
    inline auto ListViewItemPresenter::PointerOverBackgroundMarginProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.PointerOverBackgroundMarginProperty(); });
    }
    inline auto ListViewItemPresenter::ContentMarginProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics const&), ListViewItemPresenter, IListViewItemPresenterStatics>([](IListViewItemPresenterStatics const& f) { return f.ContentMarginProperty(); });
    }
    inline auto ListViewItemPresenter::SelectedPressedBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics2 const&), ListViewItemPresenter, IListViewItemPresenterStatics2>([](IListViewItemPresenterStatics2 const& f) { return f.SelectedPressedBackgroundProperty(); });
    }
    inline auto ListViewItemPresenter::PressedBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics2 const&), ListViewItemPresenter, IListViewItemPresenterStatics2>([](IListViewItemPresenterStatics2 const& f) { return f.PressedBackgroundProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBoxBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics2 const&), ListViewItemPresenter, IListViewItemPresenterStatics2>([](IListViewItemPresenterStatics2 const& f) { return f.CheckBoxBrushProperty(); });
    }
    inline auto ListViewItemPresenter::FocusSecondaryBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics2 const&), ListViewItemPresenter, IListViewItemPresenterStatics2>([](IListViewItemPresenterStatics2 const& f) { return f.FocusSecondaryBorderBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics2 const&), ListViewItemPresenter, IListViewItemPresenterStatics2>([](IListViewItemPresenterStatics2 const& f) { return f.CheckModeProperty(); });
    }
    inline auto ListViewItemPresenter::PointerOverForegroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics2 const&), ListViewItemPresenter, IListViewItemPresenterStatics2>([](IListViewItemPresenterStatics2 const& f) { return f.PointerOverForegroundProperty(); });
    }
    inline auto ListViewItemPresenter::RevealBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics3 const&), ListViewItemPresenter, IListViewItemPresenterStatics3>([](IListViewItemPresenterStatics3 const& f) { return f.RevealBackgroundProperty(); });
    }
    inline auto ListViewItemPresenter::RevealBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics3 const&), ListViewItemPresenter, IListViewItemPresenterStatics3>([](IListViewItemPresenterStatics3 const& f) { return f.RevealBorderBrushProperty(); });
    }
    inline auto ListViewItemPresenter::RevealBorderThicknessProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics3 const&), ListViewItemPresenter, IListViewItemPresenterStatics3>([](IListViewItemPresenterStatics3 const& f) { return f.RevealBorderThicknessProperty(); });
    }
    inline auto ListViewItemPresenter::RevealBackgroundShowsAboveContentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics3 const&), ListViewItemPresenter, IListViewItemPresenterStatics3>([](IListViewItemPresenterStatics3 const& f) { return f.RevealBackgroundShowsAboveContentProperty(); });
    }
    inline auto ListViewItemPresenter::SelectedDisabledBackgroundProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.SelectedDisabledBackgroundProperty(); });
    }
    inline auto ListViewItemPresenter::CheckPressedBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckPressedBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckDisabledBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckDisabledBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBoxPointerOverBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckBoxPointerOverBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBoxPressedBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckBoxPressedBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBoxDisabledBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckBoxDisabledBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBoxSelectedBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckBoxSelectedBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBoxSelectedPointerOverBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckBoxSelectedPointerOverBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBoxSelectedPressedBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckBoxSelectedPressedBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBoxSelectedDisabledBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckBoxSelectedDisabledBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBoxBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckBoxBorderBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBoxPointerOverBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckBoxPointerOverBorderBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBoxPressedBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckBoxPressedBorderBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBoxDisabledBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckBoxDisabledBorderBrushProperty(); });
    }
    inline auto ListViewItemPresenter::CheckBoxCornerRadiusProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.CheckBoxCornerRadiusProperty(); });
    }
    inline auto ListViewItemPresenter::SelectionIndicatorCornerRadiusProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.SelectionIndicatorCornerRadiusProperty(); });
    }
    inline auto ListViewItemPresenter::SelectionIndicatorVisualEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.SelectionIndicatorVisualEnabledProperty(); });
    }
    inline auto ListViewItemPresenter::SelectionIndicatorModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.SelectionIndicatorModeProperty(); });
    }
    inline auto ListViewItemPresenter::SelectionIndicatorBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.SelectionIndicatorBrushProperty(); });
    }
    inline auto ListViewItemPresenter::SelectionIndicatorPointerOverBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.SelectionIndicatorPointerOverBrushProperty(); });
    }
    inline auto ListViewItemPresenter::SelectionIndicatorPressedBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.SelectionIndicatorPressedBrushProperty(); });
    }
    inline auto ListViewItemPresenter::SelectionIndicatorDisabledBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.SelectionIndicatorDisabledBrushProperty(); });
    }
    inline auto ListViewItemPresenter::SelectedBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.SelectedBorderBrushProperty(); });
    }
    inline auto ListViewItemPresenter::SelectedPressedBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.SelectedPressedBorderBrushProperty(); });
    }
    inline auto ListViewItemPresenter::SelectedDisabledBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.SelectedDisabledBorderBrushProperty(); });
    }
    inline auto ListViewItemPresenter::SelectedInnerBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.SelectedInnerBorderBrushProperty(); });
    }
    inline auto ListViewItemPresenter::PointerOverBorderBrushProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IListViewItemPresenterStatics4 const&), ListViewItemPresenter, IListViewItemPresenterStatics4>([](IListViewItemPresenterStatics4 const& f) { return f.PointerOverBorderBrushProperty(); });
    }
    inline auto LoopingSelector::ShouldLoopProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ILoopingSelectorStatics const&), LoopingSelector, ILoopingSelectorStatics>([](ILoopingSelectorStatics const& f) { return f.ShouldLoopProperty(); });
    }
    inline auto LoopingSelector::ItemsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ILoopingSelectorStatics const&), LoopingSelector, ILoopingSelectorStatics>([](ILoopingSelectorStatics const& f) { return f.ItemsProperty(); });
    }
    inline auto LoopingSelector::SelectedIndexProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ILoopingSelectorStatics const&), LoopingSelector, ILoopingSelectorStatics>([](ILoopingSelectorStatics const& f) { return f.SelectedIndexProperty(); });
    }
    inline auto LoopingSelector::SelectedItemProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ILoopingSelectorStatics const&), LoopingSelector, ILoopingSelectorStatics>([](ILoopingSelectorStatics const& f) { return f.SelectedItemProperty(); });
    }
    inline auto LoopingSelector::ItemWidthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ILoopingSelectorStatics const&), LoopingSelector, ILoopingSelectorStatics>([](ILoopingSelectorStatics const& f) { return f.ItemWidthProperty(); });
    }
    inline auto LoopingSelector::ItemHeightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ILoopingSelectorStatics const&), LoopingSelector, ILoopingSelectorStatics>([](ILoopingSelectorStatics const& f) { return f.ItemHeightProperty(); });
    }
    inline auto LoopingSelector::ItemTemplateProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ILoopingSelectorStatics const&), LoopingSelector, ILoopingSelectorStatics>([](ILoopingSelectorStatics const& f) { return f.ItemTemplateProperty(); });
    }
    inline NavigationViewItemPresenter::NavigationViewItemPresenter()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<NavigationViewItemPresenter, INavigationViewItemPresenterFactory>([&](INavigationViewItemPresenterFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto NavigationViewItemPresenter::IconProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(INavigationViewItemPresenterStatics const&), NavigationViewItemPresenter, INavigationViewItemPresenterStatics>([](INavigationViewItemPresenterStatics const& f) { return f.IconProperty(); });
    }
    inline auto PickerFlyoutBase::TitleProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPickerFlyoutBaseStatics const&), PickerFlyoutBase, IPickerFlyoutBaseStatics>([](IPickerFlyoutBaseStatics const& f) { return f.TitleProperty(); });
    }
    inline auto PickerFlyoutBase::GetTitle(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<PickerFlyoutBase, IPickerFlyoutBaseStatics>([&](IPickerFlyoutBaseStatics const& f) { return f.GetTitle(element); });
    }
    inline auto PickerFlyoutBase::SetTitle(winrt::Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value)
    {
        impl::call_factory<PickerFlyoutBase, IPickerFlyoutBaseStatics>([&](IPickerFlyoutBaseStatics const& f) { return f.SetTitle(element, value); });
    }
    inline PivotHeaderItem::PivotHeaderItem()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<PivotHeaderItem, IPivotHeaderItemFactory>([&](IPivotHeaderItemFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline PivotHeaderPanel::PivotHeaderPanel() :
        PivotHeaderPanel(impl::call_factory_cast<PivotHeaderPanel(*)(winrt::Windows::Foundation::IActivationFactory const&), PivotHeaderPanel>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PivotHeaderPanel>(); }))
    {
    }
    inline PivotPanel::PivotPanel() :
        PivotPanel(impl::call_factory_cast<PivotPanel(*)(winrt::Windows::Foundation::IActivationFactory const&), PivotPanel>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PivotPanel>(); }))
    {
    }
    inline Popup::Popup() :
        Popup(impl::call_factory_cast<Popup(*)(winrt::Windows::Foundation::IActivationFactory const&), Popup>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Popup>(); }))
    {
    }
    inline auto Popup::ChildProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopupStatics const&), Popup, IPopupStatics>([](IPopupStatics const& f) { return f.ChildProperty(); });
    }
    inline auto Popup::IsOpenProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopupStatics const&), Popup, IPopupStatics>([](IPopupStatics const& f) { return f.IsOpenProperty(); });
    }
    inline auto Popup::HorizontalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopupStatics const&), Popup, IPopupStatics>([](IPopupStatics const& f) { return f.HorizontalOffsetProperty(); });
    }
    inline auto Popup::VerticalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopupStatics const&), Popup, IPopupStatics>([](IPopupStatics const& f) { return f.VerticalOffsetProperty(); });
    }
    inline auto Popup::ChildTransitionsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopupStatics const&), Popup, IPopupStatics>([](IPopupStatics const& f) { return f.ChildTransitionsProperty(); });
    }
    inline auto Popup::IsLightDismissEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopupStatics const&), Popup, IPopupStatics>([](IPopupStatics const& f) { return f.IsLightDismissEnabledProperty(); });
    }
    inline auto Popup::LightDismissOverlayModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopupStatics2 const&), Popup, IPopupStatics2>([](IPopupStatics2 const& f) { return f.LightDismissOverlayModeProperty(); });
    }
    inline auto Popup::ShouldConstrainToRootBoundsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopupStatics3 const&), Popup, IPopupStatics3>([](IPopupStatics3 const& f) { return f.ShouldConstrainToRootBoundsProperty(); });
    }
    inline auto Popup::PlacementTargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopupStatics4 const&), Popup, IPopupStatics4>([](IPopupStatics4 const& f) { return f.PlacementTargetProperty(); });
    }
    inline auto Popup::DesiredPlacementProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopupStatics4 const&), Popup, IPopupStatics4>([](IPopupStatics4 const& f) { return f.DesiredPlacementProperty(); });
    }
    inline auto RangeBase::MinimumProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRangeBaseStatics const&), RangeBase, IRangeBaseStatics>([](IRangeBaseStatics const& f) { return f.MinimumProperty(); });
    }
    inline auto RangeBase::MaximumProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRangeBaseStatics const&), RangeBase, IRangeBaseStatics>([](IRangeBaseStatics const& f) { return f.MaximumProperty(); });
    }
    inline auto RangeBase::SmallChangeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRangeBaseStatics const&), RangeBase, IRangeBaseStatics>([](IRangeBaseStatics const& f) { return f.SmallChangeProperty(); });
    }
    inline auto RangeBase::LargeChangeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRangeBaseStatics const&), RangeBase, IRangeBaseStatics>([](IRangeBaseStatics const& f) { return f.LargeChangeProperty(); });
    }
    inline auto RangeBase::ValueProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRangeBaseStatics const&), RangeBase, IRangeBaseStatics>([](IRangeBaseStatics const& f) { return f.ValueProperty(); });
    }
    inline RepeatButton::RepeatButton() :
        RepeatButton(impl::call_factory_cast<RepeatButton(*)(winrt::Windows::Foundation::IActivationFactory const&), RepeatButton>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<RepeatButton>(); }))
    {
    }
    inline auto RepeatButton::DelayProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRepeatButtonStatics const&), RepeatButton, IRepeatButtonStatics>([](IRepeatButtonStatics const& f) { return f.DelayProperty(); });
    }
    inline auto RepeatButton::IntervalProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRepeatButtonStatics const&), RepeatButton, IRepeatButtonStatics>([](IRepeatButtonStatics const& f) { return f.IntervalProperty(); });
    }
    inline ScrollBar::ScrollBar() :
        ScrollBar(impl::call_factory_cast<ScrollBar(*)(winrt::Windows::Foundation::IActivationFactory const&), ScrollBar>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ScrollBar>(); }))
    {
    }
    inline auto ScrollBar::OrientationProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IScrollBarStatics const&), ScrollBar, IScrollBarStatics>([](IScrollBarStatics const& f) { return f.OrientationProperty(); });
    }
    inline auto ScrollBar::ViewportSizeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IScrollBarStatics const&), ScrollBar, IScrollBarStatics>([](IScrollBarStatics const& f) { return f.ViewportSizeProperty(); });
    }
    inline auto ScrollBar::IndicatorModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IScrollBarStatics const&), ScrollBar, IScrollBarStatics>([](IScrollBarStatics const& f) { return f.IndicatorModeProperty(); });
    }
    inline ScrollEventArgs::ScrollEventArgs() :
        ScrollEventArgs(impl::call_factory_cast<ScrollEventArgs(*)(winrt::Windows::Foundation::IActivationFactory const&), ScrollEventArgs>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ScrollEventArgs>(); }))
    {
    }
    inline auto Selector::SelectedIndexProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISelectorStatics const&), Selector, ISelectorStatics>([](ISelectorStatics const& f) { return f.SelectedIndexProperty(); });
    }
    inline auto Selector::SelectedItemProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISelectorStatics const&), Selector, ISelectorStatics>([](ISelectorStatics const& f) { return f.SelectedItemProperty(); });
    }
    inline auto Selector::SelectedValueProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISelectorStatics const&), Selector, ISelectorStatics>([](ISelectorStatics const& f) { return f.SelectedValueProperty(); });
    }
    inline auto Selector::SelectedValuePathProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISelectorStatics const&), Selector, ISelectorStatics>([](ISelectorStatics const& f) { return f.SelectedValuePathProperty(); });
    }
    inline auto Selector::IsSynchronizedWithCurrentItemProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISelectorStatics const&), Selector, ISelectorStatics>([](ISelectorStatics const& f) { return f.IsSynchronizedWithCurrentItemProperty(); });
    }
    inline auto Selector::GetIsSelectionActive(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<Selector, ISelectorStatics>([&](ISelectorStatics const& f) { return f.GetIsSelectionActive(element); });
    }
    inline auto SelectorItem::IsSelectedProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISelectorItemStatics const&), SelectorItem, ISelectorItemStatics>([](ISelectorItemStatics const& f) { return f.IsSelectedProperty(); });
    }
    inline Thumb::Thumb() :
        Thumb(impl::call_factory_cast<Thumb(*)(winrt::Windows::Foundation::IActivationFactory const&), Thumb>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Thumb>(); }))
    {
    }
    inline auto Thumb::IsDraggingProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IThumbStatics const&), Thumb, IThumbStatics>([](IThumbStatics const& f) { return f.IsDraggingProperty(); });
    }
    inline TickBar::TickBar() :
        TickBar(impl::call_factory_cast<TickBar(*)(winrt::Windows::Foundation::IActivationFactory const&), TickBar>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<TickBar>(); }))
    {
    }
    inline auto TickBar::FillProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITickBarStatics const&), TickBar, ITickBarStatics>([](ITickBarStatics const& f) { return f.FillProperty(); });
    }
    inline ToggleButton::ToggleButton()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ToggleButton, IToggleButtonFactory>([&](IToggleButtonFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto ToggleButton::IsCheckedProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IToggleButtonStatics const&), ToggleButton, IToggleButtonStatics>([](IToggleButtonStatics const& f) { return f.IsCheckedProperty(); });
    }
    inline auto ToggleButton::IsThreeStateProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IToggleButtonStatics const&), ToggleButton, IToggleButtonStatics>([](IToggleButtonStatics const& f) { return f.IsThreeStateProperty(); });
    }
    template <typename L> DragCompletedEventHandler::DragCompletedEventHandler(L handler) :
        DragCompletedEventHandler(impl::make_delegate<DragCompletedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> DragCompletedEventHandler::DragCompletedEventHandler(F* handler) :
        DragCompletedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DragCompletedEventHandler::DragCompletedEventHandler(O* object, M method) :
        DragCompletedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DragCompletedEventHandler::DragCompletedEventHandler(com_ptr<O>&& object, M method) :
        DragCompletedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DragCompletedEventHandler::DragCompletedEventHandler(weak_ref<O>&& object, M method) :
        DragCompletedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DragCompletedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<DragCompletedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> DragDeltaEventHandler::DragDeltaEventHandler(L handler) :
        DragDeltaEventHandler(impl::make_delegate<DragDeltaEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> DragDeltaEventHandler::DragDeltaEventHandler(F* handler) :
        DragDeltaEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DragDeltaEventHandler::DragDeltaEventHandler(O* object, M method) :
        DragDeltaEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DragDeltaEventHandler::DragDeltaEventHandler(com_ptr<O>&& object, M method) :
        DragDeltaEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DragDeltaEventHandler::DragDeltaEventHandler(weak_ref<O>&& object, M method) :
        DragDeltaEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DragDeltaEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<DragDeltaEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> DragStartedEventHandler::DragStartedEventHandler(L handler) :
        DragStartedEventHandler(impl::make_delegate<DragStartedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> DragStartedEventHandler::DragStartedEventHandler(F* handler) :
        DragStartedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DragStartedEventHandler::DragStartedEventHandler(O* object, M method) :
        DragStartedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DragStartedEventHandler::DragStartedEventHandler(com_ptr<O>&& object, M method) :
        DragStartedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DragStartedEventHandler::DragStartedEventHandler(weak_ref<O>&& object, M method) :
        DragStartedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DragStartedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<DragStartedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> ItemsChangedEventHandler::ItemsChangedEventHandler(L handler) :
        ItemsChangedEventHandler(impl::make_delegate<ItemsChangedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> ItemsChangedEventHandler::ItemsChangedEventHandler(F* handler) :
        ItemsChangedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> ItemsChangedEventHandler::ItemsChangedEventHandler(O* object, M method) :
        ItemsChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> ItemsChangedEventHandler::ItemsChangedEventHandler(com_ptr<O>&& object, M method) :
        ItemsChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> ItemsChangedEventHandler::ItemsChangedEventHandler(weak_ref<O>&& object, M method) :
        ItemsChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto ItemsChangedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::Primitives::ItemsChangedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<ItemsChangedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> RangeBaseValueChangedEventHandler::RangeBaseValueChangedEventHandler(L handler) :
        RangeBaseValueChangedEventHandler(impl::make_delegate<RangeBaseValueChangedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> RangeBaseValueChangedEventHandler::RangeBaseValueChangedEventHandler(F* handler) :
        RangeBaseValueChangedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> RangeBaseValueChangedEventHandler::RangeBaseValueChangedEventHandler(O* object, M method) :
        RangeBaseValueChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> RangeBaseValueChangedEventHandler::RangeBaseValueChangedEventHandler(com_ptr<O>&& object, M method) :
        RangeBaseValueChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> RangeBaseValueChangedEventHandler::RangeBaseValueChangedEventHandler(weak_ref<O>&& object, M method) :
        RangeBaseValueChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto RangeBaseValueChangedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<RangeBaseValueChangedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> ScrollEventHandler::ScrollEventHandler(L handler) :
        ScrollEventHandler(impl::make_delegate<ScrollEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> ScrollEventHandler::ScrollEventHandler(F* handler) :
        ScrollEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> ScrollEventHandler::ScrollEventHandler(O* object, M method) :
        ScrollEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> ScrollEventHandler::ScrollEventHandler(com_ptr<O>&& object, M method) :
        ScrollEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> ScrollEventHandler::ScrollEventHandler(weak_ref<O>&& object, M method) :
        ScrollEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto ScrollEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<ScrollEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Control) IFlyoutBaseOverridesT<D>::CreatePresenter() const
    {
        return shim().template try_as<IFlyoutBaseOverrides>().CreatePresenter();
    }
    template <typename D> WINRT_IMPL_AUTO(void) IFlyoutBaseOverrides4T<D>::OnProcessKeyboardAccelerators(winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args) const
    {
        return shim().template try_as<IFlyoutBaseOverrides4>().OnProcessKeyboardAccelerators(args);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IPickerFlyoutBaseOverridesT<D>::OnConfirmed() const
    {
        return shim().template try_as<IPickerFlyoutBaseOverrides>().OnConfirmed();
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IPickerFlyoutBaseOverridesT<D>::ShouldShowConfirmationButtons() const
    {
        return shim().template try_as<IPickerFlyoutBaseOverrides>().ShouldShowConfirmationButtons();
    }
    template <typename D> WINRT_IMPL_AUTO(void) IRangeBaseOverridesT<D>::OnMinimumChanged(double oldMinimum, double newMinimum) const
    {
        return shim().template try_as<IRangeBaseOverrides>().OnMinimumChanged(oldMinimum, newMinimum);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IRangeBaseOverridesT<D>::OnMaximumChanged(double oldMaximum, double newMaximum) const
    {
        return shim().template try_as<IRangeBaseOverrides>().OnMaximumChanged(oldMaximum, newMaximum);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IRangeBaseOverridesT<D>::OnValueChanged(double oldValue, double newValue) const
    {
        return shim().template try_as<IRangeBaseOverrides>().OnValueChanged(oldValue, newValue);
    }
    template <typename D> WINRT_IMPL_AUTO(void) IToggleButtonOverridesT<D>::OnToggle() const
    {
        return shim().template try_as<IToggleButtonOverrides>().OnToggle();
    }
    template <typename D, typename... Interfaces>
    struct ButtonBaseT :
        implements<D, winrt::Windows::UI::Xaml::Controls::IContentControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides6, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase, winrt::Windows::UI::Xaml::Controls::IContentControl, winrt::Windows::UI::Xaml::Controls::IContentControl2, winrt::Windows::UI::Xaml::Controls::IControl, winrt::Windows::UI::Xaml::Controls::IControl2, winrt::Windows::UI::Xaml::Controls::IControl3, winrt::Windows::UI::Xaml::Controls::IControl4, winrt::Windows::UI::Xaml::Controls::IControl5, winrt::Windows::UI::Xaml::Controls::IControl7, winrt::Windows::UI::Xaml::Controls::IControlProtected, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ButtonBase, winrt::Windows::UI::Xaml::Controls::ContentControl, winrt::Windows::UI::Xaml::Controls::Control, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::IContentControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverrides6T<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = ButtonBase;
    protected:
        ButtonBaseT()
        {
            impl::call_factory<ButtonBase, IButtonBaseFactory>([&](IButtonBaseFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct CarouselPanelT :
        implements<D, winrt::Windows::UI::Xaml::Controls::IVirtualizingPanelOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel, winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo, winrt::Windows::UI::Xaml::Controls::IVirtualizingPanel, winrt::Windows::UI::Xaml::Controls::IVirtualizingPanelProtected, winrt::Windows::UI::Xaml::Controls::IPanel, winrt::Windows::UI::Xaml::Controls::IPanel2, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, CarouselPanel, winrt::Windows::UI::Xaml::Controls::VirtualizingPanel, winrt::Windows::UI::Xaml::Controls::Panel, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::IVirtualizingPanelOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = CarouselPanel;
    protected:
        CarouselPanelT()
        {
            impl::call_factory<CarouselPanel, ICarouselPanelFactory>([&](ICarouselPanelFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ColorPickerSliderT :
        implements<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides6, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSlider, winrt::Windows::UI::Xaml::Controls::ISlider, winrt::Windows::UI::Xaml::Controls::ISlider2, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase, winrt::Windows::UI::Xaml::Controls::IControl, winrt::Windows::UI::Xaml::Controls::IControl2, winrt::Windows::UI::Xaml::Controls::IControl3, winrt::Windows::UI::Xaml::Controls::IControl4, winrt::Windows::UI::Xaml::Controls::IControl5, winrt::Windows::UI::Xaml::Controls::IControl7, winrt::Windows::UI::Xaml::Controls::IControlProtected, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ColorPickerSlider, winrt::Windows::UI::Xaml::Controls::Slider, winrt::Windows::UI::Xaml::Controls::Primitives::RangeBase, winrt::Windows::UI::Xaml::Controls::Control, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverrides6T<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = ColorPickerSlider;
    protected:
        ColorPickerSliderT()
        {
            impl::call_factory<ColorPickerSlider, IColorPickerSliderFactory>([&](IColorPickerSliderFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ColorSpectrumT :
        implements<D, winrt::Windows::UI::Xaml::Controls::IControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides6, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum, winrt::Windows::UI::Xaml::Controls::IControl, winrt::Windows::UI::Xaml::Controls::IControl2, winrt::Windows::UI::Xaml::Controls::IControl3, winrt::Windows::UI::Xaml::Controls::IControl4, winrt::Windows::UI::Xaml::Controls::IControl5, winrt::Windows::UI::Xaml::Controls::IControl7, winrt::Windows::UI::Xaml::Controls::IControlProtected, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ColorSpectrum, winrt::Windows::UI::Xaml::Controls::Control, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::IControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverrides6T<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = ColorSpectrum;
    protected:
        ColorSpectrumT()
        {
            impl::call_factory<ColorSpectrum, IColorSpectrumFactory>([&](IColorSpectrumFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct CommandBarFlyoutCommandBarT :
        implements<D, winrt::Windows::UI::Xaml::Controls::IAppBarOverrides, winrt::Windows::UI::Xaml::Controls::IAppBarOverrides3, winrt::Windows::UI::Xaml::Controls::IContentControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides6, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBar, winrt::Windows::UI::Xaml::Controls::ICommandBar, winrt::Windows::UI::Xaml::Controls::ICommandBar2, winrt::Windows::UI::Xaml::Controls::ICommandBar3, winrt::Windows::UI::Xaml::Controls::IAppBar, winrt::Windows::UI::Xaml::Controls::IAppBar2, winrt::Windows::UI::Xaml::Controls::IAppBar3, winrt::Windows::UI::Xaml::Controls::IAppBar4, winrt::Windows::UI::Xaml::Controls::IContentControl, winrt::Windows::UI::Xaml::Controls::IContentControl2, winrt::Windows::UI::Xaml::Controls::IControl, winrt::Windows::UI::Xaml::Controls::IControl2, winrt::Windows::UI::Xaml::Controls::IControl3, winrt::Windows::UI::Xaml::Controls::IControl4, winrt::Windows::UI::Xaml::Controls::IControl5, winrt::Windows::UI::Xaml::Controls::IControl7, winrt::Windows::UI::Xaml::Controls::IControlProtected, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, CommandBarFlyoutCommandBar, winrt::Windows::UI::Xaml::Controls::CommandBar, winrt::Windows::UI::Xaml::Controls::AppBar, winrt::Windows::UI::Xaml::Controls::ContentControl, winrt::Windows::UI::Xaml::Controls::Control, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::IAppBarOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IAppBarOverrides3T<D>, winrt::Windows::UI::Xaml::Controls::IContentControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverrides6T<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = CommandBarFlyoutCommandBar;
    protected:
        CommandBarFlyoutCommandBarT()
        {
            impl::call_factory<CommandBarFlyoutCommandBar, ICommandBarFlyoutCommandBarFactory>([&](ICommandBarFlyoutCommandBarFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct DragCompletedEventArgsT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs, winrt::Windows::UI::Xaml::IRoutedEventArgs>,
        impl::base<D, DragCompletedEventArgs, winrt::Windows::UI::Xaml::RoutedEventArgs>
    {
        using composable = DragCompletedEventArgs;
    protected:
        DragCompletedEventArgsT(double horizontalChange, double verticalChange, bool canceled)
        {
            impl::call_factory<DragCompletedEventArgs, IDragCompletedEventArgsFactory>([&](IDragCompletedEventArgsFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithHorizontalChangeVerticalChangeAndCanceled(horizontalChange, verticalChange, canceled, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct DragDeltaEventArgsT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgs, winrt::Windows::UI::Xaml::IRoutedEventArgs>,
        impl::base<D, DragDeltaEventArgs, winrt::Windows::UI::Xaml::RoutedEventArgs>
    {
        using composable = DragDeltaEventArgs;
    protected:
        DragDeltaEventArgsT(double horizontalChange, double verticalChange)
        {
            impl::call_factory<DragDeltaEventArgs, IDragDeltaEventArgsFactory>([&](IDragDeltaEventArgsFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithHorizontalChangeAndVerticalChange(horizontalChange, verticalChange, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct DragStartedEventArgsT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgs, winrt::Windows::UI::Xaml::IRoutedEventArgs>,
        impl::base<D, DragStartedEventArgs, winrt::Windows::UI::Xaml::RoutedEventArgs>
    {
        using composable = DragStartedEventArgs;
    protected:
        DragStartedEventArgsT(double horizontalOffset, double verticalOffset)
        {
            impl::call_factory<DragStartedEventArgs, IDragStartedEventArgsFactory>([&](IDragStartedEventArgsFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithHorizontalOffsetAndVerticalOffset(horizontalOffset, verticalOffset, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct FlyoutBaseT :
        implements<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase4, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, FlyoutBase, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverridesT<D>, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4T<D>
    {
        using composable = FlyoutBase;
    protected:
        FlyoutBaseT()
        {
            impl::call_factory<FlyoutBase, IFlyoutBaseFactory>([&](IFlyoutBaseFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
        using impl::consume_t<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase>::ShowAt;
        using impl::consume_t<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5>::ShowAt;
    };
    template <typename D, typename... Interfaces>
    struct FlyoutShowOptionsT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions>,
        impl::base<D, FlyoutShowOptions>
    {
        using composable = FlyoutShowOptions;
    protected:
        FlyoutShowOptionsT()
        {
            impl::call_factory<FlyoutShowOptions, IFlyoutShowOptionsFactory>([&](IFlyoutShowOptionsFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct GridViewItemPresenterT :
        implements<D, winrt::Windows::UI::Xaml::Controls::IContentPresenterOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter, winrt::Windows::UI::Xaml::Controls::IContentPresenter, winrt::Windows::UI::Xaml::Controls::IContentPresenter2, winrt::Windows::UI::Xaml::Controls::IContentPresenter3, winrt::Windows::UI::Xaml::Controls::IContentPresenter4, winrt::Windows::UI::Xaml::Controls::IContentPresenter5, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, GridViewItemPresenter, winrt::Windows::UI::Xaml::Controls::ContentPresenter, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::IContentPresenterOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = GridViewItemPresenter;
    protected:
        GridViewItemPresenterT()
        {
            impl::call_factory<GridViewItemPresenter, IGridViewItemPresenterFactory>([&](IGridViewItemPresenterFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ListViewItemPresenterT :
        implements<D, winrt::Windows::UI::Xaml::Controls::IContentPresenterOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3, winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4, winrt::Windows::UI::Xaml::Controls::IContentPresenter, winrt::Windows::UI::Xaml::Controls::IContentPresenter2, winrt::Windows::UI::Xaml::Controls::IContentPresenter3, winrt::Windows::UI::Xaml::Controls::IContentPresenter4, winrt::Windows::UI::Xaml::Controls::IContentPresenter5, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ListViewItemPresenter, winrt::Windows::UI::Xaml::Controls::ContentPresenter, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::IContentPresenterOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = ListViewItemPresenter;
    protected:
        ListViewItemPresenterT()
        {
            impl::call_factory<ListViewItemPresenter, IListViewItemPresenterFactory>([&](IListViewItemPresenterFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct NavigationViewItemPresenterT :
        implements<D, winrt::Windows::UI::Xaml::Controls::IContentControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides6, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenter, winrt::Windows::UI::Xaml::Controls::IContentControl, winrt::Windows::UI::Xaml::Controls::IContentControl2, winrt::Windows::UI::Xaml::Controls::IControl, winrt::Windows::UI::Xaml::Controls::IControl2, winrt::Windows::UI::Xaml::Controls::IControl3, winrt::Windows::UI::Xaml::Controls::IControl4, winrt::Windows::UI::Xaml::Controls::IControl5, winrt::Windows::UI::Xaml::Controls::IControl7, winrt::Windows::UI::Xaml::Controls::IControlProtected, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, NavigationViewItemPresenter, winrt::Windows::UI::Xaml::Controls::ContentControl, winrt::Windows::UI::Xaml::Controls::Control, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::IContentControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverrides6T<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = NavigationViewItemPresenter;
    protected:
        NavigationViewItemPresenterT()
        {
            impl::call_factory<NavigationViewItemPresenter, INavigationViewItemPresenterFactory>([&](INavigationViewItemPresenterFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct PickerFlyoutBaseT :
        implements<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBase, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase4, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, PickerFlyoutBase, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverridesT<D>, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverridesT<D>, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4T<D>
    {
        using composable = PickerFlyoutBase;
    protected:
        PickerFlyoutBaseT()
        {
            impl::call_factory<PickerFlyoutBase, IPickerFlyoutBaseFactory>([&](IPickerFlyoutBaseFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
        using impl::consume_t<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase>::ShowAt;
        using impl::consume_t<D, winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5>::ShowAt;
    };
    template <typename D, typename... Interfaces>
    struct PivotHeaderItemT :
        implements<D, winrt::Windows::UI::Xaml::Controls::IContentControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides6, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItem, winrt::Windows::UI::Xaml::Controls::IContentControl, winrt::Windows::UI::Xaml::Controls::IContentControl2, winrt::Windows::UI::Xaml::Controls::IControl, winrt::Windows::UI::Xaml::Controls::IControl2, winrt::Windows::UI::Xaml::Controls::IControl3, winrt::Windows::UI::Xaml::Controls::IControl4, winrt::Windows::UI::Xaml::Controls::IControl5, winrt::Windows::UI::Xaml::Controls::IControl7, winrt::Windows::UI::Xaml::Controls::IControlProtected, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, PivotHeaderItem, winrt::Windows::UI::Xaml::Controls::ContentControl, winrt::Windows::UI::Xaml::Controls::Control, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::IContentControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverrides6T<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = PivotHeaderItem;
    protected:
        PivotHeaderItemT()
        {
            impl::call_factory<PivotHeaderItem, IPivotHeaderItemFactory>([&](IPivotHeaderItemFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct RangeBaseT :
        implements<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides6, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase, winrt::Windows::UI::Xaml::Controls::IControl, winrt::Windows::UI::Xaml::Controls::IControl2, winrt::Windows::UI::Xaml::Controls::IControl3, winrt::Windows::UI::Xaml::Controls::IControl4, winrt::Windows::UI::Xaml::Controls::IControl5, winrt::Windows::UI::Xaml::Controls::IControl7, winrt::Windows::UI::Xaml::Controls::IControlProtected, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, RangeBase, winrt::Windows::UI::Xaml::Controls::Control, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverrides6T<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = RangeBase;
    protected:
        RangeBaseT()
        {
            impl::call_factory<RangeBase, IRangeBaseFactory>([&](IRangeBaseFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct SelectorItemT :
        implements<D, winrt::Windows::UI::Xaml::Controls::IContentControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides6, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItem, winrt::Windows::UI::Xaml::Controls::IContentControl, winrt::Windows::UI::Xaml::Controls::IContentControl2, winrt::Windows::UI::Xaml::Controls::IControl, winrt::Windows::UI::Xaml::Controls::IControl2, winrt::Windows::UI::Xaml::Controls::IControl3, winrt::Windows::UI::Xaml::Controls::IControl4, winrt::Windows::UI::Xaml::Controls::IControl5, winrt::Windows::UI::Xaml::Controls::IControl7, winrt::Windows::UI::Xaml::Controls::IControlProtected, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, SelectorItem, winrt::Windows::UI::Xaml::Controls::ContentControl, winrt::Windows::UI::Xaml::Controls::Control, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::IContentControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverrides6T<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = SelectorItem;
    protected:
        SelectorItemT()
        {
            impl::call_factory<SelectorItem, ISelectorItemFactory>([&](ISelectorItemFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ToggleButtonT :
        implements<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides, winrt::Windows::UI::Xaml::Controls::IContentControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides, winrt::Windows::UI::Xaml::Controls::IControlOverrides6, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton, winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase, winrt::Windows::UI::Xaml::Controls::IContentControl, winrt::Windows::UI::Xaml::Controls::IContentControl2, winrt::Windows::UI::Xaml::Controls::IControl, winrt::Windows::UI::Xaml::Controls::IControl2, winrt::Windows::UI::Xaml::Controls::IControl3, winrt::Windows::UI::Xaml::Controls::IControl4, winrt::Windows::UI::Xaml::Controls::IControl5, winrt::Windows::UI::Xaml::Controls::IControl7, winrt::Windows::UI::Xaml::Controls::IControlProtected, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ToggleButton, winrt::Windows::UI::Xaml::Controls::Primitives::ButtonBase, winrt::Windows::UI::Xaml::Controls::ContentControl, winrt::Windows::UI::Xaml::Controls::Control, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IContentControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverridesT<D>, winrt::Windows::UI::Xaml::Controls::IControlOverrides6T<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = ToggleButton;
    protected:
        ToggleButtonT()
        {
            impl::call_factory<ToggleButton, IToggleButtonFactory>([&](IToggleButtonFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarButtonTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarTemplateSettings2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IAppBarToggleButtonTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IButtonBaseStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICalendarViewTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICarouselPanelFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSlider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IColorPickerSliderStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrum> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IColorSpectrumStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IComboBoxTemplateSettings2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarFlyoutCommandBarTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ICommandBarTemplateSettings4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IDragCompletedEventArgsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IDragDeltaEventArgsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IDragStartedEventArgsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBase6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseClosingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseOverrides4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutBaseStatics6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IFlyoutShowOptionsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IGeneratorPositionHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemPresenterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IGridViewItemTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IItemsChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemBackgroundConverterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IJumpListItemForegroundConverterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILayoutInformationStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenter4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemPresenterStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IListViewItemTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelector> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ILoopingSelectorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutItemTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IMenuFlyoutPresenterTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::INavigationViewItemPresenterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IOrientedVirtualizingPanelFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseOverrides> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPickerFlyoutBaseStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderItemFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPivotHeaderPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPivotPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopup2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopup3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopup4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IPopupStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IProgressBarTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IProgressRingTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseOverrides> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRangeBaseValueChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButton> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IRepeatButtonStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IScrollBarStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IScrollEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IScrollSnapPointsInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISelector> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItemFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorItemStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISelectorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISettingsFlyoutTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ISplitViewTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IThumb> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IThumbStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ITickBar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ITickBarStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButton> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonOverrides> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleButtonStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IToggleSwitchTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::IToolTipTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::AppBarButtonTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::AppBarTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::AppBarToggleButtonTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ButtonBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::CalendarPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::CalendarViewTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::CarouselPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ColorSpectrum> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ComboBoxTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarFlyoutCommandBarTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::CommandBarTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::DragCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::DragDeltaEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::DragStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutBaseClosingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutShowOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::GeneratorPositionHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::GridViewItemPresenter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::GridViewItemTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ItemsChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::JumpListItemBackgroundConverter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::JumpListItemForegroundConverter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::LayoutInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemPresenter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ListViewItemTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::LoopingSelector> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::LoopingSelectorItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::LoopingSelectorPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::MenuFlyoutItemTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::MenuFlyoutPresenterTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::NavigationViewItemPresenter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::OrientedVirtualizingPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::PickerFlyoutBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::PivotHeaderItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::PivotHeaderPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::PivotPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::Popup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ProgressBarTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ProgressRingTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::RangeBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::RepeatButton> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollBar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::Selector> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::SelectorItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::SettingsFlyoutTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::SplitViewTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::Thumb> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::TickBar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ToggleButton> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ToggleSwitchTemplateSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Controls::Primitives::ToolTipTemplateSettings> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
