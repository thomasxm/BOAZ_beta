// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_H
#define WINRT_Windows_UI_Input_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.h"
#include "winrt/impl/Windows.Devices.Haptics.2.h"
#include "winrt/impl/Windows.Devices.Input.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Input_ICrossSlidingEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ICrossSlidingEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_ICrossSlidingEventArgs<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ICrossSlidingEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::CrossSlidingState) consume_Windows_UI_Input_ICrossSlidingEventArgs<D>::CrossSlidingState() const
    {
        winrt::Windows::UI::Input::CrossSlidingState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ICrossSlidingEventArgs)->get_CrossSlidingState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_ICrossSlidingEventArgs2<D>::ContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ICrossSlidingEventArgs2)->get_ContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Input_IDraggingEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IDraggingEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_IDraggingEventArgs<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IDraggingEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::DraggingState) consume_Windows_UI_Input_IDraggingEventArgs<D>::DraggingState() const
    {
        winrt::Windows::UI::Input::DraggingState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IDraggingEventArgs)->get_DraggingState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IDraggingEventArgs2<D>::ContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IDraggingEventArgs2)->get_ContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IEdgeGesture<D>::Starting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IEdgeGesture)->add_Starting(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IEdgeGesture<D>::Starting_revoker consume_Windows_UI_Input_IEdgeGesture<D>::Starting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Starting_revoker>(this, Starting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IEdgeGesture<D>::Starting(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IEdgeGesture)->remove_Starting(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IEdgeGesture<D>::Completed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IEdgeGesture)->add_Completed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IEdgeGesture<D>::Completed_revoker consume_Windows_UI_Input_IEdgeGesture<D>::Completed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Completed_revoker>(this, Completed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IEdgeGesture<D>::Completed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IEdgeGesture)->remove_Completed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IEdgeGesture<D>::Canceled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IEdgeGesture)->add_Canceled(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IEdgeGesture<D>::Canceled_revoker consume_Windows_UI_Input_IEdgeGesture<D>::Canceled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Canceled_revoker>(this, Canceled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IEdgeGesture<D>::Canceled(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IEdgeGesture)->remove_Canceled(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::EdgeGestureKind) consume_Windows_UI_Input_IEdgeGestureEventArgs<D>::Kind() const
    {
        winrt::Windows::UI::Input::EdgeGestureKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IEdgeGestureEventArgs)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::EdgeGesture) consume_Windows_UI_Input_IEdgeGestureStatics<D>::GetForCurrentView() const
    {
        void* current{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IEdgeGestureStatics)->GetForCurrentView(&current));
        return winrt::Windows::UI::Input::EdgeGesture{ current, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::GestureSettings) consume_Windows_UI_Input_IGestureRecognizer<D>::GestureSettings() const
    {
        winrt::Windows::UI::Input::GestureSettings value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_GestureSettings(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::GestureSettings(winrt::Windows::UI::Input::GestureSettings const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_GestureSettings(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IGestureRecognizer<D>::IsInertial() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_IsInertial(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IGestureRecognizer<D>::IsActive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_IsActive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IGestureRecognizer<D>::ShowGestureFeedback() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_ShowGestureFeedback(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::ShowGestureFeedback(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_ShowGestureFeedback(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_IGestureRecognizer<D>::PivotCenter() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_PivotCenter(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::PivotCenter(winrt::Windows::Foundation::Point const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_PivotCenter(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IGestureRecognizer<D>::PivotRadius() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_PivotRadius(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::PivotRadius(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_PivotRadius(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaTranslationDeceleration() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_InertiaTranslationDeceleration(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaTranslationDeceleration(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_InertiaTranslationDeceleration(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaRotationDeceleration() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_InertiaRotationDeceleration(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaRotationDeceleration(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_InertiaRotationDeceleration(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaExpansionDeceleration() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_InertiaExpansionDeceleration(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaExpansionDeceleration(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_InertiaExpansionDeceleration(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaTranslationDisplacement() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_InertiaTranslationDisplacement(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaTranslationDisplacement(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_InertiaTranslationDisplacement(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaRotationAngle() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_InertiaRotationAngle(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaRotationAngle(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_InertiaRotationAngle(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaExpansion() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_InertiaExpansion(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaExpansion(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_InertiaExpansion(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationExact() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_ManipulationExact(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationExact(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_ManipulationExact(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::CrossSlideThresholds) consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSlideThresholds() const
    {
        winrt::Windows::UI::Input::CrossSlideThresholds value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_CrossSlideThresholds(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSlideThresholds(winrt::Windows::UI::Input::CrossSlideThresholds const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_CrossSlideThresholds(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSlideHorizontally() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_CrossSlideHorizontally(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSlideHorizontally(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_CrossSlideHorizontally(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSlideExact() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_CrossSlideExact(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSlideExact(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_CrossSlideExact(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IGestureRecognizer<D>::AutoProcessInertia() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_AutoProcessInertia(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::AutoProcessInertia(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->put_AutoProcessInertia(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::MouseWheelParameters) consume_Windows_UI_Input_IGestureRecognizer<D>::MouseWheelParameters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->get_MouseWheelParameters(&value));
        return winrt::Windows::UI::Input::MouseWheelParameters{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IGestureRecognizer<D>::CanBeDoubleTap(winrt::Windows::UI::Input::PointerPoint const& value) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->CanBeDoubleTap(*(void**)(&value), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::ProcessDownEvent(winrt::Windows::UI::Input::PointerPoint const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->ProcessDownEvent(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::ProcessMoveEvents(param::vector<winrt::Windows::UI::Input::PointerPoint> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->ProcessMoveEvents(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::ProcessUpEvent(winrt::Windows::UI::Input::PointerPoint const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->ProcessUpEvent(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::ProcessMouseWheelEvent(winrt::Windows::UI::Input::PointerPoint const& value, bool isShiftKeyDown, bool isControlKeyDown) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->ProcessMouseWheelEvent(*(void**)(&value), isShiftKeyDown, isControlKeyDown));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::ProcessInertia() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->ProcessInertia());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::CompleteGesture() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->CompleteGesture());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IGestureRecognizer<D>::Tapped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::TappedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->add_Tapped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::Tapped_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::Tapped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::TappedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Tapped_revoker>(this, Tapped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::Tapped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->remove_Tapped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IGestureRecognizer<D>::RightTapped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::RightTappedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->add_RightTapped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::RightTapped_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::RightTapped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::RightTappedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RightTapped_revoker>(this, RightTapped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::RightTapped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->remove_RightTapped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IGestureRecognizer<D>::Holding(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::HoldingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->add_Holding(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::Holding_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::Holding(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::HoldingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Holding_revoker>(this, Holding(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::Holding(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->remove_Holding(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IGestureRecognizer<D>::Dragging(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::DraggingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->add_Dragging(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::Dragging_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::Dragging(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::DraggingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Dragging_revoker>(this, Dragging(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::Dragging(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->remove_Dragging(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationStartedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->add_ManipulationStarted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationStarted_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationStartedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ManipulationStarted_revoker>(this, ManipulationStarted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationStarted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->remove_ManipulationStarted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationUpdatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->add_ManipulationUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationUpdated_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationUpdatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ManipulationUpdated_revoker>(this, ManipulationUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->remove_ManipulationUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationInertiaStarting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationInertiaStartingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->add_ManipulationInertiaStarting(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationInertiaStarting_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationInertiaStarting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationInertiaStartingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ManipulationInertiaStarting_revoker>(this, ManipulationInertiaStarting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationInertiaStarting(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->remove_ManipulationInertiaStarting(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->add_ManipulationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationCompleted_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ManipulationCompleted_revoker>(this, ManipulationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->remove_ManipulationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSliding(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::CrossSlidingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->add_CrossSliding(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSliding_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSliding(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::CrossSlidingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CrossSliding_revoker>(this, CrossSliding(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSliding(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer)->remove_CrossSliding(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IGestureRecognizer2<D>::TapMinContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->get_TapMinContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer2<D>::TapMinContactCount(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->put_TapMinContactCount(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IGestureRecognizer2<D>::TapMaxContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->get_TapMaxContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer2<D>::TapMaxContactCount(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->put_TapMaxContactCount(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IGestureRecognizer2<D>::HoldMinContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->get_HoldMinContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer2<D>::HoldMinContactCount(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->put_HoldMinContactCount(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IGestureRecognizer2<D>::HoldMaxContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->get_HoldMaxContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer2<D>::HoldMaxContactCount(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->put_HoldMaxContactCount(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IGestureRecognizer2<D>::HoldRadius() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->get_HoldRadius(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer2<D>::HoldRadius(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->put_HoldRadius(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_Input_IGestureRecognizer2<D>::HoldStartDelay() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->get_HoldStartDelay(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer2<D>::HoldStartDelay(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->put_HoldStartDelay(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IGestureRecognizer2<D>::TranslationMinContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->get_TranslationMinContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer2<D>::TranslationMinContactCount(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->put_TranslationMinContactCount(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IGestureRecognizer2<D>::TranslationMaxContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->get_TranslationMaxContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IGestureRecognizer2<D>::TranslationMaxContactCount(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IGestureRecognizer2)->put_TranslationMaxContactCount(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Input_IHoldingEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IHoldingEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_IHoldingEventArgs<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IHoldingEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::HoldingState) consume_Windows_UI_Input_IHoldingEventArgs<D>::HoldingState() const
    {
        winrt::Windows::UI::Input::HoldingState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IHoldingEventArgs)->get_HoldingState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IHoldingEventArgs2<D>::ContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IHoldingEventArgs2)->get_ContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IHoldingEventArgs2<D>::CurrentContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IHoldingEventArgs2)->get_CurrentContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::InputActivationState) consume_Windows_UI_Input_IInputActivationListener<D>::State() const
    {
        winrt::Windows::UI::Input::InputActivationState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IInputActivationListener)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IInputActivationListener<D>::InputActivationChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::InputActivationListener, winrt::Windows::UI::Input::InputActivationListenerActivationChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IInputActivationListener)->add_InputActivationChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IInputActivationListener<D>::InputActivationChanged_revoker consume_Windows_UI_Input_IInputActivationListener<D>::InputActivationChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::InputActivationListener, winrt::Windows::UI::Input::InputActivationListenerActivationChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, InputActivationChanged_revoker>(this, InputActivationChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IInputActivationListener<D>::InputActivationChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IInputActivationListener)->remove_InputActivationChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::InputActivationState) consume_Windows_UI_Input_IInputActivationListenerActivationChangedEventArgs<D>::State() const
    {
        winrt::Windows::UI::Input::InputActivationState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::IsInterceptionEnabledWhenInForeground() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor)->get_IsInterceptionEnabledWhenInForeground(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::IsInterceptionEnabledWhenInForeground(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor)->put_IsInterceptionEnabledWhenInForeground(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyDown(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor)->add_KeyDown(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyDown_revoker consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyDown(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, KeyDown_revoker>(this, KeyDown(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyDown(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor)->remove_KeyDown(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyUp(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor)->add_KeyUp(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyUp_revoker consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyUp(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, KeyUp_revoker>(this, KeyUp(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyUp(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor)->remove_KeyUp(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::KeyboardDeliveryInterceptor) consume_Windows_UI_Input_IKeyboardDeliveryInterceptorStatics<D>::GetForCurrentView() const
    {
        void* keyboardDeliverySettings{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IKeyboardDeliveryInterceptorStatics)->GetForCurrentView(&keyboardDeliverySettings));
        return winrt::Windows::UI::Input::KeyboardDeliveryInterceptor{ keyboardDeliverySettings, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Input_IManipulationCompletedEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationCompletedEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_IManipulationCompletedEventArgs<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationCompletedEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) consume_Windows_UI_Input_IManipulationCompletedEventArgs<D>::Cumulative() const
    {
        winrt::Windows::UI::Input::ManipulationDelta value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationCompletedEventArgs)->get_Cumulative(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationVelocities) consume_Windows_UI_Input_IManipulationCompletedEventArgs<D>::Velocities() const
    {
        winrt::Windows::UI::Input::ManipulationVelocities value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationCompletedEventArgs)->get_Velocities(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IManipulationCompletedEventArgs2<D>::ContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationCompletedEventArgs2)->get_ContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IManipulationCompletedEventArgs2<D>::CurrentContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationCompletedEventArgs2)->get_CurrentContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs<D>::Delta() const
    {
        winrt::Windows::UI::Input::ManipulationDelta value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs)->get_Delta(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs<D>::Cumulative() const
    {
        winrt::Windows::UI::Input::ManipulationDelta value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs)->get_Cumulative(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationVelocities) consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs<D>::Velocities() const
    {
        winrt::Windows::UI::Input::ManipulationVelocities value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs)->get_Velocities(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs2<D>::ContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs2)->get_ContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Input_IManipulationStartedEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationStartedEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_IManipulationStartedEventArgs<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationStartedEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) consume_Windows_UI_Input_IManipulationStartedEventArgs<D>::Cumulative() const
    {
        winrt::Windows::UI::Input::ManipulationDelta value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationStartedEventArgs)->get_Cumulative(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IManipulationStartedEventArgs2<D>::ContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationStartedEventArgs2)->get_ContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Input_IManipulationUpdatedEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationUpdatedEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_IManipulationUpdatedEventArgs<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationUpdatedEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) consume_Windows_UI_Input_IManipulationUpdatedEventArgs<D>::Delta() const
    {
        winrt::Windows::UI::Input::ManipulationDelta value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationUpdatedEventArgs)->get_Delta(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) consume_Windows_UI_Input_IManipulationUpdatedEventArgs<D>::Cumulative() const
    {
        winrt::Windows::UI::Input::ManipulationDelta value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationUpdatedEventArgs)->get_Cumulative(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationVelocities) consume_Windows_UI_Input_IManipulationUpdatedEventArgs<D>::Velocities() const
    {
        winrt::Windows::UI::Input::ManipulationVelocities value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationUpdatedEventArgs)->get_Velocities(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IManipulationUpdatedEventArgs2<D>::ContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationUpdatedEventArgs2)->get_ContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IManipulationUpdatedEventArgs2<D>::CurrentContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IManipulationUpdatedEventArgs2)->get_CurrentContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_IMouseWheelParameters<D>::CharTranslation() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IMouseWheelParameters)->get_CharTranslation(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IMouseWheelParameters<D>::CharTranslation(winrt::Windows::Foundation::Point const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IMouseWheelParameters)->put_CharTranslation(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IMouseWheelParameters<D>::DeltaScale() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IMouseWheelParameters)->get_DeltaScale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IMouseWheelParameters<D>::DeltaScale(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IMouseWheelParameters)->put_DeltaScale(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IMouseWheelParameters<D>::DeltaRotationAngle() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IMouseWheelParameters)->get_DeltaRotationAngle(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IMouseWheelParameters<D>::DeltaRotationAngle(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IMouseWheelParameters)->put_DeltaRotationAngle(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_IMouseWheelParameters<D>::PageTranslation() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IMouseWheelParameters)->get_PageTranslation(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IMouseWheelParameters<D>::PageTranslation(winrt::Windows::Foundation::Point const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IMouseWheelParameters)->put_PageTranslation(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDevice) consume_Windows_UI_Input_IPointerPoint<D>::PointerDevice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPoint)->get_PointerDevice(&value));
        return winrt::Windows::Devices::Input::PointerDevice{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_IPointerPoint<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPoint)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_IPointerPoint<D>::RawPosition() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPoint)->get_RawPosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IPointerPoint<D>::PointerId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPoint)->get_PointerId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IPointerPoint<D>::FrameId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPoint)->get_FrameId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_UI_Input_IPointerPoint<D>::Timestamp() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPoint)->get_Timestamp(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPoint<D>::IsInContact() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPoint)->get_IsInContact(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::PointerPointProperties) consume_Windows_UI_Input_IPointerPoint<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPoint)->get_Properties(&value));
        return winrt::Windows::UI::Input::PointerPointProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IPointerPointProperties<D>::Pressure() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_Pressure(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::IsInverted() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_IsInverted(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::IsEraser() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_IsEraser(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IPointerPointProperties<D>::Orientation() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_Orientation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IPointerPointProperties<D>::XTilt() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_XTilt(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IPointerPointProperties<D>::YTilt() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_YTilt(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_IPointerPointProperties<D>::Twist() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_Twist(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_IPointerPointProperties<D>::ContactRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_ContactRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_IPointerPointProperties<D>::ContactRectRaw() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_ContactRectRaw(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::TouchConfidence() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_TouchConfidence(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::IsLeftButtonPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_IsLeftButtonPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::IsRightButtonPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_IsRightButtonPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::IsMiddleButtonPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_IsMiddleButtonPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Input_IPointerPointProperties<D>::MouseWheelDelta() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_MouseWheelDelta(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::IsHorizontalMouseWheel() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_IsHorizontalMouseWheel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::IsPrimary() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_IsPrimary(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::IsInRange() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_IsInRange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::IsCanceled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_IsCanceled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::IsBarrelButtonPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_IsBarrelButtonPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::IsXButton1Pressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_IsXButton1Pressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::IsXButton2Pressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_IsXButton2Pressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::PointerUpdateKind) consume_Windows_UI_Input_IPointerPointProperties<D>::PointerUpdateKind() const
    {
        winrt::Windows::UI::Input::PointerUpdateKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->get_PointerUpdateKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointProperties<D>::HasUsage(uint32_t usagePage, uint32_t usageId) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->HasUsage(usagePage, usageId, &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Input_IPointerPointProperties<D>::GetUsageValue(uint32_t usagePage, uint32_t usageId) const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties)->GetUsageValue(usagePage, usageId, &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<float>) consume_Windows_UI_Input_IPointerPointProperties2<D>::ZDistance() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointProperties2)->get_ZDistance(&value));
        return winrt::Windows::Foundation::IReference<float>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::PointerPoint) consume_Windows_UI_Input_IPointerPointStatics<D>::GetCurrentPoint(uint32_t pointerId) const
    {
        void* pointerPoint{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointStatics)->GetCurrentPoint(pointerId, &pointerPoint));
        return winrt::Windows::UI::Input::PointerPoint{ pointerPoint, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>) consume_Windows_UI_Input_IPointerPointStatics<D>::GetIntermediatePoints(uint32_t pointerId) const
    {
        void* pointerPoints{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointStatics)->GetIntermediatePoints(pointerId, &pointerPoints));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>{ pointerPoints, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::PointerPoint) consume_Windows_UI_Input_IPointerPointStatics<D>::GetCurrentPoint(uint32_t pointerId, winrt::Windows::UI::Input::IPointerPointTransform const& transform) const
    {
        void* pointerPoint{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointStatics)->GetCurrentPointTransformed(pointerId, *(void**)(&transform), &pointerPoint));
        return winrt::Windows::UI::Input::PointerPoint{ pointerPoint, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>) consume_Windows_UI_Input_IPointerPointStatics<D>::GetIntermediatePoints(uint32_t pointerId, winrt::Windows::UI::Input::IPointerPointTransform const& transform) const
    {
        void* pointerPoints{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointStatics)->GetIntermediatePointsTransformed(pointerId, *(void**)(&transform), &pointerPoints));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>{ pointerPoints, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::IPointerPointTransform) consume_Windows_UI_Input_IPointerPointTransform<D>::Inverse() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointTransform)->get_Inverse(&value));
        return winrt::Windows::UI::Input::IPointerPointTransform{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerPointTransform<D>::TryTransform(winrt::Windows::Foundation::Point const& inPoint, winrt::Windows::Foundation::Point& outPoint) const
    {
        bool returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointTransform)->TryTransform(impl::bind_in(inPoint), impl::bind_out(outPoint), &returnValue));
        return returnValue;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_IPointerPointTransform<D>::TransformBounds(winrt::Windows::Foundation::Rect const& rect) const
    {
        winrt::Windows::Foundation::Rect returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerPointTransform)->TransformBounds(impl::bind_in(rect), put_abi(returnValue)));
        return returnValue;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IPointerVisualizationSettings<D>::IsContactFeedbackEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerVisualizationSettings)->put_IsContactFeedbackEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerVisualizationSettings<D>::IsContactFeedbackEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerVisualizationSettings)->get_IsContactFeedbackEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IPointerVisualizationSettings<D>::IsBarrelButtonFeedbackEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerVisualizationSettings)->put_IsBarrelButtonFeedbackEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IPointerVisualizationSettings<D>::IsBarrelButtonFeedbackEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerVisualizationSettings)->get_IsBarrelButtonFeedbackEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::PointerVisualizationSettings) consume_Windows_UI_Input_IPointerVisualizationSettingsStatics<D>::GetForCurrentView() const
    {
        void* visualizationSettings{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IPointerVisualizationSettingsStatics)->GetForCurrentView(&visualizationSettings));
        return winrt::Windows::UI::Input::PointerVisualizationSettings{ visualizationSettings, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerMenu) consume_Windows_UI_Input_IRadialController<D>::Menu() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->get_Menu(&value));
        return winrt::Windows::UI::Input::RadialControllerMenu{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_IRadialController<D>::RotationResolutionInDegrees() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->get_RotationResolutionInDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialController<D>::RotationResolutionInDegrees(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->put_RotationResolutionInDegrees(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IRadialController<D>::UseAutomaticHapticFeedback() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->get_UseAutomaticHapticFeedback(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialController<D>::UseAutomaticHapticFeedback(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->put_UseAutomaticHapticFeedback(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IRadialController<D>::ScreenContactStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerScreenContactStartedEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->add_ScreenContactStarted(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::ScreenContactStarted_revoker consume_Windows_UI_Input_IRadialController<D>::ScreenContactStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerScreenContactStartedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ScreenContactStarted_revoker>(this, ScreenContactStarted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialController<D>::ScreenContactStarted(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->remove_ScreenContactStarted(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IRadialController<D>::ScreenContactEnded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->add_ScreenContactEnded(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::ScreenContactEnded_revoker consume_Windows_UI_Input_IRadialController<D>::ScreenContactEnded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ScreenContactEnded_revoker>(this, ScreenContactEnded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialController<D>::ScreenContactEnded(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->remove_ScreenContactEnded(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IRadialController<D>::ScreenContactContinued(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->add_ScreenContactContinued(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::ScreenContactContinued_revoker consume_Windows_UI_Input_IRadialController<D>::ScreenContactContinued(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ScreenContactContinued_revoker>(this, ScreenContactContinued(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialController<D>::ScreenContactContinued(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->remove_ScreenContactContinued(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IRadialController<D>::ControlLost(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->add_ControlLost(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::ControlLost_revoker consume_Windows_UI_Input_IRadialController<D>::ControlLost(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ControlLost_revoker>(this, ControlLost(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialController<D>::ControlLost(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->remove_ControlLost(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IRadialController<D>::RotationChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerRotationChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->add_RotationChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::RotationChanged_revoker consume_Windows_UI_Input_IRadialController<D>::RotationChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerRotationChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RotationChanged_revoker>(this, RotationChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialController<D>::RotationChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->remove_RotationChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IRadialController<D>::ButtonClicked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonClickedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->add_ButtonClicked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::ButtonClicked_revoker consume_Windows_UI_Input_IRadialController<D>::ButtonClicked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonClickedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ButtonClicked_revoker>(this, ButtonClicked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialController<D>::ButtonClicked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->remove_ButtonClicked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IRadialController<D>::ControlAcquired(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerControlAcquiredEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->add_ControlAcquired(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::ControlAcquired_revoker consume_Windows_UI_Input_IRadialController<D>::ControlAcquired(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerControlAcquiredEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ControlAcquired_revoker>(this, ControlAcquired(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialController<D>::ControlAcquired(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController)->remove_ControlAcquired(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IRadialController2<D>::ButtonPressed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonPressedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController2)->add_ButtonPressed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IRadialController2<D>::ButtonPressed_revoker consume_Windows_UI_Input_IRadialController2<D>::ButtonPressed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonPressedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ButtonPressed_revoker>(this, ButtonPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialController2<D>::ButtonPressed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController2)->remove_ButtonPressed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IRadialController2<D>::ButtonHolding(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonHoldingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController2)->add_ButtonHolding(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IRadialController2<D>::ButtonHolding_revoker consume_Windows_UI_Input_IRadialController2<D>::ButtonHolding(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonHoldingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ButtonHolding_revoker>(this, ButtonHolding(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialController2<D>::ButtonHolding(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController2)->remove_ButtonHolding(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IRadialController2<D>::ButtonReleased(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonReleasedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController2)->add_ButtonReleased(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IRadialController2<D>::ButtonReleased_revoker consume_Windows_UI_Input_IRadialController2<D>::ButtonReleased(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonReleasedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ButtonReleased_revoker>(this, ButtonReleased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialController2<D>::ButtonReleased(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialController2)->remove_ButtonReleased(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) consume_Windows_UI_Input_IRadialControllerButtonClickedEventArgs<D>::Contact() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs)->get_Contact(&value));
        return winrt::Windows::UI::Input::RadialControllerScreenContact{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) consume_Windows_UI_Input_IRadialControllerButtonClickedEventArgs2<D>::SimpleHapticsController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs2)->get_SimpleHapticsController(&value));
        return winrt::Windows::Devices::Haptics::SimpleHapticsController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) consume_Windows_UI_Input_IRadialControllerButtonHoldingEventArgs<D>::Contact() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs)->get_Contact(&value));
        return winrt::Windows::UI::Input::RadialControllerScreenContact{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) consume_Windows_UI_Input_IRadialControllerButtonHoldingEventArgs<D>::SimpleHapticsController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs)->get_SimpleHapticsController(&value));
        return winrt::Windows::Devices::Haptics::SimpleHapticsController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) consume_Windows_UI_Input_IRadialControllerButtonPressedEventArgs<D>::Contact() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs)->get_Contact(&value));
        return winrt::Windows::UI::Input::RadialControllerScreenContact{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) consume_Windows_UI_Input_IRadialControllerButtonPressedEventArgs<D>::SimpleHapticsController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs)->get_SimpleHapticsController(&value));
        return winrt::Windows::Devices::Haptics::SimpleHapticsController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) consume_Windows_UI_Input_IRadialControllerButtonReleasedEventArgs<D>::Contact() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs)->get_Contact(&value));
        return winrt::Windows::UI::Input::RadialControllerScreenContact{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) consume_Windows_UI_Input_IRadialControllerButtonReleasedEventArgs<D>::SimpleHapticsController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs)->get_SimpleHapticsController(&value));
        return winrt::Windows::Devices::Haptics::SimpleHapticsController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialControllerConfiguration<D>::SetDefaultMenuItems(param::iterable<winrt::Windows::UI::Input::RadialControllerSystemMenuItemKind> const& buttons) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerConfiguration)->SetDefaultMenuItems(*(void**)(&buttons)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialControllerConfiguration<D>::ResetToDefaultMenuItems() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerConfiguration)->ResetToDefaultMenuItems());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IRadialControllerConfiguration<D>::TrySelectDefaultMenuItem(winrt::Windows::UI::Input::RadialControllerSystemMenuItemKind const& type) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerConfiguration)->TrySelectDefaultMenuItem(static_cast<int32_t>(type), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialControllerConfiguration2<D>::ActiveControllerWhenMenuIsSuppressed(winrt::Windows::UI::Input::RadialController const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerConfiguration2)->put_ActiveControllerWhenMenuIsSuppressed(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialController) consume_Windows_UI_Input_IRadialControllerConfiguration2<D>::ActiveControllerWhenMenuIsSuppressed() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerConfiguration2)->get_ActiveControllerWhenMenuIsSuppressed(&value));
        return winrt::Windows::UI::Input::RadialController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialControllerConfiguration2<D>::IsMenuSuppressed(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerConfiguration2)->put_IsMenuSuppressed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IRadialControllerConfiguration2<D>::IsMenuSuppressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerConfiguration2)->get_IsMenuSuppressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerConfiguration) consume_Windows_UI_Input_IRadialControllerConfigurationStatics<D>::GetForCurrentView() const
    {
        void* configuration{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerConfigurationStatics)->GetForCurrentView(&configuration));
        return winrt::Windows::UI::Input::RadialControllerConfiguration{ configuration, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialControllerConfigurationStatics2<D>::AppController(winrt::Windows::UI::Input::RadialController const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2)->put_AppController(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialController) consume_Windows_UI_Input_IRadialControllerConfigurationStatics2<D>::AppController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2)->get_AppController(&value));
        return winrt::Windows::UI::Input::RadialController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialControllerConfigurationStatics2<D>::IsAppControllerEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2)->put_IsAppControllerEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IRadialControllerConfigurationStatics2<D>::IsAppControllerEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2)->get_IsAppControllerEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) consume_Windows_UI_Input_IRadialControllerControlAcquiredEventArgs<D>::Contact() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs)->get_Contact(&value));
        return winrt::Windows::UI::Input::RadialControllerScreenContact{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IRadialControllerControlAcquiredEventArgs2<D>::IsButtonPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2)->get_IsButtonPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) consume_Windows_UI_Input_IRadialControllerControlAcquiredEventArgs2<D>::SimpleHapticsController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2)->get_SimpleHapticsController(&value));
        return winrt::Windows::Devices::Haptics::SimpleHapticsController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::RadialControllerMenuItem>) consume_Windows_UI_Input_IRadialControllerMenu<D>::Items() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenu)->get_Items(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::RadialControllerMenuItem>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IRadialControllerMenu<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenu)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialControllerMenu<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenu)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerMenuItem) consume_Windows_UI_Input_IRadialControllerMenu<D>::GetSelectedMenuItem() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenu)->GetSelectedMenuItem(&result));
        return winrt::Windows::UI::Input::RadialControllerMenuItem{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialControllerMenu<D>::SelectMenuItem(winrt::Windows::UI::Input::RadialControllerMenuItem const& menuItem) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenu)->SelectMenuItem(*(void**)(&menuItem)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IRadialControllerMenu<D>::TrySelectPreviouslySelectedMenuItem() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenu)->TrySelectPreviouslySelectedMenuItem(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Input_IRadialControllerMenuItem<D>::DisplayText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenuItem)->get_DisplayText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Input_IRadialControllerMenuItem<D>::Tag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenuItem)->get_Tag(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialControllerMenuItem<D>::Tag(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenuItem)->put_Tag(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_IRadialControllerMenuItem<D>::Invoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialControllerMenuItem, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenuItem)->add_Invoked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_IRadialControllerMenuItem<D>::Invoked_revoker consume_Windows_UI_Input_IRadialControllerMenuItem<D>::Invoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialControllerMenuItem, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Invoked_revoker>(this, Invoked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_IRadialControllerMenuItem<D>::Invoked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenuItem)->remove_Invoked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerMenuItem) consume_Windows_UI_Input_IRadialControllerMenuItemStatics<D>::CreateFromIcon(param::hstring const& displayText, winrt::Windows::Storage::Streams::RandomAccessStreamReference const& icon) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenuItemStatics)->CreateFromIcon(*(void**)(&displayText), *(void**)(&icon), &result));
        return winrt::Windows::UI::Input::RadialControllerMenuItem{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerMenuItem) consume_Windows_UI_Input_IRadialControllerMenuItemStatics<D>::CreateFromKnownIcon(param::hstring const& displayText, winrt::Windows::UI::Input::RadialControllerMenuKnownIcon const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenuItemStatics)->CreateFromKnownIcon(*(void**)(&displayText), static_cast<int32_t>(value), &result));
        return winrt::Windows::UI::Input::RadialControllerMenuItem{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerMenuItem) consume_Windows_UI_Input_IRadialControllerMenuItemStatics2<D>::CreateFromFontGlyph(param::hstring const& displayText, param::hstring const& glyph, param::hstring const& fontFamily) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenuItemStatics2)->CreateFromFontGlyph(*(void**)(&displayText), *(void**)(&glyph), *(void**)(&fontFamily), &result));
        return winrt::Windows::UI::Input::RadialControllerMenuItem{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerMenuItem) consume_Windows_UI_Input_IRadialControllerMenuItemStatics2<D>::CreateFromFontGlyph(param::hstring const& displayText, param::hstring const& glyph, param::hstring const& fontFamily, winrt::Windows::Foundation::Uri const& fontUri) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerMenuItemStatics2)->CreateFromFontGlyphWithUri(*(void**)(&displayText), *(void**)(&glyph), *(void**)(&fontFamily), *(void**)(&fontUri), &result));
        return winrt::Windows::UI::Input::RadialControllerMenuItem{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_IRadialControllerRotationChangedEventArgs<D>::RotationDeltaInDegrees() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs)->get_RotationDeltaInDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) consume_Windows_UI_Input_IRadialControllerRotationChangedEventArgs<D>::Contact() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs)->get_Contact(&value));
        return winrt::Windows::UI::Input::RadialControllerScreenContact{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IRadialControllerRotationChangedEventArgs2<D>::IsButtonPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs2)->get_IsButtonPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) consume_Windows_UI_Input_IRadialControllerRotationChangedEventArgs2<D>::SimpleHapticsController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs2)->get_SimpleHapticsController(&value));
        return winrt::Windows::Devices::Haptics::SimpleHapticsController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_IRadialControllerScreenContact<D>::Bounds() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerScreenContact)->get_Bounds(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_IRadialControllerScreenContact<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerScreenContact)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) consume_Windows_UI_Input_IRadialControllerScreenContactContinuedEventArgs<D>::Contact() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs)->get_Contact(&value));
        return winrt::Windows::UI::Input::RadialControllerScreenContact{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IRadialControllerScreenContactContinuedEventArgs2<D>::IsButtonPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2)->get_IsButtonPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) consume_Windows_UI_Input_IRadialControllerScreenContactContinuedEventArgs2<D>::SimpleHapticsController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2)->get_SimpleHapticsController(&value));
        return winrt::Windows::Devices::Haptics::SimpleHapticsController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IRadialControllerScreenContactEndedEventArgs<D>::IsButtonPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs)->get_IsButtonPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) consume_Windows_UI_Input_IRadialControllerScreenContactEndedEventArgs<D>::SimpleHapticsController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs)->get_SimpleHapticsController(&value));
        return winrt::Windows::Devices::Haptics::SimpleHapticsController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) consume_Windows_UI_Input_IRadialControllerScreenContactStartedEventArgs<D>::Contact() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs)->get_Contact(&value));
        return winrt::Windows::UI::Input::RadialControllerScreenContact{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IRadialControllerScreenContactStartedEventArgs2<D>::IsButtonPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2)->get_IsButtonPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) consume_Windows_UI_Input_IRadialControllerScreenContactStartedEventArgs2<D>::SimpleHapticsController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2)->get_SimpleHapticsController(&value));
        return winrt::Windows::Devices::Haptics::SimpleHapticsController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_IRadialControllerStatics<D>::IsSupported() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerStatics)->IsSupported(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialController) consume_Windows_UI_Input_IRadialControllerStatics<D>::CreateForCurrentView() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRadialControllerStatics)->CreateForCurrentView(&result));
        return winrt::Windows::UI::Input::RadialController{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Input_IRightTappedEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRightTappedEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_IRightTappedEventArgs<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRightTappedEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_IRightTappedEventArgs2<D>::ContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::IRightTappedEventArgs2)->get_ContactCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionButtonPressed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionButtonEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemButtonEventController)->add_SystemFunctionButtonPressed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionButtonPressed_revoker consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionButtonPressed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionButtonEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SystemFunctionButtonPressed_revoker>(this, SystemFunctionButtonPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionButtonPressed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemButtonEventController)->remove_SystemFunctionButtonPressed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionButtonReleased(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionButtonEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemButtonEventController)->add_SystemFunctionButtonReleased(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionButtonReleased_revoker consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionButtonReleased(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionButtonEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SystemFunctionButtonReleased_revoker>(this, SystemFunctionButtonReleased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionButtonReleased(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemButtonEventController)->remove_SystemFunctionButtonReleased(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionLockChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionLockChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemButtonEventController)->add_SystemFunctionLockChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionLockChanged_revoker consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionLockChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionLockChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SystemFunctionLockChanged_revoker>(this, SystemFunctionLockChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionLockChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemButtonEventController)->remove_SystemFunctionLockChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionLockIndicatorChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionLockIndicatorChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemButtonEventController)->add_SystemFunctionLockIndicatorChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionLockIndicatorChanged_revoker consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionLockIndicatorChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionLockIndicatorChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SystemFunctionLockIndicatorChanged_revoker>(this, SystemFunctionLockIndicatorChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_ISystemButtonEventController<D>::SystemFunctionLockIndicatorChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemButtonEventController)->remove_SystemFunctionLockIndicatorChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::SystemButtonEventController) consume_Windows_UI_Input_ISystemButtonEventControllerStatics<D>::CreateForDispatcherQueue(winrt::Windows::System::DispatcherQueue const& queue) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemButtonEventControllerStatics)->CreateForDispatcherQueue(*(void**)(&queue), &result));
        return winrt::Windows::UI::Input::SystemButtonEventController{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_UI_Input_ISystemFunctionButtonEventArgs<D>::Timestamp() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs)->get_Timestamp(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_ISystemFunctionButtonEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_ISystemFunctionButtonEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_UI_Input_ISystemFunctionLockChangedEventArgs<D>::Timestamp() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs)->get_Timestamp(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_ISystemFunctionLockChangedEventArgs<D>::IsLocked() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs)->get_IsLocked(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_ISystemFunctionLockChangedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_ISystemFunctionLockChangedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_UI_Input_ISystemFunctionLockIndicatorChangedEventArgs<D>::Timestamp() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs)->get_Timestamp(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_ISystemFunctionLockIndicatorChangedEventArgs<D>::IsIndicatorOn() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs)->get_IsIndicatorOn(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_ISystemFunctionLockIndicatorChangedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_ISystemFunctionLockIndicatorChangedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) consume_Windows_UI_Input_ITappedEventArgs<D>::PointerDeviceType() const
    {
        winrt::Windows::Devices::Input::PointerDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ITappedEventArgs)->get_PointerDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_ITappedEventArgs<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ITappedEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_ITappedEventArgs<D>::TapCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ITappedEventArgs)->get_TapCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_ITappedEventArgs2<D>::ContactCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::ITappedEventArgs2)->get_ContactCount(&value));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IAttachableInputObject> : produce_base<D, winrt::Windows::UI::Input::IAttachableInputObject>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IAttachableInputObjectFactory> : produce_base<D, winrt::Windows::UI::Input::IAttachableInputObjectFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::ICrossSlidingEventArgs> : produce_base<D, winrt::Windows::UI::Input::ICrossSlidingEventArgs>
    {
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
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
        int32_t __stdcall get_CrossSlidingState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::CrossSlidingState>(this->shim().CrossSlidingState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::ICrossSlidingEventArgs2> : produce_base<D, winrt::Windows::UI::Input::ICrossSlidingEventArgs2>
    {
        int32_t __stdcall get_ContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IDraggingEventArgs> : produce_base<D, winrt::Windows::UI::Input::IDraggingEventArgs>
    {
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
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
        int32_t __stdcall get_DraggingState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::DraggingState>(this->shim().DraggingState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IDraggingEventArgs2> : produce_base<D, winrt::Windows::UI::Input::IDraggingEventArgs2>
    {
        int32_t __stdcall get_ContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IEdgeGesture> : produce_base<D, winrt::Windows::UI::Input::IEdgeGesture>
    {
        int32_t __stdcall add_Starting(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Starting(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Starting(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Starting(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Completed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Completed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Completed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Canceled(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Canceled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Canceled(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Canceled(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IEdgeGestureEventArgs> : produce_base<D, winrt::Windows::UI::Input::IEdgeGestureEventArgs>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::EdgeGestureKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IEdgeGestureStatics> : produce_base<D, winrt::Windows::UI::Input::IEdgeGestureStatics>
    {
        int32_t __stdcall GetForCurrentView(void** current) noexcept final try
        {
            clear_abi(current);
            typename D::abi_guard guard(this->shim());
            *current = detach_from<winrt::Windows::UI::Input::EdgeGesture>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IGestureRecognizer> : produce_base<D, winrt::Windows::UI::Input::IGestureRecognizer>
    {
        int32_t __stdcall get_GestureSettings(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::GestureSettings>(this->shim().GestureSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_GestureSettings(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GestureSettings(*reinterpret_cast<winrt::Windows::UI::Input::GestureSettings const*>(&value));
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
        int32_t __stdcall get_IsActive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShowGestureFeedback(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShowGestureFeedback());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShowGestureFeedback(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowGestureFeedback(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PivotCenter(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().PivotCenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PivotCenter(winrt::Windows::Foundation::Point value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PivotCenter(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PivotRadius(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().PivotRadius());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PivotRadius(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PivotRadius(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InertiaTranslationDeceleration(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().InertiaTranslationDeceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InertiaTranslationDeceleration(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InertiaTranslationDeceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InertiaRotationDeceleration(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().InertiaRotationDeceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InertiaRotationDeceleration(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InertiaRotationDeceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InertiaExpansionDeceleration(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().InertiaExpansionDeceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InertiaExpansionDeceleration(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InertiaExpansionDeceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InertiaTranslationDisplacement(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().InertiaTranslationDisplacement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InertiaTranslationDisplacement(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InertiaTranslationDisplacement(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InertiaRotationAngle(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().InertiaRotationAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InertiaRotationAngle(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InertiaRotationAngle(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InertiaExpansion(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().InertiaExpansion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InertiaExpansion(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InertiaExpansion(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManipulationExact(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ManipulationExact());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ManipulationExact(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationExact(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CrossSlideThresholds(struct struct_Windows_UI_Input_CrossSlideThresholds* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::CrossSlideThresholds>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::CrossSlideThresholds>(this->shim().CrossSlideThresholds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CrossSlideThresholds(struct struct_Windows_UI_Input_CrossSlideThresholds value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CrossSlideThresholds(*reinterpret_cast<winrt::Windows::UI::Input::CrossSlideThresholds const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CrossSlideHorizontally(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CrossSlideHorizontally());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CrossSlideHorizontally(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CrossSlideHorizontally(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CrossSlideExact(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CrossSlideExact());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CrossSlideExact(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CrossSlideExact(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutoProcessInertia(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AutoProcessInertia());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoProcessInertia(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoProcessInertia(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MouseWheelParameters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::MouseWheelParameters>(this->shim().MouseWheelParameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CanBeDoubleTap(void* value, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().CanBeDoubleTap(*reinterpret_cast<winrt::Windows::UI::Input::PointerPoint const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessDownEvent(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessDownEvent(*reinterpret_cast<winrt::Windows::UI::Input::PointerPoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessMoveEvents(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessMoveEvents(*reinterpret_cast<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessUpEvent(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessUpEvent(*reinterpret_cast<winrt::Windows::UI::Input::PointerPoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessMouseWheelEvent(void* value, bool isShiftKeyDown, bool isControlKeyDown) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessMouseWheelEvent(*reinterpret_cast<winrt::Windows::UI::Input::PointerPoint const*>(&value), isShiftKeyDown, isControlKeyDown);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessInertia() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessInertia();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CompleteGesture() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CompleteGesture();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Tapped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Tapped(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::TappedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Tapped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tapped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RightTapped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RightTapped(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::RightTappedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RightTapped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RightTapped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Holding(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Holding(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::HoldingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Holding(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Holding(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Dragging(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Dragging(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::DraggingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Dragging(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Dragging(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ManipulationStarted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ManipulationStarted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ManipulationStarted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationStarted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ManipulationUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ManipulationUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ManipulationUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ManipulationInertiaStarting(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ManipulationInertiaStarting(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationInertiaStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ManipulationInertiaStarting(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationInertiaStarting(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ManipulationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ManipulationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ManipulationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CrossSliding(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CrossSliding(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::CrossSlidingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CrossSliding(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CrossSliding(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IGestureRecognizer2> : produce_base<D, winrt::Windows::UI::Input::IGestureRecognizer2>
    {
        int32_t __stdcall get_TapMinContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TapMinContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TapMinContactCount(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TapMinContactCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TapMaxContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TapMaxContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TapMaxContactCount(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TapMaxContactCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HoldMinContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().HoldMinContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HoldMinContactCount(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HoldMinContactCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HoldMaxContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().HoldMaxContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HoldMaxContactCount(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HoldMaxContactCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HoldRadius(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().HoldRadius());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HoldRadius(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HoldRadius(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HoldStartDelay(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().HoldStartDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HoldStartDelay(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HoldStartDelay(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TranslationMinContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TranslationMinContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TranslationMinContactCount(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TranslationMinContactCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TranslationMaxContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TranslationMaxContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TranslationMaxContactCount(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TranslationMaxContactCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IHoldingEventArgs> : produce_base<D, winrt::Windows::UI::Input::IHoldingEventArgs>
    {
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
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
        int32_t __stdcall get_HoldingState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::HoldingState>(this->shim().HoldingState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IHoldingEventArgs2> : produce_base<D, winrt::Windows::UI::Input::IHoldingEventArgs2>
    {
        int32_t __stdcall get_ContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CurrentContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IInputActivationListener> : produce_base<D, winrt::Windows::UI::Input::IInputActivationListener>
    {
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::InputActivationState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_InputActivationChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().InputActivationChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::InputActivationListener, winrt::Windows::UI::Input::InputActivationListenerActivationChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_InputActivationChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InputActivationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs> : produce_base<D, winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs>
    {
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::InputActivationState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor> : produce_base<D, winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor>
    {
        int32_t __stdcall get_IsInterceptionEnabledWhenInForeground(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInterceptionEnabledWhenInForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsInterceptionEnabledWhenInForeground(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsInterceptionEnabledWhenInForeground(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_KeyDown(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().KeyDown(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor, winrt::Windows::UI::Core::KeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_KeyDown(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyDown(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_KeyUp(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().KeyUp(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor, winrt::Windows::UI::Core::KeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_KeyUp(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyUp(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IKeyboardDeliveryInterceptorStatics> : produce_base<D, winrt::Windows::UI::Input::IKeyboardDeliveryInterceptorStatics>
    {
        int32_t __stdcall GetForCurrentView(void** keyboardDeliverySettings) noexcept final try
        {
            clear_abi(keyboardDeliverySettings);
            typename D::abi_guard guard(this->shim());
            *keyboardDeliverySettings = detach_from<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IManipulationCompletedEventArgs> : produce_base<D, winrt::Windows::UI::Input::IManipulationCompletedEventArgs>
    {
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
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
    struct produce<D, winrt::Windows::UI::Input::IManipulationCompletedEventArgs2> : produce_base<D, winrt::Windows::UI::Input::IManipulationCompletedEventArgs2>
    {
        int32_t __stdcall get_ContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CurrentContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs> : produce_base<D, winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs>
    {
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
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
    struct produce<D, winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs2> : produce_base<D, winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs2>
    {
        int32_t __stdcall get_ContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IManipulationStartedEventArgs> : produce_base<D, winrt::Windows::UI::Input::IManipulationStartedEventArgs>
    {
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
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
        int32_t __stdcall get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::ManipulationDelta>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::ManipulationDelta>(this->shim().Cumulative());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IManipulationStartedEventArgs2> : produce_base<D, winrt::Windows::UI::Input::IManipulationStartedEventArgs2>
    {
        int32_t __stdcall get_ContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IManipulationUpdatedEventArgs> : produce_base<D, winrt::Windows::UI::Input::IManipulationUpdatedEventArgs>
    {
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
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
    struct produce<D, winrt::Windows::UI::Input::IManipulationUpdatedEventArgs2> : produce_base<D, winrt::Windows::UI::Input::IManipulationUpdatedEventArgs2>
    {
        int32_t __stdcall get_ContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CurrentContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IMouseWheelParameters> : produce_base<D, winrt::Windows::UI::Input::IMouseWheelParameters>
    {
        int32_t __stdcall get_CharTranslation(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().CharTranslation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CharTranslation(winrt::Windows::Foundation::Point value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CharTranslation(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeltaScale(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().DeltaScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DeltaScale(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeltaScale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeltaRotationAngle(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().DeltaRotationAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DeltaRotationAngle(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeltaRotationAngle(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageTranslation(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().PageTranslation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PageTranslation(winrt::Windows::Foundation::Point value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PageTranslation(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IPointerPoint> : produce_base<D, winrt::Windows::UI::Input::IPointerPoint>
    {
        int32_t __stdcall get_PointerDevice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDevice>(this->shim().PointerDevice());
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
        int32_t __stdcall get_RawPosition(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().RawPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().PointerId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().FrameId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Timestamp(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().Timestamp());
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
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::PointerPointProperties>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IPointerPointProperties> : produce_base<D, winrt::Windows::UI::Input::IPointerPointProperties>
    {
        int32_t __stdcall get_Pressure(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInverted(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInverted());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsEraser(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEraser());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Orientation(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XTilt(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().XTilt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_YTilt(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().YTilt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Twist(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().Twist());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContactRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().ContactRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContactRectRaw(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().ContactRectRaw());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TouchConfidence(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().TouchConfidence());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLeftButtonPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLeftButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsRightButtonPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRightButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMiddleButtonPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMiddleButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MouseWheelDelta(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MouseWheelDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHorizontalMouseWheel(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHorizontalMouseWheel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPrimary(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPrimary());
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
        int32_t __stdcall get_IsCanceled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCanceled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsBarrelButtonPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBarrelButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsXButton1Pressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsXButton1Pressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsXButton2Pressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsXButton2Pressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerUpdateKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::PointerUpdateKind>(this->shim().PointerUpdateKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall HasUsage(uint32_t usagePage, uint32_t usageId, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasUsage(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetUsageValue(uint32_t usagePage, uint32_t usageId, int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().GetUsageValue(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IPointerPointProperties2> : produce_base<D, winrt::Windows::UI::Input::IPointerPointProperties2>
    {
        int32_t __stdcall get_ZDistance(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<float>>(this->shim().ZDistance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IPointerPointStatics> : produce_base<D, winrt::Windows::UI::Input::IPointerPointStatics>
    {
        int32_t __stdcall GetCurrentPoint(uint32_t pointerId, void** pointerPoint) noexcept final try
        {
            clear_abi(pointerPoint);
            typename D::abi_guard guard(this->shim());
            *pointerPoint = detach_from<winrt::Windows::UI::Input::PointerPoint>(this->shim().GetCurrentPoint(pointerId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIntermediatePoints(uint32_t pointerId, void** pointerPoints) noexcept final try
        {
            clear_abi(pointerPoints);
            typename D::abi_guard guard(this->shim());
            *pointerPoints = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>>(this->shim().GetIntermediatePoints(pointerId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentPointTransformed(uint32_t pointerId, void* transform, void** pointerPoint) noexcept final try
        {
            clear_abi(pointerPoint);
            typename D::abi_guard guard(this->shim());
            *pointerPoint = detach_from<winrt::Windows::UI::Input::PointerPoint>(this->shim().GetCurrentPoint(pointerId, *reinterpret_cast<winrt::Windows::UI::Input::IPointerPointTransform const*>(&transform)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIntermediatePointsTransformed(uint32_t pointerId, void* transform, void** pointerPoints) noexcept final try
        {
            clear_abi(pointerPoints);
            typename D::abi_guard guard(this->shim());
            *pointerPoints = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>>(this->shim().GetIntermediatePoints(pointerId, *reinterpret_cast<winrt::Windows::UI::Input::IPointerPointTransform const*>(&transform)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IPointerPointTransform> : produce_base<D, winrt::Windows::UI::Input::IPointerPointTransform>
    {
        int32_t __stdcall get_Inverse(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::IPointerPointTransform>(this->shim().Inverse());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryTransform(winrt::Windows::Foundation::Point inPoint, winrt::Windows::Foundation::Point* outPoint, bool* returnValue) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(outPoint);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<bool>(this->shim().TryTransform(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&inPoint), *reinterpret_cast<winrt::Windows::Foundation::Point*>(outPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TransformBounds(winrt::Windows::Foundation::Rect rect, winrt::Windows::Foundation::Rect* returnValue) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Foundation::Rect>(this->shim().TransformBounds(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&rect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IPointerVisualizationSettings> : produce_base<D, winrt::Windows::UI::Input::IPointerVisualizationSettings>
    {
        int32_t __stdcall put_IsContactFeedbackEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsContactFeedbackEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsContactFeedbackEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsContactFeedbackEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsBarrelButtonFeedbackEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsBarrelButtonFeedbackEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsBarrelButtonFeedbackEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBarrelButtonFeedbackEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IPointerVisualizationSettingsStatics> : produce_base<D, winrt::Windows::UI::Input::IPointerVisualizationSettingsStatics>
    {
        int32_t __stdcall GetForCurrentView(void** visualizationSettings) noexcept final try
        {
            clear_abi(visualizationSettings);
            typename D::abi_guard guard(this->shim());
            *visualizationSettings = detach_from<winrt::Windows::UI::Input::PointerVisualizationSettings>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialController> : produce_base<D, winrt::Windows::UI::Input::IRadialController>
    {
        int32_t __stdcall get_Menu(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::RadialControllerMenu>(this->shim().Menu());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RotationResolutionInDegrees(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RotationResolutionInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RotationResolutionInDegrees(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RotationResolutionInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UseAutomaticHapticFeedback(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().UseAutomaticHapticFeedback());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UseAutomaticHapticFeedback(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UseAutomaticHapticFeedback(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ScreenContactStarted(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().ScreenContactStarted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerScreenContactStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ScreenContactStarted(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScreenContactStarted(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_ScreenContactEnded(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().ScreenContactEnded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ScreenContactEnded(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScreenContactEnded(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_ScreenContactContinued(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().ScreenContactContinued(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ScreenContactContinued(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScreenContactContinued(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_ControlLost(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().ControlLost(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ControlLost(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ControlLost(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_RotationChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RotationChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerRotationChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RotationChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RotationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ButtonClicked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ButtonClicked(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonClickedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ButtonClicked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ButtonClicked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ControlAcquired(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().ControlAcquired(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerControlAcquiredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ControlAcquired(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ControlAcquired(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialController2> : produce_base<D, winrt::Windows::UI::Input::IRadialController2>
    {
        int32_t __stdcall add_ButtonPressed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ButtonPressed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonPressedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ButtonPressed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ButtonPressed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ButtonHolding(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ButtonHolding(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonHoldingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ButtonHolding(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ButtonHolding(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ButtonReleased(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ButtonReleased(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonReleasedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ButtonReleased(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ButtonReleased(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs>
    {
        int32_t __stdcall get_Contact(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs2> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs2>
    {
        int32_t __stdcall get_SimpleHapticsController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs>
    {
        int32_t __stdcall get_Contact(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SimpleHapticsController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs>
    {
        int32_t __stdcall get_Contact(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SimpleHapticsController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs>
    {
        int32_t __stdcall get_Contact(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SimpleHapticsController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerConfiguration> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerConfiguration>
    {
        int32_t __stdcall SetDefaultMenuItems(void* buttons) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDefaultMenuItems(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Input::RadialControllerSystemMenuItemKind> const*>(&buttons));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResetToDefaultMenuItems() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResetToDefaultMenuItems();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySelectDefaultMenuItem(int32_t type, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TrySelectDefaultMenuItem(*reinterpret_cast<winrt::Windows::UI::Input::RadialControllerSystemMenuItemKind const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerConfiguration2> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerConfiguration2>
    {
        int32_t __stdcall put_ActiveControllerWhenMenuIsSuppressed(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ActiveControllerWhenMenuIsSuppressed(*reinterpret_cast<winrt::Windows::UI::Input::RadialController const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActiveControllerWhenMenuIsSuppressed(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::RadialController>(this->shim().ActiveControllerWhenMenuIsSuppressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsMenuSuppressed(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsMenuSuppressed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMenuSuppressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMenuSuppressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerConfigurationStatics> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerConfigurationStatics>
    {
        int32_t __stdcall GetForCurrentView(void** configuration) noexcept final try
        {
            clear_abi(configuration);
            typename D::abi_guard guard(this->shim());
            *configuration = detach_from<winrt::Windows::UI::Input::RadialControllerConfiguration>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2>
    {
        int32_t __stdcall put_AppController(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppController(*reinterpret_cast<winrt::Windows::UI::Input::RadialController const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::RadialController>(this->shim().AppController());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAppControllerEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAppControllerEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAppControllerEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAppControllerEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs>
    {
        int32_t __stdcall get_Contact(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2>
    {
        int32_t __stdcall get_IsButtonPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SimpleHapticsController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerMenu> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerMenu>
    {
        int32_t __stdcall get_Items(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::RadialControllerMenuItem>>(this->shim().Items());
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
        int32_t __stdcall GetSelectedMenuItem(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::RadialControllerMenuItem>(this->shim().GetSelectedMenuItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SelectMenuItem(void* menuItem) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectMenuItem(*reinterpret_cast<winrt::Windows::UI::Input::RadialControllerMenuItem const*>(&menuItem));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySelectPreviouslySelectedMenuItem(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TrySelectPreviouslySelectedMenuItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerMenuItem> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerMenuItem>
    {
        int32_t __stdcall get_DisplayText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Tag(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tag(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Invoked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Invoked(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialControllerMenuItem, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
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
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerMenuItemStatics> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerMenuItemStatics>
    {
        int32_t __stdcall CreateFromIcon(void* displayText, void* icon, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::RadialControllerMenuItem>(this->shim().CreateFromIcon(*reinterpret_cast<hstring const*>(&displayText), *reinterpret_cast<winrt::Windows::Storage::Streams::RandomAccessStreamReference const*>(&icon)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromKnownIcon(void* displayText, int32_t value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::RadialControllerMenuItem>(this->shim().CreateFromKnownIcon(*reinterpret_cast<hstring const*>(&displayText), *reinterpret_cast<winrt::Windows::UI::Input::RadialControllerMenuKnownIcon const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerMenuItemStatics2> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerMenuItemStatics2>
    {
        int32_t __stdcall CreateFromFontGlyph(void* displayText, void* glyph, void* fontFamily, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::RadialControllerMenuItem>(this->shim().CreateFromFontGlyph(*reinterpret_cast<hstring const*>(&displayText), *reinterpret_cast<hstring const*>(&glyph), *reinterpret_cast<hstring const*>(&fontFamily)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromFontGlyphWithUri(void* displayText, void* glyph, void* fontFamily, void* fontUri, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::RadialControllerMenuItem>(this->shim().CreateFromFontGlyph(*reinterpret_cast<hstring const*>(&displayText), *reinterpret_cast<hstring const*>(&glyph), *reinterpret_cast<hstring const*>(&fontFamily), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&fontUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs>
    {
        int32_t __stdcall get_RotationDeltaInDegrees(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RotationDeltaInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Contact(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs2> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs2>
    {
        int32_t __stdcall get_IsButtonPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SimpleHapticsController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerScreenContact> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerScreenContact>
    {
        int32_t __stdcall get_Bounds(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().Bounds());
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs>
    {
        int32_t __stdcall get_Contact(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2>
    {
        int32_t __stdcall get_IsButtonPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SimpleHapticsController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs>
    {
        int32_t __stdcall get_IsButtonPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SimpleHapticsController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs>
    {
        int32_t __stdcall get_Contact(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2>
    {
        int32_t __stdcall get_IsButtonPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SimpleHapticsController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRadialControllerStatics> : produce_base<D, winrt::Windows::UI::Input::IRadialControllerStatics>
    {
        int32_t __stdcall IsSupported(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateForCurrentView(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::RadialController>(this->shim().CreateForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRightTappedEventArgs> : produce_base<D, winrt::Windows::UI::Input::IRightTappedEventArgs>
    {
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::IRightTappedEventArgs2> : produce_base<D, winrt::Windows::UI::Input::IRightTappedEventArgs2>
    {
        int32_t __stdcall get_ContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::ISystemButtonEventController> : produce_base<D, winrt::Windows::UI::Input::ISystemButtonEventController>
    {
        int32_t __stdcall add_SystemFunctionButtonPressed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SystemFunctionButtonPressed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionButtonEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SystemFunctionButtonPressed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SystemFunctionButtonPressed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SystemFunctionButtonReleased(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SystemFunctionButtonReleased(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionButtonEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SystemFunctionButtonReleased(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SystemFunctionButtonReleased(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SystemFunctionLockChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SystemFunctionLockChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionLockChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SystemFunctionLockChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SystemFunctionLockChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SystemFunctionLockIndicatorChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SystemFunctionLockIndicatorChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionLockIndicatorChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SystemFunctionLockIndicatorChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SystemFunctionLockIndicatorChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::ISystemButtonEventControllerStatics> : produce_base<D, winrt::Windows::UI::Input::ISystemButtonEventControllerStatics>
    {
        int32_t __stdcall CreateForDispatcherQueue(void* queue, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::SystemButtonEventController>(this->shim().CreateForDispatcherQueue(*reinterpret_cast<winrt::Windows::System::DispatcherQueue const*>(&queue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs> : produce_base<D, winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs>
    {
        int32_t __stdcall get_Timestamp(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().Timestamp());
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
    struct produce<D, winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs> : produce_base<D, winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs>
    {
        int32_t __stdcall get_Timestamp(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLocked(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLocked());
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
    struct produce<D, winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs> : produce_base<D, winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs>
    {
        int32_t __stdcall get_Timestamp(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsIndicatorOn(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsIndicatorOn());
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
    struct produce<D, winrt::Windows::UI::Input::ITappedEventArgs> : produce_base<D, winrt::Windows::UI::Input::ITappedEventArgs>
    {
        int32_t __stdcall get_PointerDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
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
        int32_t __stdcall get_TapCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TapCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::ITappedEventArgs2> : produce_base<D, winrt::Windows::UI::Input::ITappedEventArgs2>
    {
        int32_t __stdcall get_ContactCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ContactCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Input
{
    constexpr auto operator|(GestureSettings const left, GestureSettings const right) noexcept
    {
        return static_cast<GestureSettings>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(GestureSettings& left, GestureSettings const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(GestureSettings const left, GestureSettings const right) noexcept
    {
        return static_cast<GestureSettings>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(GestureSettings& left, GestureSettings const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(GestureSettings const value) noexcept
    {
        return static_cast<GestureSettings>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(GestureSettings const left, GestureSettings const right) noexcept
    {
        return static_cast<GestureSettings>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(GestureSettings& left, GestureSettings const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto EdgeGesture::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Input::EdgeGesture(*)(IEdgeGestureStatics const&), EdgeGesture, IEdgeGestureStatics>([](IEdgeGestureStatics const& f) { return f.GetForCurrentView(); });
    }
    inline GestureRecognizer::GestureRecognizer() :
        GestureRecognizer(impl::call_factory_cast<GestureRecognizer(*)(winrt::Windows::Foundation::IActivationFactory const&), GestureRecognizer>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<GestureRecognizer>(); }))
    {
    }
    inline auto KeyboardDeliveryInterceptor::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor(*)(IKeyboardDeliveryInterceptorStatics const&), KeyboardDeliveryInterceptor, IKeyboardDeliveryInterceptorStatics>([](IKeyboardDeliveryInterceptorStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto PointerPoint::GetCurrentPoint(uint32_t pointerId)
    {
        return impl::call_factory<PointerPoint, IPointerPointStatics>([&](IPointerPointStatics const& f) { return f.GetCurrentPoint(pointerId); });
    }
    inline auto PointerPoint::GetIntermediatePoints(uint32_t pointerId)
    {
        return impl::call_factory<PointerPoint, IPointerPointStatics>([&](IPointerPointStatics const& f) { return f.GetIntermediatePoints(pointerId); });
    }
    inline auto PointerPoint::GetCurrentPoint(uint32_t pointerId, winrt::Windows::UI::Input::IPointerPointTransform const& transform)
    {
        return impl::call_factory<PointerPoint, IPointerPointStatics>([&](IPointerPointStatics const& f) { return f.GetCurrentPoint(pointerId, transform); });
    }
    inline auto PointerPoint::GetIntermediatePoints(uint32_t pointerId, winrt::Windows::UI::Input::IPointerPointTransform const& transform)
    {
        return impl::call_factory<PointerPoint, IPointerPointStatics>([&](IPointerPointStatics const& f) { return f.GetIntermediatePoints(pointerId, transform); });
    }
    inline auto PointerVisualizationSettings::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Input::PointerVisualizationSettings(*)(IPointerVisualizationSettingsStatics const&), PointerVisualizationSettings, IPointerVisualizationSettingsStatics>([](IPointerVisualizationSettingsStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto RadialController::IsSupported()
    {
        return impl::call_factory_cast<bool(*)(IRadialControllerStatics const&), RadialController, IRadialControllerStatics>([](IRadialControllerStatics const& f) { return f.IsSupported(); });
    }
    inline auto RadialController::CreateForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Input::RadialController(*)(IRadialControllerStatics const&), RadialController, IRadialControllerStatics>([](IRadialControllerStatics const& f) { return f.CreateForCurrentView(); });
    }
    inline auto RadialControllerConfiguration::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Input::RadialControllerConfiguration(*)(IRadialControllerConfigurationStatics const&), RadialControllerConfiguration, IRadialControllerConfigurationStatics>([](IRadialControllerConfigurationStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto RadialControllerConfiguration::AppController(winrt::Windows::UI::Input::RadialController const& value)
    {
        impl::call_factory<RadialControllerConfiguration, IRadialControllerConfigurationStatics2>([&](IRadialControllerConfigurationStatics2 const& f) { return f.AppController(value); });
    }
    inline auto RadialControllerConfiguration::AppController()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Input::RadialController(*)(IRadialControllerConfigurationStatics2 const&), RadialControllerConfiguration, IRadialControllerConfigurationStatics2>([](IRadialControllerConfigurationStatics2 const& f) { return f.AppController(); });
    }
    inline auto RadialControllerConfiguration::IsAppControllerEnabled(bool value)
    {
        impl::call_factory<RadialControllerConfiguration, IRadialControllerConfigurationStatics2>([&](IRadialControllerConfigurationStatics2 const& f) { return f.IsAppControllerEnabled(value); });
    }
    inline auto RadialControllerConfiguration::IsAppControllerEnabled()
    {
        return impl::call_factory_cast<bool(*)(IRadialControllerConfigurationStatics2 const&), RadialControllerConfiguration, IRadialControllerConfigurationStatics2>([](IRadialControllerConfigurationStatics2 const& f) { return f.IsAppControllerEnabled(); });
    }
    inline auto RadialControllerMenuItem::CreateFromIcon(param::hstring const& displayText, winrt::Windows::Storage::Streams::RandomAccessStreamReference const& icon)
    {
        return impl::call_factory<RadialControllerMenuItem, IRadialControllerMenuItemStatics>([&](IRadialControllerMenuItemStatics const& f) { return f.CreateFromIcon(displayText, icon); });
    }
    inline auto RadialControllerMenuItem::CreateFromKnownIcon(param::hstring const& displayText, winrt::Windows::UI::Input::RadialControllerMenuKnownIcon const& value)
    {
        return impl::call_factory<RadialControllerMenuItem, IRadialControllerMenuItemStatics>([&](IRadialControllerMenuItemStatics const& f) { return f.CreateFromKnownIcon(displayText, value); });
    }
    inline auto RadialControllerMenuItem::CreateFromFontGlyph(param::hstring const& displayText, param::hstring const& glyph, param::hstring const& fontFamily)
    {
        return impl::call_factory<RadialControllerMenuItem, IRadialControllerMenuItemStatics2>([&](IRadialControllerMenuItemStatics2 const& f) { return f.CreateFromFontGlyph(displayText, glyph, fontFamily); });
    }
    inline auto RadialControllerMenuItem::CreateFromFontGlyph(param::hstring const& displayText, param::hstring const& glyph, param::hstring const& fontFamily, winrt::Windows::Foundation::Uri const& fontUri)
    {
        return impl::call_factory<RadialControllerMenuItem, IRadialControllerMenuItemStatics2>([&](IRadialControllerMenuItemStatics2 const& f) { return f.CreateFromFontGlyph(displayText, glyph, fontFamily, fontUri); });
    }
    inline auto SystemButtonEventController::CreateForDispatcherQueue(winrt::Windows::System::DispatcherQueue const& queue)
    {
        return impl::call_factory<SystemButtonEventController, ISystemButtonEventControllerStatics>([&](ISystemButtonEventControllerStatics const& f) { return f.CreateForDispatcherQueue(queue); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Input::IAttachableInputObject> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IAttachableInputObjectFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::ICrossSlidingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::ICrossSlidingEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IDraggingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IDraggingEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IEdgeGesture> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IEdgeGestureEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IEdgeGestureStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IGestureRecognizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IGestureRecognizer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IHoldingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IHoldingEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IInputActivationListener> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IManipulationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IManipulationCompletedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IManipulationStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IManipulationStartedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IMouseWheelParameters> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IPointerPoint> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IPointerPointProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IPointerPointProperties2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IPointerPointStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IPointerPointTransform> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IPointerVisualizationSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IPointerVisualizationSettingsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialController2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerConfiguration2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerMenu> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerMenuItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerScreenContact> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRadialControllerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRightTappedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::IRightTappedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::ISystemButtonEventController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::ISystemButtonEventControllerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::ITappedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::ITappedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::AttachableInputObject> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::CrossSlidingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::DraggingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::EdgeGesture> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::EdgeGestureEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::GestureRecognizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::HoldingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::InputActivationListener> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::InputActivationListenerActivationChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::ManipulationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::ManipulationInertiaStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::ManipulationStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::ManipulationUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::MouseWheelParameters> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::PointerPoint> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::PointerPointProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::PointerVisualizationSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialControllerButtonClickedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialControllerButtonHoldingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialControllerButtonPressedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialControllerButtonReleasedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialControllerConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialControllerControlAcquiredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialControllerMenu> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialControllerMenuItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialControllerRotationChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialControllerScreenContact> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialControllerScreenContactEndedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RadialControllerScreenContactStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::RightTappedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::SystemButtonEventController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::SystemFunctionButtonEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::SystemFunctionLockChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::SystemFunctionLockIndicatorChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::TappedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
