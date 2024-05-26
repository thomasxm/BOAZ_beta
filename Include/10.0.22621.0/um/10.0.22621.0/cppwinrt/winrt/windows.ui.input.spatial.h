// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Spatial_H
#define WINRT_Windows_UI_Input_Spatial_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Input.h"
#include "winrt/impl/Windows.Devices.Haptics.2.h"
#include "winrt/impl/Windows.Devices.Power.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"
#include "winrt/impl/Windows.Perception.2.h"
#include "winrt/impl/Windows.Perception.People.2.h"
#include "winrt/impl/Windows.Perception.Spatial.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Input.Spatial.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialRecognitionStartedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_RecognitionStarted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionStarted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialRecognitionStartedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RecognitionStarted_revoker>(this, RecognitionStarted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionStarted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_RecognitionStarted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionEnded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialRecognitionEndedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_RecognitionEnded(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionEnded_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionEnded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialRecognitionEndedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RecognitionEnded_revoker>(this, RecognitionEnded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionEnded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_RecognitionEnded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::Tapped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialTappedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_Tapped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::Tapped_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::Tapped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialTappedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Tapped_revoker>(this, Tapped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::Tapped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_Tapped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialHoldStartedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_HoldStarted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldStarted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialHoldStartedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, HoldStarted_revoker>(this, HoldStarted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldStarted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_HoldStarted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialHoldCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_HoldCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCompleted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialHoldCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, HoldCompleted_revoker>(this, HoldCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_HoldCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCanceled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialHoldCanceledEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_HoldCanceled(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCanceled_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCanceled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialHoldCanceledEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, HoldCanceled_revoker>(this, HoldCanceled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCanceled(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_HoldCanceled(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialManipulationStartedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_ManipulationStarted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationStarted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialManipulationStartedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ManipulationStarted_revoker>(this, ManipulationStarted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationStarted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_ManipulationStarted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialManipulationUpdatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_ManipulationUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationUpdated_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialManipulationUpdatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ManipulationUpdated_revoker>(this, ManipulationUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_ManipulationUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialManipulationCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_ManipulationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCompleted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialManipulationCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ManipulationCompleted_revoker>(this, ManipulationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_ManipulationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCanceled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialManipulationCanceledEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_ManipulationCanceled(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCanceled_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCanceled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialManipulationCanceledEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ManipulationCanceled_revoker>(this, ManipulationCanceled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCanceled(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_ManipulationCanceled(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialNavigationStartedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_NavigationStarted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationStarted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialNavigationStartedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, NavigationStarted_revoker>(this, NavigationStarted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationStarted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_NavigationStarted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialNavigationUpdatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_NavigationUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationUpdated_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialNavigationUpdatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, NavigationUpdated_revoker>(this, NavigationUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_NavigationUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialNavigationCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_NavigationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCompleted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialNavigationCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, NavigationCompleted_revoker>(this, NavigationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_NavigationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCanceled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialNavigationCanceledEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_NavigationCanceled(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCanceled_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCanceled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialNavigationCanceledEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, NavigationCanceled_revoker>(this, NavigationCanceled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCanceled(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_NavigationCanceled(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::CaptureInteraction(winrt::Windows::UI::Input::Spatial::SpatialInteraction const& interaction) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->CaptureInteraction(*(void**)(&interaction)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::CancelPendingGestures() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->CancelPendingGestures());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::TrySetGestureSettings(winrt::Windows::UI::Input::Spatial::SpatialGestureSettings const& settings) const
    {
        bool succeeded{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->TrySetGestureSettings(static_cast<uint32_t>(settings), &succeeded));
        return succeeded;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialGestureSettings) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::GestureSettings() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialGestureSettings value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->get_GestureSettings(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer) consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizerFactory<D>::Create(winrt::Windows::UI::Input::Spatial::SpatialGestureSettings const& settings) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizerFactory)->Create(static_cast<uint32_t>(settings), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialHoldCanceledEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialHoldCanceledEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialHoldCompletedEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialHoldCompletedEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialHoldStartedEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialHoldStartedEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialPointerPose) consume_Windows_UI_Input_Spatial_ISpatialHoldStartedEventArgs<D>::TryGetPointerPose(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialHoldStartedEventArgs)->TryGetPointerPose(*(void**)(&coordinateSystem), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialPointerPose{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState) consume_Windows_UI_Input_Spatial_ISpatialInteraction<D>::SourceState() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteraction)->get_SourceState(&value));
        return winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialInteractionController<D>::HasTouchpad() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionController)->get_HasTouchpad(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialInteractionController<D>::HasThumbstick() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionController)->get_HasThumbstick(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) consume_Windows_UI_Input_Spatial_ISpatialInteractionController<D>::SimpleHapticsController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionController)->get_SimpleHapticsController(&value));
        return winrt::Windows::Devices::Haptics::SimpleHapticsController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_UI_Input_Spatial_ISpatialInteractionController<D>::VendorId() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionController)->get_VendorId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_UI_Input_Spatial_ISpatialInteractionController<D>::ProductId() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionController)->get_ProductId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_UI_Input_Spatial_ISpatialInteractionController<D>::Version() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionController)->get_Version(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>) consume_Windows_UI_Input_Spatial_ISpatialInteractionController2<D>::TryGetRenderableModelAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionController2)->TryGetRenderableModelAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Power::BatteryReport) consume_Windows_UI_Input_Spatial_ISpatialInteractionController3<D>::TryGetBatteryReport() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionController3)->TryGetBatteryReport(&value));
        return winrt::Windows::Devices::Power::BatteryReport{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::IsTouchpadTouched() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_IsTouchpadTouched(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::IsTouchpadPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_IsTouchpadPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::IsThumbstickPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_IsThumbstickPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::ThumbstickX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_ThumbstickX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::ThumbstickY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_ThumbstickY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::TouchpadX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_TouchpadX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::TouchpadY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_TouchpadY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialInteractionDetectedEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialPointerPose) consume_Windows_UI_Input_Spatial_ISpatialInteractionDetectedEventArgs<D>::TryGetPointerPose(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs)->TryGetPointerPose(*(void**)(&coordinateSystem), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialPointerPose{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteraction) consume_Windows_UI_Input_Spatial_ISpatialInteractionDetectedEventArgs<D>::Interaction() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs)->get_Interaction(&value));
        return winrt::Windows::UI::Input::Spatial::SpatialInteraction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSource) consume_Windows_UI_Input_Spatial_ISpatialInteractionDetectedEventArgs2<D>::InteractionSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs2)->get_InteractionSource(&value));
        return winrt::Windows::UI::Input::Spatial::SpatialInteractionSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceDetected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager)->add_SourceDetected(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceDetected_revoker consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceDetected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SourceDetected_revoker>(this, SourceDetected(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceDetected(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager)->remove_SourceDetected(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceLost(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager)->add_SourceLost(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceLost_revoker consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceLost(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SourceLost_revoker>(this, SourceLost(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceLost(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager)->remove_SourceLost(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager)->add_SourceUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceUpdated_revoker consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SourceUpdated_revoker>(this, SourceUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager)->remove_SourceUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourcePressed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager)->add_SourcePressed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourcePressed_revoker consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourcePressed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SourcePressed_revoker>(this, SourcePressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourcePressed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager)->remove_SourcePressed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceReleased(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager)->add_SourceReleased(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceReleased_revoker consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceReleased(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SourceReleased_revoker>(this, SourceReleased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceReleased(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager)->remove_SourceReleased(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::InteractionDetected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionDetectedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager)->add_InteractionDetected(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::InteractionDetected_revoker consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::InteractionDetected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionDetectedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, InteractionDetected_revoker>(this, InteractionDetected(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::InteractionDetected(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager)->remove_InteractionDetected(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState>) consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::GetDetectedSourcesAtTimestamp(winrt::Windows::Perception::PerceptionTimestamp const& timeStamp) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager)->GetDetectedSourcesAtTimestamp(*(void**)(&timeStamp), &value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionManager) consume_Windows_UI_Input_Spatial_ISpatialInteractionManagerStatics<D>::GetForCurrentView() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics)->GetForCurrentView(&value));
        return winrt::Windows::UI::Input::Spatial::SpatialInteractionManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialInteractionManagerStatics2<D>::IsSourceKindSupported(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind const& kind) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics2)->IsSourceKindSupported(static_cast<int32_t>(kind), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_Spatial_ISpatialInteractionSource<D>::Id() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource)->get_Id(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialInteractionSource<D>::Kind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialInteractionSource2<D>::IsPointingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource2)->get_IsPointingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialInteractionSource2<D>::IsMenuSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource2)->get_IsMenuSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialInteractionSource2<D>::IsGraspSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource2)->get_IsGraspSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionController) consume_Windows_UI_Input_Spatial_ISpatialInteractionSource2<D>::Controller() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource2)->get_Controller(&value));
        return winrt::Windows::UI::Input::Spatial::SpatialInteractionController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState) consume_Windows_UI_Input_Spatial_ISpatialInteractionSource2<D>::TryGetStateAtTimestamp(winrt::Windows::Perception::PerceptionTimestamp const& timestamp) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource2)->TryGetStateAtTimestamp(*(void**)(&timestamp), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceHandedness) consume_Windows_UI_Input_Spatial_ISpatialInteractionSource3<D>::Handedness() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceHandedness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource3)->get_Handedness(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::People::HandMeshObserver) consume_Windows_UI_Input_Spatial_ISpatialInteractionSource4<D>::TryCreateHandMeshObserver() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource4)->TryCreateHandMeshObserver(&result));
        return winrt::Windows::Perception::People::HandMeshObserver{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::People::HandMeshObserver>) consume_Windows_UI_Input_Spatial_ISpatialInteractionSource4<D>::TryCreateHandMeshObserverAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource4)->TryCreateHandMeshObserverAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::People::HandMeshObserver>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceEventArgs<D>::State() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs)->get_State(&value));
        return winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionPressKind) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceEventArgs2<D>::PressKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionPressKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs2)->get_PressKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceLocation<D>::Position() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation)->get_Position(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceLocation<D>::Velocity() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation)->get_Velocity(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::quaternion>) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceLocation2<D>::Orientation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation2)->get_Orientation(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::quaternion>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceLocation3<D>::PositionAccuracy() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3)->get_PositionAccuracy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceLocation3<D>::AngularVelocity() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3)->get_AngularVelocity(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceLocation3<D>::SourcePointerPose() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3)->get_SourcePointerPose(&value));
        return winrt::Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceProperties<D>::TryGetSourceLossMitigationDirection(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties)->TryGetSourceLossMitigationDirection(*(void**)(&coordinateSystem), &value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceProperties<D>::SourceLossRisk() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties)->get_SourceLossRisk(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceLocation) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceProperties<D>::TryGetLocation(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties)->TryGetLocation(*(void**)(&coordinateSystem), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceLocation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSource) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState)->get_Source(&value));
        return winrt::Windows::UI::Input::Spatial::SpatialInteractionSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceProperties) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState)->get_Properties(&value));
        return winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState<D>::IsPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState)->get_IsPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::PerceptionTimestamp) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState<D>::Timestamp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState)->get_Timestamp(&value));
        return winrt::Windows::Perception::PerceptionTimestamp{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialPointerPose) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState<D>::TryGetPointerPose(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState)->TryGetPointerPose(*(void**)(&coordinateSystem), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialPointerPose{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState2<D>::IsSelectPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState2)->get_IsSelectPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState2<D>::IsMenuPressed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState2)->get_IsMenuPressed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState2<D>::IsGrasped() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState2)->get_IsGrasped(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState2<D>::SelectPressedValue() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState2)->get_SelectPressedValue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionControllerProperties) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState2<D>::ControllerProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState2)->get_ControllerProperties(&value));
        return winrt::Windows::UI::Input::Spatial::SpatialInteractionControllerProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::People::HandPose) consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState3<D>::TryGetHandPose() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState3)->TryGetHandPose(&value));
        return winrt::Windows::Perception::People::HandPose{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialManipulationCanceledEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialManipulationCanceledEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialManipulationCompletedEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialManipulationCompletedEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialManipulationDelta) consume_Windows_UI_Input_Spatial_ISpatialManipulationCompletedEventArgs<D>::TryGetCumulativeDelta(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialManipulationCompletedEventArgs)->TryGetCumulativeDelta(*(void**)(&coordinateSystem), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialManipulationDelta{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Input_Spatial_ISpatialManipulationDelta<D>::Translation() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialManipulationDelta)->get_Translation(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialManipulationStartedEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialManipulationStartedEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialPointerPose) consume_Windows_UI_Input_Spatial_ISpatialManipulationStartedEventArgs<D>::TryGetPointerPose(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialManipulationStartedEventArgs)->TryGetPointerPose(*(void**)(&coordinateSystem), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialPointerPose{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialManipulationUpdatedEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialManipulationUpdatedEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialManipulationDelta) consume_Windows_UI_Input_Spatial_ISpatialManipulationUpdatedEventArgs<D>::TryGetCumulativeDelta(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialManipulationUpdatedEventArgs)->TryGetCumulativeDelta(*(void**)(&coordinateSystem), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialManipulationDelta{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialNavigationCanceledEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialNavigationCanceledEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialNavigationCompletedEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialNavigationCompletedEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Input_Spatial_ISpatialNavigationCompletedEventArgs<D>::NormalizedOffset() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialNavigationCompletedEventArgs)->get_NormalizedOffset(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialNavigationStartedEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialPointerPose) consume_Windows_UI_Input_Spatial_ISpatialNavigationStartedEventArgs<D>::TryGetPointerPose(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs)->TryGetPointerPose(*(void**)(&coordinateSystem), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialPointerPose{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialNavigationStartedEventArgs<D>::IsNavigatingX() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs)->get_IsNavigatingX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialNavigationStartedEventArgs<D>::IsNavigatingY() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs)->get_IsNavigatingY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialNavigationStartedEventArgs<D>::IsNavigatingZ() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs)->get_IsNavigatingZ(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialNavigationUpdatedEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialNavigationUpdatedEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Input_Spatial_ISpatialNavigationUpdatedEventArgs<D>::NormalizedOffset() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialNavigationUpdatedEventArgs)->get_NormalizedOffset(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Input_Spatial_ISpatialPointerInteractionSourcePose<D>::Position() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Input_Spatial_ISpatialPointerInteractionSourcePose<D>::ForwardDirection() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose)->get_ForwardDirection(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Input_Spatial_ISpatialPointerInteractionSourcePose<D>::UpDirection() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose)->get_UpDirection(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::quaternion) consume_Windows_UI_Input_Spatial_ISpatialPointerInteractionSourcePose2<D>::Orientation() const
    {
        winrt::Windows::Foundation::Numerics::quaternion value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose2)->get_Orientation(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy) consume_Windows_UI_Input_Spatial_ISpatialPointerInteractionSourcePose2<D>::PositionAccuracy() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose2)->get_PositionAccuracy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::PerceptionTimestamp) consume_Windows_UI_Input_Spatial_ISpatialPointerPose<D>::Timestamp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialPointerPose)->get_Timestamp(&value));
        return winrt::Windows::Perception::PerceptionTimestamp{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::People::HeadPose) consume_Windows_UI_Input_Spatial_ISpatialPointerPose<D>::Head() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialPointerPose)->get_Head(&value));
        return winrt::Windows::Perception::People::HeadPose{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose) consume_Windows_UI_Input_Spatial_ISpatialPointerPose2<D>::TryGetInteractionSourcePose(winrt::Windows::UI::Input::Spatial::SpatialInteractionSource const& source) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialPointerPose2)->TryGetInteractionSourcePose(*(void**)(&source), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::People::EyesPose) consume_Windows_UI_Input_Spatial_ISpatialPointerPose3<D>::Eyes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialPointerPose3)->get_Eyes(&value));
        return winrt::Windows::Perception::People::EyesPose{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialPointerPose3<D>::IsHeadCapturedBySystem() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialPointerPose3)->get_IsHeadCapturedBySystem(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialPointerPose) consume_Windows_UI_Input_Spatial_ISpatialPointerPoseStatics<D>::TryGetAtTimestamp(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Perception::PerceptionTimestamp const& timestamp) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialPointerPoseStatics)->TryGetAtTimestamp(*(void**)(&coordinateSystem), *(void**)(&timestamp), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialPointerPose{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialRecognitionEndedEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialRecognitionEndedEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialRecognitionStartedEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialPointerPose) consume_Windows_UI_Input_Spatial_ISpatialRecognitionStartedEventArgs<D>::TryGetPointerPose(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs)->TryGetPointerPose(*(void**)(&coordinateSystem), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialPointerPose{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Spatial_ISpatialRecognitionStartedEventArgs<D>::IsGesturePossible(winrt::Windows::UI::Input::Spatial::SpatialGestureSettings const& gesture) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs)->IsGesturePossible(static_cast<uint32_t>(gesture), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind) consume_Windows_UI_Input_Spatial_ISpatialTappedEventArgs<D>::InteractionSourceKind() const
    {
        winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialTappedEventArgs)->get_InteractionSourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Spatial::SpatialPointerPose) consume_Windows_UI_Input_Spatial_ISpatialTappedEventArgs<D>::TryGetPointerPose(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialTappedEventArgs)->TryGetPointerPose(*(void**)(&coordinateSystem), &value));
        return winrt::Windows::UI::Input::Spatial::SpatialPointerPose{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_Spatial_ISpatialTappedEventArgs<D>::TapCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Spatial::ISpatialTappedEventArgs)->get_TapCount(&value));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer>
    {
        int32_t __stdcall add_RecognitionStarted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RecognitionStarted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialRecognitionStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RecognitionStarted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RecognitionStarted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RecognitionEnded(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RecognitionEnded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialRecognitionEndedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RecognitionEnded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RecognitionEnded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Tapped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Tapped(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialTappedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Tapped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tapped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_HoldStarted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().HoldStarted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialHoldStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_HoldStarted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HoldStarted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_HoldCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().HoldCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialHoldCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_HoldCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HoldCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_HoldCanceled(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().HoldCanceled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialHoldCanceledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_HoldCanceled(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HoldCanceled(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ManipulationStarted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ManipulationStarted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialManipulationStartedEventArgs> const*>(&handler)));
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
            *token = detach_from<winrt::event_token>(this->shim().ManipulationUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialManipulationUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ManipulationUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ManipulationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ManipulationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialManipulationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ManipulationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ManipulationCanceled(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ManipulationCanceled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialManipulationCanceledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ManipulationCanceled(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationCanceled(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_NavigationStarted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NavigationStarted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialNavigationStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NavigationStarted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NavigationStarted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_NavigationUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NavigationUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialNavigationUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NavigationUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NavigationUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_NavigationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NavigationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialNavigationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NavigationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NavigationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_NavigationCanceled(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NavigationCanceled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer, winrt::Windows::UI::Input::Spatial::SpatialNavigationCanceledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NavigationCanceled(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NavigationCanceled(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall CaptureInteraction(void* interaction) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CaptureInteraction(*reinterpret_cast<winrt::Windows::UI::Input::Spatial::SpatialInteraction const*>(&interaction));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CancelPendingGestures() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CancelPendingGestures();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySetGestureSettings(uint32_t settings, bool* succeeded) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *succeeded = detach_from<bool>(this->shim().TrySetGestureSettings(*reinterpret_cast<winrt::Windows::UI::Input::Spatial::SpatialGestureSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GestureSettings(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialGestureSettings>(this->shim().GestureSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizerFactory> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizerFactory>
    {
        int32_t __stdcall Create(uint32_t settings, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer>(this->shim().Create(*reinterpret_cast<winrt::Windows::UI::Input::Spatial::SpatialGestureSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialHoldCanceledEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialHoldCanceledEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialHoldCompletedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialHoldCompletedEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialHoldStartedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialHoldStartedEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetPointerPose(void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteraction> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteraction>
    {
        int32_t __stdcall get_SourceState(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState>(this->shim().SourceState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionController> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionController>
    {
        int32_t __stdcall get_HasTouchpad(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasTouchpad());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasThumbstick(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasThumbstick());
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
        int32_t __stdcall get_VendorId(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().VendorId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProductId(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().ProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Version(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Version());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionController2> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionController2>
    {
        int32_t __stdcall TryGetRenderableModelAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>>(this->shim().TryGetRenderableModelAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionController3> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionController3>
    {
        int32_t __stdcall TryGetBatteryReport(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Power::BatteryReport>(this->shim().TryGetBatteryReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties>
    {
        int32_t __stdcall get_IsTouchpadTouched(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTouchpadTouched());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTouchpadPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTouchpadPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsThumbstickPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsThumbstickPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ThumbstickX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ThumbstickX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ThumbstickY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ThumbstickY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TouchpadX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().TouchpadX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TouchpadY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().TouchpadY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetPointerPose(void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Interaction(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteraction>(this->shim().Interaction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs2> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs2>
    {
        int32_t __stdcall get_InteractionSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSource>(this->shim().InteractionSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager>
    {
        int32_t __stdcall add_SourceDetected(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SourceDetected(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SourceDetected(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceDetected(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SourceLost(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SourceLost(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SourceLost(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceLost(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SourceUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SourceUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SourceUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SourcePressed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SourcePressed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SourcePressed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourcePressed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SourceReleased(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SourceReleased(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SourceReleased(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceReleased(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_InteractionDetected(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().InteractionDetected(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager, winrt::Windows::UI::Input::Spatial::SpatialInteractionDetectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_InteractionDetected(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InteractionDetected(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetDetectedSourcesAtTimestamp(void* timeStamp, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState>>(this->shim().GetDetectedSourcesAtTimestamp(*reinterpret_cast<winrt::Windows::Perception::PerceptionTimestamp const*>(&timeStamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics>
    {
        int32_t __stdcall GetForCurrentView(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics2> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics2>
    {
        int32_t __stdcall IsSourceKindSupported(int32_t kind, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSourceKindSupported(*reinterpret_cast<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource>
    {
        int32_t __stdcall get_Id(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource2> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource2>
    {
        int32_t __stdcall get_IsPointingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPointingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMenuSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMenuSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsGraspSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsGraspSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Controller(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionController>(this->shim().Controller());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetStateAtTimestamp(void* timestamp, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState>(this->shim().TryGetStateAtTimestamp(*reinterpret_cast<winrt::Windows::Perception::PerceptionTimestamp const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource3> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource3>
    {
        int32_t __stdcall get_Handedness(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceHandedness>(this->shim().Handedness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource4> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource4>
    {
        int32_t __stdcall TryCreateHandMeshObserver(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Perception::People::HandMeshObserver>(this->shim().TryCreateHandMeshObserver());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCreateHandMeshObserverAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::People::HandMeshObserver>>(this->shim().TryCreateHandMeshObserverAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs>
    {
        int32_t __stdcall get_State(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs2> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs2>
    {
        int32_t __stdcall get_PressKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionPressKind>(this->shim().PressKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation>
    {
        int32_t __stdcall get_Position(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Velocity(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>>(this->shim().Velocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation2> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation2>
    {
        int32_t __stdcall get_Orientation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::quaternion>>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3>
    {
        int32_t __stdcall get_PositionAccuracy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy>(this->shim().PositionAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AngularVelocity(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>>(this->shim().AngularVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourcePointerPose(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose>(this->shim().SourcePointerPose());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties>
    {
        int32_t __stdcall TryGetSourceLossMitigationDirection(void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>>(this->shim().TryGetSourceLossMitigationDirection(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceLossRisk(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().SourceLossRisk());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetLocation(void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceLocation>(this->shim().TryGetLocation(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState>
    {
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceProperties>(this->shim().Properties());
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
        int32_t __stdcall get_Timestamp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::PerceptionTimestamp>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetPointerPose(void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState2> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState2>
    {
        int32_t __stdcall get_IsSelectPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSelectPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMenuPressed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMenuPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsGrasped(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsGrasped());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectPressedValue(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().SelectPressedValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ControllerProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionControllerProperties>(this->shim().ControllerProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState3> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState3>
    {
        int32_t __stdcall TryGetHandPose(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::People::HandPose>(this->shim().TryGetHandPose());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialManipulationCanceledEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialManipulationCanceledEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialManipulationCompletedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialManipulationCompletedEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetCumulativeDelta(void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialManipulationDelta>(this->shim().TryGetCumulativeDelta(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialManipulationDelta> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialManipulationDelta>
    {
        int32_t __stdcall get_Translation(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().Translation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialManipulationStartedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialManipulationStartedEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetPointerPose(void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialManipulationUpdatedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialManipulationUpdatedEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetCumulativeDelta(void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialManipulationDelta>(this->shim().TryGetCumulativeDelta(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialNavigationCanceledEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialNavigationCanceledEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialNavigationCompletedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialNavigationCompletedEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NormalizedOffset(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().NormalizedOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetPointerPose(void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsNavigatingX(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsNavigatingX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsNavigatingY(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsNavigatingY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsNavigatingZ(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsNavigatingZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialNavigationUpdatedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialNavigationUpdatedEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NormalizedOffset(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().NormalizedOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose>
    {
        int32_t __stdcall get_Position(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ForwardDirection(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().ForwardDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UpDirection(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().UpDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose2> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose2>
    {
        int32_t __stdcall get_Orientation(winrt::Windows::Foundation::Numerics::quaternion* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::quaternion>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::quaternion>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PositionAccuracy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy>(this->shim().PositionAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialPointerPose> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialPointerPose>
    {
        int32_t __stdcall get_Timestamp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::PerceptionTimestamp>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Head(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::People::HeadPose>(this->shim().Head());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialPointerPose2> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialPointerPose2>
    {
        int32_t __stdcall TryGetInteractionSourcePose(void* source, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose>(this->shim().TryGetInteractionSourcePose(*reinterpret_cast<winrt::Windows::UI::Input::Spatial::SpatialInteractionSource const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialPointerPose3> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialPointerPose3>
    {
        int32_t __stdcall get_Eyes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::People::EyesPose>(this->shim().Eyes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHeadCapturedBySystem(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHeadCapturedBySystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialPointerPoseStatics> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialPointerPoseStatics>
    {
        int32_t __stdcall TryGetAtTimestamp(void* coordinateSystem, void* timestamp, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetAtTimestamp(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<winrt::Windows::Perception::PerceptionTimestamp const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialRecognitionEndedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialRecognitionEndedEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetPointerPose(void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsGesturePossible(uint32_t gesture, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsGesturePossible(*reinterpret_cast<winrt::Windows::UI::Input::Spatial::SpatialGestureSettings const*>(&gesture)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Spatial::ISpatialTappedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Spatial::ISpatialTappedEventArgs>
    {
        int32_t __stdcall get_InteractionSourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetPointerPose(void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
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
}
WINRT_EXPORT namespace winrt::Windows::UI::Input::Spatial
{
    constexpr auto operator|(SpatialGestureSettings const left, SpatialGestureSettings const right) noexcept
    {
        return static_cast<SpatialGestureSettings>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(SpatialGestureSettings& left, SpatialGestureSettings const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(SpatialGestureSettings const left, SpatialGestureSettings const right) noexcept
    {
        return static_cast<SpatialGestureSettings>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(SpatialGestureSettings& left, SpatialGestureSettings const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(SpatialGestureSettings const value) noexcept
    {
        return static_cast<SpatialGestureSettings>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(SpatialGestureSettings const left, SpatialGestureSettings const right) noexcept
    {
        return static_cast<SpatialGestureSettings>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(SpatialGestureSettings& left, SpatialGestureSettings const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline SpatialGestureRecognizer::SpatialGestureRecognizer(winrt::Windows::UI::Input::Spatial::SpatialGestureSettings const& settings) :
        SpatialGestureRecognizer(impl::call_factory<SpatialGestureRecognizer, ISpatialGestureRecognizerFactory>([&](ISpatialGestureRecognizerFactory const& f) { return f.Create(settings); }))
    {
    }
    inline auto SpatialInteractionManager::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager(*)(ISpatialInteractionManagerStatics const&), SpatialInteractionManager, ISpatialInteractionManagerStatics>([](ISpatialInteractionManagerStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto SpatialInteractionManager::IsSourceKindSupported(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind const& kind)
    {
        return impl::call_factory<SpatialInteractionManager, ISpatialInteractionManagerStatics2>([&](ISpatialInteractionManagerStatics2 const& f) { return f.IsSourceKindSupported(kind); });
    }
    inline auto SpatialPointerPose::TryGetAtTimestamp(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Perception::PerceptionTimestamp const& timestamp)
    {
        return impl::call_factory<SpatialPointerPose, ISpatialPointerPoseStatics>([&](ISpatialPointerPoseStatics const& f) { return f.TryGetAtTimestamp(coordinateSystem, timestamp); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialHoldCanceledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialHoldCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialHoldStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteraction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionController2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionController3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialManipulationCanceledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialManipulationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialManipulationDelta> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialManipulationStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialManipulationUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialNavigationCanceledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialNavigationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialNavigationUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialPointerPose> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialPointerPose2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialPointerPose3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialPointerPoseStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialRecognitionEndedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialTappedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialHoldCanceledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialHoldCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialHoldStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteraction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionControllerProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionDetectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceLocation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialManipulationCanceledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialManipulationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialManipulationDelta> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialManipulationStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialManipulationUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialNavigationCanceledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialNavigationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialNavigationStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialNavigationUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialPointerPose> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialRecognitionEndedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialRecognitionStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialTappedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
