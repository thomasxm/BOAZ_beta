// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_ViewManagement_Core_H
#define WINRT_Windows_UI_ViewManagement_Core_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.ViewManagement.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.ViewManagement.Core.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputView<D>::PrimaryViewAnimationStarting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView, winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputViewAnimationStartingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputView)->add_PrimaryViewAnimationStarting(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputView<D>::PrimaryViewAnimationStarting_revoker consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputView<D>::PrimaryViewAnimationStarting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView, winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputViewAnimationStartingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PrimaryViewAnimationStarting_revoker>(this, PrimaryViewAnimationStarting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputView<D>::PrimaryViewAnimationStarting(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputView)->remove_PrimaryViewAnimationStarting(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputView<D>::OcclusionsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView, winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputViewOcclusionsChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputView)->add_OcclusionsChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputView<D>::OcclusionsChanged_revoker consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputView<D>::OcclusionsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView, winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputViewOcclusionsChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, OcclusionsChanged_revoker>(this, OcclusionsChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputView<D>::OcclusionsChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputView)->remove_OcclusionsChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>) consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputViewAnimationStartingEventArgs<D>::Occlusions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewAnimationStartingEventArgs)->get_Occlusions(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputViewAnimationStartingEventArgs<D>::FrameworkAnimationRecommended() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewAnimationStartingEventArgs)->get_FrameworkAnimationRecommended(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputViewAnimationStartingEventArgs<D>::AnimationDuration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewAnimationStartingEventArgs)->get_AnimationDuration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>) consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputViewOcclusionsChangedEventArgs<D>::Occlusions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewOcclusionsChangedEventArgs)->get_Occlusions(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputViewOcclusionsChangedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewOcclusionsChangedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView) consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputViewStatics<D>::GetForUIContext(winrt::Windows::UI::UIContext const& context) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewStatics)->GetForUIContext(*(void**)(&context), &result));
        return winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView) consume_Windows_UI_ViewManagement_Core_ICoreFrameworkInputViewStatics<D>::GetForCurrentView() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewStatics)->GetForCurrentView(&result));
        return winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::OcclusionsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView)->add_OcclusionsChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::OcclusionsChanged_revoker consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::OcclusionsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, OcclusionsChanged_revoker>(this, OcclusionsChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::OcclusionsChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView)->remove_OcclusionsChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>) consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::GetCoreInputViewOcclusions() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView)->GetCoreInputViewOcclusions(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::TryShowPrimaryView() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView)->TryShowPrimaryView(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::TryHidePrimaryView() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView)->TryHidePrimaryView(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferringFromPrimaryView(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView2)->add_XYFocusTransferringFromPrimaryView(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferringFromPrimaryView_revoker consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferringFromPrimaryView(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, XYFocusTransferringFromPrimaryView_revoker>(this, XYFocusTransferringFromPrimaryView(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferringFromPrimaryView(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView2)->remove_XYFocusTransferringFromPrimaryView(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferredToPrimaryView(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView2)->add_XYFocusTransferredToPrimaryView(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferredToPrimaryView_revoker consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferredToPrimaryView(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, XYFocusTransferredToPrimaryView_revoker>(this, XYFocusTransferredToPrimaryView(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferredToPrimaryView(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView2)->remove_XYFocusTransferredToPrimaryView(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::TryTransferXYFocusToPrimaryView(winrt::Windows::Foundation::Rect const& origin, winrt::Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection const& direction) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView2)->TryTransferXYFocusToPrimaryView(impl::bind_in(origin), static_cast<int32_t>(direction), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreInputView3<D>::TryShow() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView3)->TryShow(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreInputView3<D>::TryShow(winrt::Windows::UI::ViewManagement::Core::CoreInputViewKind const& type) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView3)->TryShowWithKind(static_cast<int32_t>(type), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreInputView3<D>::TryHide() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView3)->TryHide(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_ViewManagement_Core_ICoreInputView4<D>::PrimaryViewShowing(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewShowingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView4)->add_PrimaryViewShowing(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_ViewManagement_Core_ICoreInputView4<D>::PrimaryViewShowing_revoker consume_Windows_UI_ViewManagement_Core_ICoreInputView4<D>::PrimaryViewShowing(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewShowingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PrimaryViewShowing_revoker>(this, PrimaryViewShowing(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_ICoreInputView4<D>::PrimaryViewShowing(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView4)->remove_PrimaryViewShowing(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_ViewManagement_Core_ICoreInputView4<D>::PrimaryViewHiding(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewHidingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView4)->add_PrimaryViewHiding(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_ViewManagement_Core_ICoreInputView4<D>::PrimaryViewHiding_revoker consume_Windows_UI_ViewManagement_Core_ICoreInputView4<D>::PrimaryViewHiding(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewHidingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PrimaryViewHiding_revoker>(this, PrimaryViewHiding(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_ICoreInputView4<D>::PrimaryViewHiding(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView4)->remove_PrimaryViewHiding(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreInputView5<D>::IsKindSupported(winrt::Windows::UI::ViewManagement::Core::CoreInputViewKind const& type) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView5)->IsKindSupported(static_cast<int32_t>(type), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_ViewManagement_Core_ICoreInputView5<D>::SupportedKindsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView5)->add_SupportedKindsChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_ViewManagement_Core_ICoreInputView5<D>::SupportedKindsChanged_revoker consume_Windows_UI_ViewManagement_Core_ICoreInputView5<D>::SupportedKindsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SupportedKindsChanged_revoker>(this, SupportedKindsChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_ICoreInputView5<D>::SupportedKindsChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView5)->remove_SupportedKindsChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_ViewManagement_Core_ICoreInputView5<D>::PrimaryViewAnimationStarting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewAnimationStartingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView5)->add_PrimaryViewAnimationStarting(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_ViewManagement_Core_ICoreInputView5<D>::PrimaryViewAnimationStarting_revoker consume_Windows_UI_ViewManagement_Core_ICoreInputView5<D>::PrimaryViewAnimationStarting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewAnimationStartingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PrimaryViewAnimationStarting_revoker>(this, PrimaryViewAnimationStarting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_ICoreInputView5<D>::PrimaryViewAnimationStarting(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputView5)->remove_PrimaryViewAnimationStarting(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>) consume_Windows_UI_ViewManagement_Core_ICoreInputViewAnimationStartingEventArgs<D>::Occlusions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewAnimationStartingEventArgs)->get_Occlusions(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreInputViewAnimationStartingEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewAnimationStartingEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_ICoreInputViewAnimationStartingEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewAnimationStartingEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_ViewManagement_Core_ICoreInputViewAnimationStartingEventArgs<D>::AnimationDuration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewAnimationStartingEventArgs)->get_AnimationDuration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreInputViewHidingEventArgs<D>::TryCancel() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewHidingEventArgs)->TryCancel(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusion<D>::OccludingRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion)->get_OccludingRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusionKind) consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusion<D>::OcclusionKind() const
    {
        winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusionKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion)->get_OcclusionKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>) consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusionsChangedEventArgs<D>::Occlusions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs)->get_Occlusions(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusionsChangedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusionsChangedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreInputViewShowingEventArgs<D>::TryCancel() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewShowingEventArgs)->TryCancel(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::Core::CoreInputView) consume_Windows_UI_ViewManagement_Core_ICoreInputViewStatics<D>::GetForCurrentView() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewStatics)->GetForCurrentView(&result));
        return winrt::Windows::UI::ViewManagement::Core::CoreInputView{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::Core::CoreInputView) consume_Windows_UI_ViewManagement_Core_ICoreInputViewStatics2<D>::GetForUIContext(winrt::Windows::UI::UIContext const& context) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewStatics2)->GetForUIContext(*(void**)(&context), &result));
        return winrt::Windows::UI::ViewManagement::Core::CoreInputView{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs<D>::Origin() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs)->get_Origin(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection) consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs<D>::Direction() const
    {
        winrt::Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs)->get_Direction(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs<D>::TransferHandled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs)->put_TransferHandled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs<D>::TransferHandled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs)->get_TransferHandled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs<D>::KeepPrimaryViewVisible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs)->put_KeepPrimaryViewVisible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs<D>::KeepPrimaryViewVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs)->get_KeepPrimaryViewVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_IUISettingsController<D>::SetAdvancedEffectsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::IUISettingsController)->SetAdvancedEffectsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_IUISettingsController<D>::SetAnimationsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::IUISettingsController)->SetAnimationsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_IUISettingsController<D>::SetAutoHideScrollBars(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::IUISettingsController)->SetAutoHideScrollBars(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_IUISettingsController<D>::SetMessageDuration(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::IUISettingsController)->SetMessageDuration(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_ViewManagement_Core_IUISettingsController<D>::SetTextScaleFactor(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::IUISettingsController)->SetTextScaleFactor(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::ViewManagement::Core::UISettingsController>) consume_Windows_UI_ViewManagement_Core_IUISettingsControllerStatics<D>::RequestDefaultAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::ViewManagement::Core::IUISettingsControllerStatics)->RequestDefaultAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::ViewManagement::Core::UISettingsController>{ operation, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputView> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputView>
    {
        int32_t __stdcall add_PrimaryViewAnimationStarting(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PrimaryViewAnimationStarting(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView, winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputViewAnimationStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PrimaryViewAnimationStarting(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrimaryViewAnimationStarting(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_OcclusionsChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().OcclusionsChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView, winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputViewOcclusionsChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_OcclusionsChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OcclusionsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewAnimationStartingEventArgs> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewAnimationStartingEventArgs>
    {
        int32_t __stdcall get_Occlusions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>>(this->shim().Occlusions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameworkAnimationRecommended(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().FrameworkAnimationRecommended());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AnimationDuration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().AnimationDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewOcclusionsChangedEventArgs> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewOcclusionsChangedEventArgs>
    {
        int32_t __stdcall get_Occlusions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>>(this->shim().Occlusions());
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewStatics> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewStatics>
    {
        int32_t __stdcall GetForUIContext(void* context, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView>(this->shim().GetForUIContext(*reinterpret_cast<winrt::Windows::UI::UIContext const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForCurrentView(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputView> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputView>
    {
        int32_t __stdcall add_OcclusionsChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().OcclusionsChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_OcclusionsChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OcclusionsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetCoreInputViewOcclusions(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>>(this->shim().GetCoreInputViewOcclusions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryShowPrimaryView(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryShowPrimaryView());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryHidePrimaryView(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryHidePrimaryView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputView2> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputView2>
    {
        int32_t __stdcall add_XYFocusTransferringFromPrimaryView(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().XYFocusTransferringFromPrimaryView(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_XYFocusTransferringFromPrimaryView(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusTransferringFromPrimaryView(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_XYFocusTransferredToPrimaryView(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().XYFocusTransferredToPrimaryView(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_XYFocusTransferredToPrimaryView(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XYFocusTransferredToPrimaryView(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall TryTransferXYFocusToPrimaryView(winrt::Windows::Foundation::Rect origin, int32_t direction, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryTransferXYFocusToPrimaryView(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&origin), *reinterpret_cast<winrt::Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputView3> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputView3>
    {
        int32_t __stdcall TryShow(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryShow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryShowWithKind(int32_t type, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryShow(*reinterpret_cast<winrt::Windows::UI::ViewManagement::Core::CoreInputViewKind const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryHide(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryHide());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputView4> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputView4>
    {
        int32_t __stdcall add_PrimaryViewShowing(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PrimaryViewShowing(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewShowingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PrimaryViewShowing(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrimaryViewShowing(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PrimaryViewHiding(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PrimaryViewHiding(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewHidingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PrimaryViewHiding(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrimaryViewHiding(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputView5> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputView5>
    {
        int32_t __stdcall IsKindSupported(int32_t type, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsKindSupported(*reinterpret_cast<winrt::Windows::UI::ViewManagement::Core::CoreInputViewKind const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SupportedKindsChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SupportedKindsChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SupportedKindsChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SupportedKindsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PrimaryViewAnimationStarting(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PrimaryViewAnimationStarting(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::Core::CoreInputView, winrt::Windows::UI::ViewManagement::Core::CoreInputViewAnimationStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PrimaryViewAnimationStarting(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrimaryViewAnimationStarting(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewAnimationStartingEventArgs> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewAnimationStartingEventArgs>
    {
        int32_t __stdcall get_Occlusions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>>(this->shim().Occlusions());
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
        int32_t __stdcall get_AnimationDuration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().AnimationDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewHidingEventArgs> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewHidingEventArgs>
    {
        int32_t __stdcall TryCancel(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryCancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion>
    {
        int32_t __stdcall get_OccludingRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().OccludingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OcclusionKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusionKind>(this->shim().OcclusionKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs>
    {
        int32_t __stdcall get_Occlusions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>>(this->shim().Occlusions());
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
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewShowingEventArgs> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewShowingEventArgs>
    {
        int32_t __stdcall TryCancel(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryCancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewStatics> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewStatics>
    {
        int32_t __stdcall GetForCurrentView(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::ViewManagement::Core::CoreInputView>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewStatics2> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewStatics2>
    {
        int32_t __stdcall GetForUIContext(void* context, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::ViewManagement::Core::CoreInputView>(this->shim().GetForUIContext(*reinterpret_cast<winrt::Windows::UI::UIContext const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs>
    {
        int32_t __stdcall get_Origin(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().Origin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Direction(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection>(this->shim().Direction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TransferHandled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferHandled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransferHandled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().TransferHandled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeepPrimaryViewVisible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeepPrimaryViewVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeepPrimaryViewVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().KeepPrimaryViewVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::IUISettingsController> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::IUISettingsController>
    {
        int32_t __stdcall SetAdvancedEffectsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetAdvancedEffectsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetAnimationsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetAnimationsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetAutoHideScrollBars(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetAutoHideScrollBars(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetMessageDuration(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetMessageDuration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetTextScaleFactor(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetTextScaleFactor(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::ViewManagement::Core::IUISettingsControllerStatics> : produce_base<D, winrt::Windows::UI::ViewManagement::Core::IUISettingsControllerStatics>
    {
        int32_t __stdcall RequestDefaultAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::ViewManagement::Core::UISettingsController>>(this->shim().RequestDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::ViewManagement::Core
{
    inline auto CoreFrameworkInputView::GetForUIContext(winrt::Windows::UI::UIContext const& context)
    {
        return impl::call_factory<CoreFrameworkInputView, ICoreFrameworkInputViewStatics>([&](ICoreFrameworkInputViewStatics const& f) { return f.GetForUIContext(context); });
    }
    inline auto CoreFrameworkInputView::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView(*)(ICoreFrameworkInputViewStatics const&), CoreFrameworkInputView, ICoreFrameworkInputViewStatics>([](ICoreFrameworkInputViewStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto CoreInputView::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::ViewManagement::Core::CoreInputView(*)(ICoreInputViewStatics const&), CoreInputView, ICoreInputViewStatics>([](ICoreInputViewStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto CoreInputView::GetForUIContext(winrt::Windows::UI::UIContext const& context)
    {
        return impl::call_factory<CoreInputView, ICoreInputViewStatics2>([&](ICoreInputViewStatics2 const& f) { return f.GetForUIContext(context); });
    }
    inline auto UISettingsController::RequestDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::ViewManagement::Core::UISettingsController>(*)(IUISettingsControllerStatics const&), UISettingsController, IUISettingsControllerStatics>([](IUISettingsControllerStatics const& f) { return f.RequestDefaultAsync(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewAnimationStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewOcclusionsChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputView2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputView3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputView4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputView5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewAnimationStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewHidingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewShowingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::IUISettingsController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::IUISettingsControllerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputViewAnimationStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreFrameworkInputViewOcclusionsChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreInputView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreInputViewAnimationStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreInputViewHidingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreInputViewShowingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::ViewManagement::Core::UISettingsController> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
