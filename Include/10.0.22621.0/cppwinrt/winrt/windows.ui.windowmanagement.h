// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_WindowManagement_H
#define WINRT_Windows_UI_WindowManagement_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.WindowManagement.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::UIContentRoot) consume_Windows_UI_WindowManagement_IAppWindow<D>::Content() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->get_Content(&value));
        return winrt::Windows::UI::UIContentRoot{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::DispatcherQueue) consume_Windows_UI_WindowManagement_IAppWindow<D>::DispatcherQueue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->get_DispatcherQueue(&value));
        return winrt::Windows::System::DispatcherQueue{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::AppWindowFrame) consume_Windows_UI_WindowManagement_IAppWindow<D>::Frame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->get_Frame(&value));
        return winrt::Windows::UI::WindowManagement::AppWindowFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindow<D>::IsVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->get_IsVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_WindowManagement_IAppWindow<D>::PersistedStateId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->get_PersistedStateId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindow<D>::PersistedStateId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->put_PersistedStateId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::AppWindowPresenter) consume_Windows_UI_WindowManagement_IAppWindow<D>::Presenter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->get_Presenter(&value));
        return winrt::Windows::UI::WindowManagement::AppWindowPresenter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_WindowManagement_IAppWindow<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindow<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::AppWindowTitleBar) consume_Windows_UI_WindowManagement_IAppWindow<D>::TitleBar() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->get_TitleBar(&value));
        return winrt::Windows::UI::WindowManagement::AppWindowTitleBar{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::UIContext) consume_Windows_UI_WindowManagement_IAppWindow<D>::UIContext() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->get_UIContext(&value));
        return winrt::Windows::UI::UIContext{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::WindowingEnvironment) consume_Windows_UI_WindowManagement_IAppWindow<D>::WindowingEnvironment() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->get_WindowingEnvironment(&value));
        return winrt::Windows::UI::WindowManagement::WindowingEnvironment{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_WindowManagement_IAppWindow<D>::CloseAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->CloseAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::AppWindowPlacement) consume_Windows_UI_WindowManagement_IAppWindow<D>::GetPlacement() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->GetPlacement(&result));
        return winrt::Windows::UI::WindowManagement::AppWindowPlacement{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::DisplayRegion>) consume_Windows_UI_WindowManagement_IAppWindow<D>::GetDisplayRegions() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->GetDisplayRegions(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::DisplayRegion>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestMoveToDisplayRegion(winrt::Windows::UI::WindowManagement::DisplayRegion const& displayRegion) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->RequestMoveToDisplayRegion(*(void**)(&displayRegion)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestMoveAdjacentToCurrentView() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->RequestMoveAdjacentToCurrentView());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestMoveAdjacentToWindow(winrt::Windows::UI::WindowManagement::AppWindow const& anchorWindow) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->RequestMoveAdjacentToWindow(*(void**)(&anchorWindow)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestMoveRelativeToWindowContent(winrt::Windows::UI::WindowManagement::AppWindow const& anchorWindow, winrt::Windows::Foundation::Point const& contentOffset) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->RequestMoveRelativeToWindowContent(*(void**)(&anchorWindow), impl::bind_in(contentOffset)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestMoveRelativeToCurrentViewContent(winrt::Windows::Foundation::Point const& contentOffset) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->RequestMoveRelativeToCurrentViewContent(impl::bind_in(contentOffset)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestMoveRelativeToDisplayRegion(winrt::Windows::UI::WindowManagement::DisplayRegion const& displayRegion, winrt::Windows::Foundation::Point const& displayRegionOffset) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->RequestMoveRelativeToDisplayRegion(*(void**)(&displayRegion), impl::bind_in(displayRegionOffset)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestSize(winrt::Windows::Foundation::Size const& frameSize) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->RequestSize(impl::bind_in(frameSize)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_UI_WindowManagement_IAppWindow<D>::TryShowAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->TryShowAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_WindowManagement_IAppWindow<D>::Changed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::AppWindow, winrt::Windows::UI::WindowManagement::AppWindowChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->add_Changed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_WindowManagement_IAppWindow<D>::Changed_revoker consume_Windows_UI_WindowManagement_IAppWindow<D>::Changed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::AppWindow, winrt::Windows::UI::WindowManagement::AppWindowChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindow<D>::Changed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->remove_Changed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_WindowManagement_IAppWindow<D>::Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::AppWindow, winrt::Windows::UI::WindowManagement::AppWindowClosedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->add_Closed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_WindowManagement_IAppWindow<D>::Closed_revoker consume_Windows_UI_WindowManagement_IAppWindow<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::AppWindow, winrt::Windows::UI::WindowManagement::AppWindowClosedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindow<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_WindowManagement_IAppWindow<D>::CloseRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::AppWindow, winrt::Windows::UI::WindowManagement::AppWindowCloseRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->add_CloseRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_WindowManagement_IAppWindow<D>::CloseRequested_revoker consume_Windows_UI_WindowManagement_IAppWindow<D>::CloseRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::AppWindow, winrt::Windows::UI::WindowManagement::AppWindowCloseRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CloseRequested_revoker>(this, CloseRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindow<D>::CloseRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindow)->remove_CloseRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidAvailableWindowPresentationsChange() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidAvailableWindowPresentationsChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidDisplayRegionsChange() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidDisplayRegionsChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidFrameChange() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidFrameChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidSizeChange() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidSizeChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidTitleBarChange() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidTitleBarChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidVisibilityChange() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidVisibilityChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidWindowingEnvironmentChange() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidWindowingEnvironmentChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidWindowPresentationChange() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidWindowPresentationChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowCloseRequestedEventArgs<D>::Cancel() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs)->get_Cancel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowCloseRequestedEventArgs<D>::Cancel(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs)->put_Cancel(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_UI_WindowManagement_IAppWindowCloseRequestedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::AppWindowClosedReason) consume_Windows_UI_WindowManagement_IAppWindowClosedEventArgs<D>::Reason() const
    {
        winrt::Windows::UI::WindowManagement::AppWindowClosedReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowClosedEventArgs)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Composition::IVisualElement>) consume_Windows_UI_WindowManagement_IAppWindowFrame<D>::DragRegionVisuals() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowFrame)->get_DragRegionVisuals(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Composition::IVisualElement>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::AppWindowFrameStyle) consume_Windows_UI_WindowManagement_IAppWindowFrameStyle<D>::GetFrameStyle() const
    {
        winrt::Windows::UI::WindowManagement::AppWindowFrameStyle result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowFrameStyle)->GetFrameStyle(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowFrameStyle<D>::SetFrameStyle(winrt::Windows::UI::WindowManagement::AppWindowFrameStyle const& frameStyle) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowFrameStyle)->SetFrameStyle(static_cast<int32_t>(frameStyle)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::DisplayRegion) consume_Windows_UI_WindowManagement_IAppWindowPlacement<D>::DisplayRegion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowPlacement)->get_DisplayRegion(&value));
        return winrt::Windows::UI::WindowManagement::DisplayRegion{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_WindowManagement_IAppWindowPlacement<D>::Offset() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowPlacement)->get_Offset(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_WindowManagement_IAppWindowPlacement<D>::Size() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowPlacement)->get_Size(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::AppWindowPresentationKind) consume_Windows_UI_WindowManagement_IAppWindowPresentationConfiguration<D>::Kind() const
    {
        winrt::Windows::UI::WindowManagement::AppWindowPresentationKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::AppWindowPresentationConfiguration) consume_Windows_UI_WindowManagement_IAppWindowPresenter<D>::GetConfiguration() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowPresenter)->GetConfiguration(&result));
        return winrt::Windows::UI::WindowManagement::AppWindowPresentationConfiguration{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowPresenter<D>::IsPresentationSupported(winrt::Windows::UI::WindowManagement::AppWindowPresentationKind const& presentationKind) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowPresenter)->IsPresentationSupported(static_cast<int32_t>(presentationKind), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowPresenter<D>::RequestPresentation(winrt::Windows::UI::WindowManagement::AppWindowPresentationConfiguration const& configuration) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowPresenter)->RequestPresentation(*(void**)(&configuration), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowPresenter<D>::RequestPresentation(winrt::Windows::UI::WindowManagement::AppWindowPresentationKind const& presentationKind) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowPresenter)->RequestPresentationByKind(static_cast<int32_t>(presentationKind), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::WindowManagement::AppWindow>) consume_Windows_UI_WindowManagement_IAppWindowStatics<D>::TryCreateAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowStatics)->TryCreateAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::WindowManagement::AppWindow>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowStatics<D>::ClearAllPersistedState() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowStatics)->ClearAllPersistedState());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowStatics<D>::ClearPersistedState(param::hstring const& key) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowStatics)->ClearPersistedState(*(void**)(&key)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::BackgroundColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_BackgroundColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::BackgroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->put_BackgroundColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonBackgroundColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonBackgroundColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonBackgroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonBackgroundColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonForegroundColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonForegroundColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonForegroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonForegroundColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonHoverBackgroundColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonHoverBackgroundColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonHoverBackgroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonHoverBackgroundColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonHoverForegroundColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonHoverForegroundColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonHoverForegroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonHoverForegroundColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonInactiveBackgroundColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonInactiveBackgroundColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonInactiveBackgroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonInactiveBackgroundColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonInactiveForegroundColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonInactiveForegroundColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonInactiveForegroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonInactiveForegroundColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonPressedBackgroundColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonPressedBackgroundColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonPressedBackgroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonPressedBackgroundColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonPressedForegroundColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonPressedForegroundColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonPressedForegroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonPressedForegroundColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ExtendsContentIntoTitleBar() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ExtendsContentIntoTitleBar(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ExtendsContentIntoTitleBar(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ExtendsContentIntoTitleBar(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ForegroundColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ForegroundColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ForegroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ForegroundColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::InactiveBackgroundColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_InactiveBackgroundColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::InactiveBackgroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->put_InactiveBackgroundColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::InactiveForegroundColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_InactiveForegroundColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::InactiveForegroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->put_InactiveForegroundColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::IsVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->get_IsVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion>) consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::GetTitleBarOcclusions() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBar)->GetTitleBarOcclusions(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_WindowManagement_IAppWindowTitleBarOcclusion<D>::OccludingRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion)->get_OccludingRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::AppWindowTitleBarVisibility) consume_Windows_UI_WindowManagement_IAppWindowTitleBarVisibility<D>::GetPreferredVisibility() const
    {
        winrt::Windows::UI::WindowManagement::AppWindowTitleBarVisibility result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBarVisibility)->GetPreferredVisibility(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IAppWindowTitleBarVisibility<D>::SetPreferredVisibility(winrt::Windows::UI::WindowManagement::AppWindowTitleBarVisibility const& visibilityMode) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IAppWindowTitleBarVisibility)->SetPreferredVisibility(static_cast<int32_t>(visibilityMode)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_WindowManagement_IDisplayRegion<D>::DisplayMonitorDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IDisplayRegion)->get_DisplayMonitorDeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IDisplayRegion<D>::IsVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IDisplayRegion)->get_IsVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_WindowManagement_IDisplayRegion<D>::WorkAreaOffset() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IDisplayRegion)->get_WorkAreaOffset(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_WindowManagement_IDisplayRegion<D>::WorkAreaSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IDisplayRegion)->get_WorkAreaSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::WindowingEnvironment) consume_Windows_UI_WindowManagement_IDisplayRegion<D>::WindowingEnvironment() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IDisplayRegion)->get_WindowingEnvironment(&value));
        return winrt::Windows::UI::WindowManagement::WindowingEnvironment{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_WindowManagement_IDisplayRegion<D>::Changed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::DisplayRegion, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IDisplayRegion)->add_Changed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_WindowManagement_IDisplayRegion<D>::Changed_revoker consume_Windows_UI_WindowManagement_IDisplayRegion<D>::Changed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::DisplayRegion, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IDisplayRegion<D>::Changed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IDisplayRegion)->remove_Changed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IFullScreenPresentationConfiguration<D>::IsExclusive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IFullScreenPresentationConfiguration)->get_IsExclusive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IFullScreenPresentationConfiguration<D>::IsExclusive(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IFullScreenPresentationConfiguration)->put_IsExclusive(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowId>) consume_Windows_UI_WindowManagement_IWindowServicesStatics<D>::FindAllTopLevelWindowIds() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IWindowServicesStatics)->FindAllTopLevelWindowIds(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowId>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IWindowingEnvironment)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::WindowingEnvironmentKind) consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::Kind() const
    {
        winrt::Windows::UI::WindowManagement::WindowingEnvironmentKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IWindowingEnvironment)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::DisplayRegion>) consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::GetDisplayRegions() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IWindowingEnvironment)->GetDisplayRegions(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::DisplayRegion>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::Changed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::WindowingEnvironment, winrt::Windows::UI::WindowManagement::WindowingEnvironmentChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IWindowingEnvironment)->add_Changed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::Changed_revoker consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::Changed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::WindowingEnvironment, winrt::Windows::UI::WindowManagement::WindowingEnvironmentChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::Changed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IWindowingEnvironment)->remove_Changed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::WindowingEnvironment) consume_Windows_UI_WindowManagement_IWindowingEnvironmentAddedEventArgs<D>::WindowingEnvironment() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IWindowingEnvironmentAddedEventArgs)->get_WindowingEnvironment(&value));
        return winrt::Windows::UI::WindowManagement::WindowingEnvironment{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::WindowingEnvironment) consume_Windows_UI_WindowManagement_IWindowingEnvironmentRemovedEventArgs<D>::WindowingEnvironment() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IWindowingEnvironmentRemovedEventArgs)->get_WindowingEnvironment(&value));
        return winrt::Windows::UI::WindowManagement::WindowingEnvironment{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::WindowingEnvironment>) consume_Windows_UI_WindowManagement_IWindowingEnvironmentStatics<D>::FindAll() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IWindowingEnvironmentStatics)->FindAll(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::WindowingEnvironment>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::WindowingEnvironment>) consume_Windows_UI_WindowManagement_IWindowingEnvironmentStatics<D>::FindAll(winrt::Windows::UI::WindowManagement::WindowingEnvironmentKind const& kind) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::WindowManagement::IWindowingEnvironmentStatics)->FindAllWithKind(static_cast<int32_t>(kind), &result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::WindowingEnvironment>{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindow> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindow>
    {
        int32_t __stdcall get_Content(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::UIContentRoot>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DispatcherQueue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::DispatcherQueue>(this->shim().DispatcherQueue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Frame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WindowManagement::AppWindowFrame>(this->shim().Frame());
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
        int32_t __stdcall get_PersistedStateId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PersistedStateId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PersistedStateId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PersistedStateId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Presenter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WindowManagement::AppWindowPresenter>(this->shim().Presenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TitleBar(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WindowManagement::AppWindowTitleBar>(this->shim().TitleBar());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UIContext(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::UIContext>(this->shim().UIContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WindowingEnvironment(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WindowManagement::WindowingEnvironment>(this->shim().WindowingEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CloseAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().CloseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPlacement(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::WindowManagement::AppWindowPlacement>(this->shim().GetPlacement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDisplayRegions(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::DisplayRegion>>(this->shim().GetDisplayRegions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestMoveToDisplayRegion(void* displayRegion) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestMoveToDisplayRegion(*reinterpret_cast<winrt::Windows::UI::WindowManagement::DisplayRegion const*>(&displayRegion));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestMoveAdjacentToCurrentView() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestMoveAdjacentToCurrentView();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestMoveAdjacentToWindow(void* anchorWindow) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestMoveAdjacentToWindow(*reinterpret_cast<winrt::Windows::UI::WindowManagement::AppWindow const*>(&anchorWindow));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestMoveRelativeToWindowContent(void* anchorWindow, winrt::Windows::Foundation::Point contentOffset) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestMoveRelativeToWindowContent(*reinterpret_cast<winrt::Windows::UI::WindowManagement::AppWindow const*>(&anchorWindow), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&contentOffset));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestMoveRelativeToCurrentViewContent(winrt::Windows::Foundation::Point contentOffset) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestMoveRelativeToCurrentViewContent(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&contentOffset));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestMoveRelativeToDisplayRegion(void* displayRegion, winrt::Windows::Foundation::Point displayRegionOffset) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestMoveRelativeToDisplayRegion(*reinterpret_cast<winrt::Windows::UI::WindowManagement::DisplayRegion const*>(&displayRegion), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&displayRegionOffset));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestSize(winrt::Windows::Foundation::Size frameSize) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestSize(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&frameSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryShowAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryShowAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Changed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::AppWindow, winrt::Windows::UI::WindowManagement::AppWindowChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Changed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Closed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::AppWindow, winrt::Windows::UI::WindowManagement::AppWindowClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CloseRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CloseRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::AppWindow, winrt::Windows::UI::WindowManagement::AppWindowCloseRequestedEventArgs> const*>(&handler)));
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
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs>
    {
        int32_t __stdcall get_DidAvailableWindowPresentationsChange(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DidAvailableWindowPresentationsChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DidDisplayRegionsChange(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DidDisplayRegionsChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DidFrameChange(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DidFrameChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DidSizeChange(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DidSizeChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DidTitleBarChange(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DidTitleBarChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DidVisibilityChange(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DidVisibilityChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DidWindowingEnvironmentChange(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DidWindowingEnvironmentChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DidWindowPresentationChange(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DidWindowPresentationChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs>
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
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindowClosedEventArgs> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindowClosedEventArgs>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WindowManagement::AppWindowClosedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindowFrame> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindowFrame>
    {
        int32_t __stdcall get_DragRegionVisuals(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Composition::IVisualElement>>(this->shim().DragRegionVisuals());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindowFrameStyle> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindowFrameStyle>
    {
        int32_t __stdcall GetFrameStyle(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::WindowManagement::AppWindowFrameStyle>(this->shim().GetFrameStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetFrameStyle(int32_t frameStyle) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetFrameStyle(*reinterpret_cast<winrt::Windows::UI::WindowManagement::AppWindowFrameStyle const*>(&frameStyle));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindowPlacement> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindowPlacement>
    {
        int32_t __stdcall get_DisplayRegion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WindowManagement::DisplayRegion>(this->shim().DisplayRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Offset(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().Offset());
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WindowManagement::AppWindowPresentationKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfigurationFactory> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfigurationFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindowPresenter> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindowPresenter>
    {
        int32_t __stdcall GetConfiguration(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::WindowManagement::AppWindowPresentationConfiguration>(this->shim().GetConfiguration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsPresentationSupported(int32_t presentationKind, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsPresentationSupported(*reinterpret_cast<winrt::Windows::UI::WindowManagement::AppWindowPresentationKind const*>(&presentationKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPresentation(void* configuration, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().RequestPresentation(*reinterpret_cast<winrt::Windows::UI::WindowManagement::AppWindowPresentationConfiguration const*>(&configuration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPresentationByKind(int32_t presentationKind, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().RequestPresentation(*reinterpret_cast<winrt::Windows::UI::WindowManagement::AppWindowPresentationKind const*>(&presentationKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindowStatics> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindowStatics>
    {
        int32_t __stdcall TryCreateAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::WindowManagement::AppWindow>>(this->shim().TryCreateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearAllPersistedState() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClearAllPersistedState();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearPersistedState(void* key) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClearPersistedState(*reinterpret_cast<hstring const*>(&key));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindowTitleBar> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindowTitleBar>
    {
        int32_t __stdcall get_BackgroundColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BackgroundColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BackgroundColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ButtonBackgroundColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ButtonBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ButtonBackgroundColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ButtonBackgroundColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ButtonForegroundColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ButtonForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ButtonForegroundColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ButtonForegroundColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ButtonHoverBackgroundColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ButtonHoverBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ButtonHoverBackgroundColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ButtonHoverBackgroundColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ButtonHoverForegroundColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ButtonHoverForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ButtonHoverForegroundColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ButtonHoverForegroundColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ButtonInactiveBackgroundColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ButtonInactiveBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ButtonInactiveBackgroundColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ButtonInactiveBackgroundColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ButtonInactiveForegroundColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ButtonInactiveForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ButtonInactiveForegroundColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ButtonInactiveForegroundColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ButtonPressedBackgroundColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ButtonPressedBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ButtonPressedBackgroundColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ButtonPressedBackgroundColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ButtonPressedForegroundColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ButtonPressedForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ButtonPressedForegroundColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ButtonPressedForegroundColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendsContentIntoTitleBar(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ExtendsContentIntoTitleBar());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExtendsContentIntoTitleBar(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExtendsContentIntoTitleBar(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ForegroundColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().ForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ForegroundColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ForegroundColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InactiveBackgroundColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().InactiveBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InactiveBackgroundColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InactiveBackgroundColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InactiveForegroundColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().InactiveForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InactiveForegroundColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InactiveForegroundColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
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
        int32_t __stdcall GetTitleBarOcclusions(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion>>(this->shim().GetTitleBarOcclusions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion>
    {
        int32_t __stdcall get_OccludingRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().OccludingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IAppWindowTitleBarVisibility> : produce_base<D, winrt::Windows::UI::WindowManagement::IAppWindowTitleBarVisibility>
    {
        int32_t __stdcall GetPreferredVisibility(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::WindowManagement::AppWindowTitleBarVisibility>(this->shim().GetPreferredVisibility());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPreferredVisibility(int32_t visibilityMode) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPreferredVisibility(*reinterpret_cast<winrt::Windows::UI::WindowManagement::AppWindowTitleBarVisibility const*>(&visibilityMode));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::ICompactOverlayPresentationConfiguration> : produce_base<D, winrt::Windows::UI::WindowManagement::ICompactOverlayPresentationConfiguration>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IDefaultPresentationConfiguration> : produce_base<D, winrt::Windows::UI::WindowManagement::IDefaultPresentationConfiguration>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IDisplayRegion> : produce_base<D, winrt::Windows::UI::WindowManagement::IDisplayRegion>
    {
        int32_t __stdcall get_DisplayMonitorDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayMonitorDeviceId());
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
        int32_t __stdcall get_WorkAreaOffset(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().WorkAreaOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WorkAreaSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().WorkAreaSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WindowingEnvironment(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WindowManagement::WindowingEnvironment>(this->shim().WindowingEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Changed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::DisplayRegion, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Changed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IFullScreenPresentationConfiguration> : produce_base<D, winrt::Windows::UI::WindowManagement::IFullScreenPresentationConfiguration>
    {
        int32_t __stdcall get_IsExclusive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsExclusive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsExclusive(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsExclusive(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IWindowServicesStatics> : produce_base<D, winrt::Windows::UI::WindowManagement::IWindowServicesStatics>
    {
        int32_t __stdcall FindAllTopLevelWindowIds(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowId>>(this->shim().FindAllTopLevelWindowIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IWindowingEnvironment> : produce_base<D, winrt::Windows::UI::WindowManagement::IWindowingEnvironment>
    {
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WindowManagement::WindowingEnvironmentKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDisplayRegions(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::DisplayRegion>>(this->shim().GetDisplayRegions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Changed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::WindowManagement::WindowingEnvironment, winrt::Windows::UI::WindowManagement::WindowingEnvironmentChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Changed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IWindowingEnvironmentAddedEventArgs> : produce_base<D, winrt::Windows::UI::WindowManagement::IWindowingEnvironmentAddedEventArgs>
    {
        int32_t __stdcall get_WindowingEnvironment(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WindowManagement::WindowingEnvironment>(this->shim().WindowingEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs> : produce_base<D, winrt::Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IWindowingEnvironmentRemovedEventArgs> : produce_base<D, winrt::Windows::UI::WindowManagement::IWindowingEnvironmentRemovedEventArgs>
    {
        int32_t __stdcall get_WindowingEnvironment(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::WindowManagement::WindowingEnvironment>(this->shim().WindowingEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::WindowManagement::IWindowingEnvironmentStatics> : produce_base<D, winrt::Windows::UI::WindowManagement::IWindowingEnvironmentStatics>
    {
        int32_t __stdcall FindAll(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::WindowingEnvironment>>(this->shim().FindAll());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllWithKind(int32_t kind, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::WindowingEnvironment>>(this->shim().FindAll(*reinterpret_cast<winrt::Windows::UI::WindowManagement::WindowingEnvironmentKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement
{
    inline auto AppWindow::TryCreateAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::WindowManagement::AppWindow>(*)(IAppWindowStatics const&), AppWindow, IAppWindowStatics>([](IAppWindowStatics const& f) { return f.TryCreateAsync(); });
    }
    inline auto AppWindow::ClearAllPersistedState()
    {
        impl::call_factory_cast<void(*)(IAppWindowStatics const&), AppWindow, IAppWindowStatics>([](IAppWindowStatics const& f) { return f.ClearAllPersistedState(); });
    }
    inline auto AppWindow::ClearPersistedState(param::hstring const& key)
    {
        impl::call_factory<AppWindow, IAppWindowStatics>([&](IAppWindowStatics const& f) { return f.ClearPersistedState(key); });
    }
    inline CompactOverlayPresentationConfiguration::CompactOverlayPresentationConfiguration() :
        CompactOverlayPresentationConfiguration(impl::call_factory_cast<CompactOverlayPresentationConfiguration(*)(winrt::Windows::Foundation::IActivationFactory const&), CompactOverlayPresentationConfiguration>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CompactOverlayPresentationConfiguration>(); }))
    {
    }
    inline DefaultPresentationConfiguration::DefaultPresentationConfiguration() :
        DefaultPresentationConfiguration(impl::call_factory_cast<DefaultPresentationConfiguration(*)(winrt::Windows::Foundation::IActivationFactory const&), DefaultPresentationConfiguration>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DefaultPresentationConfiguration>(); }))
    {
    }
    inline FullScreenPresentationConfiguration::FullScreenPresentationConfiguration() :
        FullScreenPresentationConfiguration(impl::call_factory_cast<FullScreenPresentationConfiguration(*)(winrt::Windows::Foundation::IActivationFactory const&), FullScreenPresentationConfiguration>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<FullScreenPresentationConfiguration>(); }))
    {
    }
    inline auto WindowServices::FindAllTopLevelWindowIds()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowId>(*)(IWindowServicesStatics const&), WindowServices, IWindowServicesStatics>([](IWindowServicesStatics const& f) { return f.FindAllTopLevelWindowIds(); });
    }
    inline auto WindowingEnvironment::FindAll()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::WindowingEnvironment>(*)(IWindowingEnvironmentStatics const&), WindowingEnvironment, IWindowingEnvironmentStatics>([](IWindowingEnvironmentStatics const& f) { return f.FindAll(); });
    }
    inline auto WindowingEnvironment::FindAll(winrt::Windows::UI::WindowManagement::WindowingEnvironmentKind const& kind)
    {
        return impl::call_factory<WindowingEnvironment, IWindowingEnvironmentStatics>([&](IWindowingEnvironmentStatics const& f) { return f.FindAll(kind); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindow> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowFrameStyle> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowPlacement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfigurationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowPresenter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowTitleBar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowTitleBarVisibility> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::ICompactOverlayPresentationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IDefaultPresentationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IDisplayRegion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IFullScreenPresentationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IWindowServicesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IWindowingEnvironment> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IWindowingEnvironmentAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IWindowingEnvironmentRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::IWindowingEnvironmentStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindow> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowCloseRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowPlacement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowPresentationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowPresenter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowTitleBar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::CompactOverlayPresentationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::DefaultPresentationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::DisplayRegion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::FullScreenPresentationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::WindowServices> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::WindowingEnvironment> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::WindowingEnvironmentAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::WindowingEnvironmentChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::WindowManagement::WindowingEnvironmentRemovedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
