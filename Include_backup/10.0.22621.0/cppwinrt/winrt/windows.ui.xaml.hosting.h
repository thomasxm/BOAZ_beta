// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Hosting_H
#define WINRT_Windows_UI_Xaml_Hosting_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Xaml.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.WindowManagement.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Primitives.2.h"
#include "winrt/impl/Windows.UI.Xaml.Hosting.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Xaml_Hosting_IDesignerAppExitedEventArgs<D>::ExitCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs)->get_ExitCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::AppUserModelId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesignerAppManager)->get_AppUserModelId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::DesignerAppExited(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Hosting::DesignerAppManager, winrt::Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesignerAppManager)->add_DesignerAppExited(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::DesignerAppExited_revoker consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::DesignerAppExited(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Hosting::DesignerAppManager, winrt::Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DesignerAppExited_revoker>(this, DesignerAppExited(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::DesignerAppExited(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesignerAppManager)->remove_DesignerAppExited(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Hosting::DesignerAppView>) consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::CreateNewViewAsync(winrt::Windows::UI::Xaml::Hosting::DesignerAppViewState const& initialViewState, winrt::Windows::Foundation::Size const& initialViewSize) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesignerAppManager)->CreateNewViewAsync(static_cast<int32_t>(initialViewState), impl::bind_in(initialViewSize), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Hosting::DesignerAppView>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::LoadObjectIntoAppAsync(param::hstring const& dllName, winrt::guid const& classId, param::hstring const& initializationData) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesignerAppManager)->LoadObjectIntoAppAsync(*(void**)(&dllName), impl::bind_in(classId), *(void**)(&initializationData), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Hosting::DesignerAppManager) consume_Windows_UI_Xaml_Hosting_IDesignerAppManagerFactory<D>::Create(param::hstring const& appUserModelId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory)->Create(*(void**)(&appUserModelId), &value));
        return winrt::Windows::UI::Xaml::Hosting::DesignerAppManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Hosting_IDesignerAppView<D>::ApplicationViewId() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesignerAppView)->get_ApplicationViewId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Hosting_IDesignerAppView<D>::AppUserModelId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesignerAppView)->get_AppUserModelId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Hosting::DesignerAppViewState) consume_Windows_UI_Xaml_Hosting_IDesignerAppView<D>::ViewState() const
    {
        winrt::Windows::UI::Xaml::Hosting::DesignerAppViewState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesignerAppView)->get_ViewState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Xaml_Hosting_IDesignerAppView<D>::ViewSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesignerAppView)->get_ViewSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_Xaml_Hosting_IDesignerAppView<D>::UpdateViewAsync(winrt::Windows::UI::Xaml::Hosting::DesignerAppViewState const& viewState, winrt::Windows::Foundation::Size const& viewSize) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesignerAppView)->UpdateViewAsync(static_cast<int32_t>(viewState), impl::bind_in(viewSize), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::Content() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->get_Content(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::Content(winrt::Windows::UI::Xaml::UIElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->put_Content(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::HasFocus() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->get_HasFocus(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::TakeFocusRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->add_TakeFocusRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::TakeFocusRequested_revoker consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::TakeFocusRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TakeFocusRequested_revoker>(this, TakeFocusRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::TakeFocusRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->remove_TakeFocusRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::GotFocus(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->add_GotFocus(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::GotFocus_revoker consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::GotFocus(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::GotFocus(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->remove_GotFocus(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult) consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::NavigateFocus(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest const& request) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->NavigateFocus(*(void**)(&request), &result));
        return winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSource) consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSourceFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest) consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSourceGotFocusEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs)->get_Request(&value));
        return winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest) consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSourceTakeFocusRequestedEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs)->get_Request(&value));
        return winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Visual) consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics<D>::GetElementVisual(winrt::Windows::UI::Xaml::UIElement const& element) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics)->GetElementVisual(*(void**)(&element), &result));
        return winrt::Windows::UI::Composition::Visual{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Visual) consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics<D>::GetElementChildVisual(winrt::Windows::UI::Xaml::UIElement const& element) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics)->GetElementChildVisual(*(void**)(&element), &result));
        return winrt::Windows::UI::Composition::Visual{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics<D>::SetElementChildVisual(winrt::Windows::UI::Xaml::UIElement const& element, winrt::Windows::UI::Composition::Visual const& visual) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics)->SetElementChildVisual(*(void**)(&element), *(void**)(&visual)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::CompositionPropertySet) consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics<D>::GetScrollViewerManipulationPropertySet(winrt::Windows::UI::Xaml::Controls::ScrollViewer const& scrollViewer) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics)->GetScrollViewerManipulationPropertySet(*(void**)(&scrollViewer), &result));
        return winrt::Windows::UI::Composition::CompositionPropertySet{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics2<D>::SetImplicitShowAnimation(winrt::Windows::UI::Xaml::UIElement const& element, winrt::Windows::UI::Composition::ICompositionAnimationBase const& animation) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2)->SetImplicitShowAnimation(*(void**)(&element), *(void**)(&animation)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics2<D>::SetImplicitHideAnimation(winrt::Windows::UI::Xaml::UIElement const& element, winrt::Windows::UI::Composition::ICompositionAnimationBase const& animation) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2)->SetImplicitHideAnimation(*(void**)(&element), *(void**)(&animation)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics2<D>::SetIsTranslationEnabled(winrt::Windows::UI::Xaml::UIElement const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2)->SetIsTranslationEnabled(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::CompositionPropertySet) consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics2<D>::GetPointerPositionPropertySet(winrt::Windows::UI::Xaml::UIElement const& targetElement) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2)->GetPointerPositionPropertySet(*(void**)(&targetElement), &result));
        return winrt::Windows::UI::Composition::CompositionPropertySet{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics3<D>::SetAppWindowContent(winrt::Windows::UI::WindowManagement::AppWindow const& appWindow, winrt::Windows::UI::Xaml::UIElement const& xamlContent) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3)->SetAppWindowContent(*(void**)(&appWindow), *(void**)(&xamlContent)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics3<D>::GetAppWindowContent(winrt::Windows::UI::WindowManagement::AppWindow const& appWindow) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3)->GetAppWindowContent(*(void**)(&appWindow), &result));
        return winrt::Windows::UI::Xaml::UIElement{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Hosting::WindowsXamlManager) consume_Windows_UI_Xaml_Hosting_IWindowsXamlManagerStatics<D>::InitializeForCurrentThread() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics)->InitializeForCurrentThread(&result));
        return winrt::Windows::UI::Xaml::Hosting::WindowsXamlManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason) consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequest<D>::Reason() const
    {
        winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequest<D>::HintRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest)->get_HintRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequest<D>::CorrelationId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest)->get_CorrelationId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest) consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequestFactory<D>::CreateInstance(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory)->CreateInstance(static_cast<int32_t>(reason), &value));
        return winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest) consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequestFactory<D>::CreateInstanceWithHintRect(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason, winrt::Windows::Foundation::Rect const& hintRect) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory)->CreateInstanceWithHintRect(static_cast<int32_t>(reason), impl::bind_in(hintRect), &value));
        return winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest) consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequestFactory<D>::CreateInstanceWithHintRectAndCorrelationId(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason, winrt::Windows::Foundation::Rect const& hintRect, winrt::guid const& correlationId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory)->CreateInstanceWithHintRectAndCorrelationId(static_cast<int32_t>(reason), impl::bind_in(hintRect), impl::bind_in(correlationId), &value));
        return winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationResult<D>::WasFocusMoved() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult)->get_WasFocusMoved(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult) consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationResultFactory<D>::CreateInstance(bool focusMoved) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory)->CreateInstance(focusMoved, &value));
        return winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::RootElement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter)->get_RootElement(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::RootElement(winrt::Windows::UI::Xaml::UIElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter)->put_RootElement(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::ThemeKey() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter)->get_ThemeKey(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::ThemeKey(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter)->put_ThemeKey(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::ThemeResourcesXaml() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter)->get_ThemeResourcesXaml(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::ThemeResourcesXaml(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter)->put_ThemeResourcesXaml(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::SetSize(int32_t width, int32_t height) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter)->SetSize(width, height));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::Render() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter)->Render());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::Present() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter)->Present());
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterHost<D>::ResolveFileResource(param::hstring const& path) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost)->ResolveFileResource(*(void**)(&path), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterHost2<D>::GetGenericXamlFilePath() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2)->GetGenericXamlFilePath(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterHost3<D>::ResolveDictionaryResource(winrt::Windows::UI::Xaml::ResourceDictionary const& dictionary, winrt::Windows::Foundation::IInspectable const& dictionaryKey, winrt::Windows::Foundation::IInspectable const& suggestedValue) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3)->ResolveDictionaryResource(*(void**)(&dictionary), *(void**)(&dictionaryKey), *(void**)(&suggestedValue), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics<D>::CompleteTimelinesAutomatically() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics)->get_CompleteTimelinesAutomatically(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics<D>::CompleteTimelinesAutomatically(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics)->put_CompleteTimelinesAutomatically(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics<D>::SetHost(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost const& host) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics)->SetHost(*(void**)(&host)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics<D>::NotifyWindowSizeChanged() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics)->NotifyWindowSizeChanged());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics2<D>::GetFlyoutPlacementTargetInfo(winrt::Windows::UI::Xaml::FrameworkElement const& placementTarget, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& preferredPlacement, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode& targetPreferredPlacement, bool& allowFallbacks) const
    {
        winrt::Windows::Foundation::Rect returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2)->GetFlyoutPlacementTargetInfo(*(void**)(&placementTarget), static_cast<int32_t>(preferredPlacement), reinterpret_cast<int32_t*>(&targetPreferredPlacement), &allowFallbacks, put_abi(returnValue)));
        return returnValue;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics2<D>::GetFlyoutPlacement(winrt::Windows::Foundation::Rect const& placementTargetBounds, winrt::Windows::Foundation::Size const& controlSize, winrt::Windows::Foundation::Size const& minControlSize, winrt::Windows::Foundation::Rect const& containerRect, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& targetPreferredPlacement, bool allowFallbacks, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode& chosenPlacement) const
    {
        winrt::Windows::Foundation::Rect returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2)->GetFlyoutPlacement(impl::bind_in(placementTargetBounds), impl::bind_in(controlSize), impl::bind_in(minControlSize), impl::bind_in(containerRect), static_cast<int32_t>(targetPreferredPlacement), allowFallbacks, reinterpret_cast<int32_t*>(&chosenPlacement), put_abi(returnValue)));
        return returnValue;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs>
    {
        int32_t __stdcall get_ExitCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExitCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IDesignerAppManager> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IDesignerAppManager>
    {
        int32_t __stdcall get_AppUserModelId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppUserModelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_DesignerAppExited(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DesignerAppExited(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Hosting::DesignerAppManager, winrt::Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DesignerAppExited(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesignerAppExited(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall CreateNewViewAsync(int32_t initialViewState, winrt::Windows::Foundation::Size initialViewSize, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Hosting::DesignerAppView>>(this->shim().CreateNewViewAsync(*reinterpret_cast<winrt::Windows::UI::Xaml::Hosting::DesignerAppViewState const*>(&initialViewState), *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&initialViewSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadObjectIntoAppAsync(void* dllName, winrt::guid classId, void* initializationData, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().LoadObjectIntoAppAsync(*reinterpret_cast<hstring const*>(&dllName), *reinterpret_cast<winrt::guid const*>(&classId), *reinterpret_cast<hstring const*>(&initializationData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory>
    {
        int32_t __stdcall Create(void* appUserModelId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Hosting::DesignerAppManager>(this->shim().Create(*reinterpret_cast<hstring const*>(&appUserModelId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IDesignerAppView> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IDesignerAppView>
    {
        int32_t __stdcall get_ApplicationViewId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ApplicationViewId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppUserModelId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppUserModelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ViewState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Hosting::DesignerAppViewState>(this->shim().ViewState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ViewSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().ViewSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateViewAsync(int32_t viewState, winrt::Windows::Foundation::Size viewSize, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().UpdateViewAsync(*reinterpret_cast<winrt::Windows::UI::Xaml::Hosting::DesignerAppViewState const*>(&viewState), *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&viewSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource>
    {
        int32_t __stdcall get_Content(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Content(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Content(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasFocus(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasFocus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_TakeFocusRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TakeFocusRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TakeFocusRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TakeFocusRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_GotFocus(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_GotFocus(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GotFocus(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall NavigateFocus(void* request, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult>(this->shim().NavigateFocus(*reinterpret_cast<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSource>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreview> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreview>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics>
    {
        int32_t __stdcall GetElementVisual(void* element, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::Visual>(this->shim().GetElementVisual(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetElementChildVisual(void* element, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::Visual>(this->shim().GetElementChildVisual(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetElementChildVisual(void* element, void* visual) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetElementChildVisual(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element), *reinterpret_cast<winrt::Windows::UI::Composition::Visual const*>(&visual));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetScrollViewerManipulationPropertySet(void* scrollViewer, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::CompositionPropertySet>(this->shim().GetScrollViewerManipulationPropertySet(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ScrollViewer const*>(&scrollViewer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2>
    {
        int32_t __stdcall SetImplicitShowAnimation(void* element, void* animation) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetImplicitShowAnimation(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element), *reinterpret_cast<winrt::Windows::UI::Composition::ICompositionAnimationBase const*>(&animation));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetImplicitHideAnimation(void* element, void* animation) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetImplicitHideAnimation(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element), *reinterpret_cast<winrt::Windows::UI::Composition::ICompositionAnimationBase const*>(&animation));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetIsTranslationEnabled(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetIsTranslationEnabled(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPointerPositionPropertySet(void* targetElement, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::CompositionPropertySet>(this->shim().GetPointerPositionPropertySet(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&targetElement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3>
    {
        int32_t __stdcall SetAppWindowContent(void* appWindow, void* xamlContent) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetAppWindowContent(*reinterpret_cast<winrt::Windows::UI::WindowManagement::AppWindow const*>(&appWindow), *reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&xamlContent));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAppWindowContent(void* appWindow, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().GetAppWindowContent(*reinterpret_cast<winrt::Windows::UI::WindowManagement::AppWindow const*>(&appWindow)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IWindowsXamlManager> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IWindowsXamlManager>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics>
    {
        int32_t __stdcall InitializeForCurrentThread(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Hosting::WindowsXamlManager>(this->shim().InitializeForCurrentThread());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason>(this->shim().Reason());
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
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory>
    {
        int32_t __stdcall CreateInstance(int32_t reason, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const*>(&reason)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstanceWithHintRect(int32_t reason, winrt::Windows::Foundation::Rect hintRect, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest>(this->shim().CreateInstanceWithHintRect(*reinterpret_cast<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const*>(&reason), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&hintRect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstanceWithHintRectAndCorrelationId(int32_t reason, winrt::Windows::Foundation::Rect hintRect, winrt::guid correlationId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest>(this->shim().CreateInstanceWithHintRectAndCorrelationId(*reinterpret_cast<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const*>(&reason), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&hintRect), *reinterpret_cast<winrt::guid const*>(&correlationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult>
    {
        int32_t __stdcall get_WasFocusMoved(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().WasFocusMoved());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory>
    {
        int32_t __stdcall CreateInstance(bool focusMoved, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult>(this->shim().CreateInstance(focusMoved));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter>
    {
        int32_t __stdcall get_RootElement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().RootElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RootElement(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RootElement(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ThemeKey(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ThemeKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ThemeKey(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ThemeKey(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ThemeResourcesXaml(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ThemeResourcesXaml());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ThemeResourcesXaml(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ThemeResourcesXaml(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetSize(int32_t width, int32_t height) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSize(width, height);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Render() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Render();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Present() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Present();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost>
    {
        int32_t __stdcall ResolveFileResource(void* path, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().ResolveFileResource(*reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2>
    {
        int32_t __stdcall GetGenericXamlFilePath(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetGenericXamlFilePath());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3>
    {
        int32_t __stdcall ResolveDictionaryResource(void* dictionary, void* dictionaryKey, void* suggestedValue, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().ResolveDictionaryResource(*reinterpret_cast<winrt::Windows::UI::Xaml::ResourceDictionary const*>(&dictionary), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dictionaryKey), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&suggestedValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics>
    {
        int32_t __stdcall get_CompleteTimelinesAutomatically(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CompleteTimelinesAutomatically());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CompleteTimelinesAutomatically(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CompleteTimelinesAutomatically(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetHost(void* host) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetHost(*reinterpret_cast<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost const*>(&host));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifyWindowSizeChanged() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyWindowSizeChanged();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2>
    {
        int32_t __stdcall GetFlyoutPlacementTargetInfo(void* placementTarget, int32_t preferredPlacement, int32_t* targetPreferredPlacement, bool* allowFallbacks, winrt::Windows::Foundation::Rect* returnValue) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Foundation::Rect>(this->shim().GetFlyoutPlacementTargetInfo(*reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&placementTarget), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const*>(&preferredPlacement), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode*>(targetPreferredPlacement), *allowFallbacks));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFlyoutPlacement(winrt::Windows::Foundation::Rect placementTargetBounds, winrt::Windows::Foundation::Size controlSize, winrt::Windows::Foundation::Size minControlSize, winrt::Windows::Foundation::Rect containerRect, int32_t targetPreferredPlacement, bool allowFallbacks, int32_t* chosenPlacement, winrt::Windows::Foundation::Rect* returnValue) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Foundation::Rect>(this->shim().GetFlyoutPlacement(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&placementTargetBounds), *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&controlSize), *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&minControlSize), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&containerRect), *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const*>(&targetPreferredPlacement), allowFallbacks, *reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode*>(chosenPlacement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Hosting
{
    inline DesignerAppManager::DesignerAppManager(param::hstring const& appUserModelId) :
        DesignerAppManager(impl::call_factory<DesignerAppManager, IDesignerAppManagerFactory>([&](IDesignerAppManagerFactory const& f) { return f.Create(appUserModelId); }))
    {
    }
    inline DesktopWindowXamlSource::DesktopWindowXamlSource()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<DesktopWindowXamlSource, IDesktopWindowXamlSourceFactory>([&](IDesktopWindowXamlSourceFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto ElementCompositionPreview::GetElementVisual(winrt::Windows::UI::Xaml::UIElement const& element)
    {
        return impl::call_factory<ElementCompositionPreview, IElementCompositionPreviewStatics>([&](IElementCompositionPreviewStatics const& f) { return f.GetElementVisual(element); });
    }
    inline auto ElementCompositionPreview::GetElementChildVisual(winrt::Windows::UI::Xaml::UIElement const& element)
    {
        return impl::call_factory<ElementCompositionPreview, IElementCompositionPreviewStatics>([&](IElementCompositionPreviewStatics const& f) { return f.GetElementChildVisual(element); });
    }
    inline auto ElementCompositionPreview::SetElementChildVisual(winrt::Windows::UI::Xaml::UIElement const& element, winrt::Windows::UI::Composition::Visual const& visual)
    {
        impl::call_factory<ElementCompositionPreview, IElementCompositionPreviewStatics>([&](IElementCompositionPreviewStatics const& f) { return f.SetElementChildVisual(element, visual); });
    }
    inline auto ElementCompositionPreview::GetScrollViewerManipulationPropertySet(winrt::Windows::UI::Xaml::Controls::ScrollViewer const& scrollViewer)
    {
        return impl::call_factory<ElementCompositionPreview, IElementCompositionPreviewStatics>([&](IElementCompositionPreviewStatics const& f) { return f.GetScrollViewerManipulationPropertySet(scrollViewer); });
    }
    inline auto ElementCompositionPreview::SetImplicitShowAnimation(winrt::Windows::UI::Xaml::UIElement const& element, winrt::Windows::UI::Composition::ICompositionAnimationBase const& animation)
    {
        impl::call_factory<ElementCompositionPreview, IElementCompositionPreviewStatics2>([&](IElementCompositionPreviewStatics2 const& f) { return f.SetImplicitShowAnimation(element, animation); });
    }
    inline auto ElementCompositionPreview::SetImplicitHideAnimation(winrt::Windows::UI::Xaml::UIElement const& element, winrt::Windows::UI::Composition::ICompositionAnimationBase const& animation)
    {
        impl::call_factory<ElementCompositionPreview, IElementCompositionPreviewStatics2>([&](IElementCompositionPreviewStatics2 const& f) { return f.SetImplicitHideAnimation(element, animation); });
    }
    inline auto ElementCompositionPreview::SetIsTranslationEnabled(winrt::Windows::UI::Xaml::UIElement const& element, bool value)
    {
        impl::call_factory<ElementCompositionPreview, IElementCompositionPreviewStatics2>([&](IElementCompositionPreviewStatics2 const& f) { return f.SetIsTranslationEnabled(element, value); });
    }
    inline auto ElementCompositionPreview::GetPointerPositionPropertySet(winrt::Windows::UI::Xaml::UIElement const& targetElement)
    {
        return impl::call_factory<ElementCompositionPreview, IElementCompositionPreviewStatics2>([&](IElementCompositionPreviewStatics2 const& f) { return f.GetPointerPositionPropertySet(targetElement); });
    }
    inline auto ElementCompositionPreview::SetAppWindowContent(winrt::Windows::UI::WindowManagement::AppWindow const& appWindow, winrt::Windows::UI::Xaml::UIElement const& xamlContent)
    {
        impl::call_factory<ElementCompositionPreview, IElementCompositionPreviewStatics3>([&](IElementCompositionPreviewStatics3 const& f) { return f.SetAppWindowContent(appWindow, xamlContent); });
    }
    inline auto ElementCompositionPreview::GetAppWindowContent(winrt::Windows::UI::WindowManagement::AppWindow const& appWindow)
    {
        return impl::call_factory<ElementCompositionPreview, IElementCompositionPreviewStatics3>([&](IElementCompositionPreviewStatics3 const& f) { return f.GetAppWindowContent(appWindow); });
    }
    inline auto WindowsXamlManager::InitializeForCurrentThread()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::Hosting::WindowsXamlManager(*)(IWindowsXamlManagerStatics const&), WindowsXamlManager, IWindowsXamlManagerStatics>([](IWindowsXamlManagerStatics const& f) { return f.InitializeForCurrentThread(); });
    }
    inline XamlSourceFocusNavigationRequest::XamlSourceFocusNavigationRequest(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason) :
        XamlSourceFocusNavigationRequest(impl::call_factory<XamlSourceFocusNavigationRequest, IXamlSourceFocusNavigationRequestFactory>([&](IXamlSourceFocusNavigationRequestFactory const& f) { return f.CreateInstance(reason); }))
    {
    }
    inline XamlSourceFocusNavigationRequest::XamlSourceFocusNavigationRequest(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason, winrt::Windows::Foundation::Rect const& hintRect) :
        XamlSourceFocusNavigationRequest(impl::call_factory<XamlSourceFocusNavigationRequest, IXamlSourceFocusNavigationRequestFactory>([&](IXamlSourceFocusNavigationRequestFactory const& f) { return f.CreateInstanceWithHintRect(reason, hintRect); }))
    {
    }
    inline XamlSourceFocusNavigationRequest::XamlSourceFocusNavigationRequest(winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason, winrt::Windows::Foundation::Rect const& hintRect, winrt::guid const& correlationId) :
        XamlSourceFocusNavigationRequest(impl::call_factory<XamlSourceFocusNavigationRequest, IXamlSourceFocusNavigationRequestFactory>([&](IXamlSourceFocusNavigationRequestFactory const& f) { return f.CreateInstanceWithHintRectAndCorrelationId(reason, hintRect, correlationId); }))
    {
    }
    inline XamlSourceFocusNavigationResult::XamlSourceFocusNavigationResult(bool focusMoved) :
        XamlSourceFocusNavigationResult(impl::call_factory<XamlSourceFocusNavigationResult, IXamlSourceFocusNavigationResultFactory>([&](IXamlSourceFocusNavigationResultFactory const& f) { return f.CreateInstance(focusMoved); }))
    {
    }
    inline auto XamlUIPresenter::CompleteTimelinesAutomatically()
    {
        return impl::call_factory_cast<bool(*)(IXamlUIPresenterStatics const&), XamlUIPresenter, IXamlUIPresenterStatics>([](IXamlUIPresenterStatics const& f) { return f.CompleteTimelinesAutomatically(); });
    }
    inline auto XamlUIPresenter::CompleteTimelinesAutomatically(bool value)
    {
        impl::call_factory<XamlUIPresenter, IXamlUIPresenterStatics>([&](IXamlUIPresenterStatics const& f) { return f.CompleteTimelinesAutomatically(value); });
    }
    inline auto XamlUIPresenter::SetHost(winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost const& host)
    {
        impl::call_factory<XamlUIPresenter, IXamlUIPresenterStatics>([&](IXamlUIPresenterStatics const& f) { return f.SetHost(host); });
    }
    inline auto XamlUIPresenter::NotifyWindowSizeChanged()
    {
        impl::call_factory_cast<void(*)(IXamlUIPresenterStatics const&), XamlUIPresenter, IXamlUIPresenterStatics>([](IXamlUIPresenterStatics const& f) { return f.NotifyWindowSizeChanged(); });
    }
    inline auto XamlUIPresenter::GetFlyoutPlacementTargetInfo(winrt::Windows::UI::Xaml::FrameworkElement const& placementTarget, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& preferredPlacement, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode& targetPreferredPlacement, bool& allowFallbacks)
    {
        return impl::call_factory<XamlUIPresenter, IXamlUIPresenterStatics2>([&](IXamlUIPresenterStatics2 const& f) { return f.GetFlyoutPlacementTargetInfo(placementTarget, preferredPlacement, targetPreferredPlacement, allowFallbacks); });
    }
    inline auto XamlUIPresenter::GetFlyoutPlacement(winrt::Windows::Foundation::Rect const& placementTargetBounds, winrt::Windows::Foundation::Size const& controlSize, winrt::Windows::Foundation::Size const& minControlSize, winrt::Windows::Foundation::Rect const& containerRect, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& targetPreferredPlacement, bool allowFallbacks, winrt::Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode& chosenPlacement)
    {
        return impl::call_factory<XamlUIPresenter, IXamlUIPresenterStatics2>([&](IXamlUIPresenterStatics2 const& f) { return f.GetFlyoutPlacement(placementTargetBounds, controlSize, minControlSize, containerRect, targetPreferredPlacement, allowFallbacks, chosenPlacement); });
    }
    template <typename D, typename... Interfaces>
    struct DesktopWindowXamlSourceT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource, winrt::Windows::Foundation::IClosable>,
        impl::base<D, DesktopWindowXamlSource>
    {
        using composable = DesktopWindowXamlSource;
    protected:
        DesktopWindowXamlSourceT()
        {
            impl::call_factory<DesktopWindowXamlSource, IDesktopWindowXamlSourceFactory>([&](IDesktopWindowXamlSourceFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesignerAppManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesignerAppView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IWindowsXamlManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::DesignerAppManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::DesignerAppView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::ElementCompositionPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::WindowsXamlManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Hosting::XamlUIPresenter> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
