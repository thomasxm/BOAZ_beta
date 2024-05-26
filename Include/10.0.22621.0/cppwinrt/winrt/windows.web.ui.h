// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_UI_H
#define WINRT_Windows_Web_UI_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Web.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Web.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.Web.UI.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControl<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->get_Source(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::Source(winrt::Windows::Foundation::Uri const& source) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->put_Source(*(void**)(&source)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_UI_IWebViewControl<D>::DocumentTitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->get_DocumentTitle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_IWebViewControl<D>::CanGoBack() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->get_CanGoBack(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_IWebViewControl<D>::CanGoForward() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->get_CanGoForward(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::DefaultBackgroundColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->put_DefaultBackgroundColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Web_UI_IWebViewControl<D>::DefaultBackgroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->get_DefaultBackgroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_IWebViewControl<D>::ContainsFullScreenElement() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->get_ContainsFullScreenElement(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::UI::WebViewControlSettings) consume_Windows_Web_UI_IWebViewControl<D>::Settings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->get_Settings(&value));
        return winrt::Windows::Web::UI::WebViewControlSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::UI::WebViewControlDeferredPermissionRequest>) consume_Windows_Web_UI_IWebViewControl<D>::DeferredPermissionRequests() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->get_DeferredPermissionRequests(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::UI::WebViewControlDeferredPermissionRequest>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::GoForward() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->GoForward());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::GoBack() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->GoBack());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::Refresh() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->Refresh());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::Navigate(winrt::Windows::Foundation::Uri const& source) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->Navigate(*(void**)(&source)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::NavigateToString(param::hstring const& text) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->NavigateToString(*(void**)(&text)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::NavigateToLocalStreamUri(winrt::Windows::Foundation::Uri const& source, winrt::Windows::Web::IUriToStreamResolver const& streamResolver) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->NavigateToLocalStreamUri(*(void**)(&source), *(void**)(&streamResolver)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::NavigateWithHttpRequestMessage(winrt::Windows::Web::Http::HttpRequestMessage const& requestMessage) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->NavigateWithHttpRequestMessage(*(void**)(&requestMessage)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Web_UI_IWebViewControl<D>::InvokeScriptAsync(param::hstring const& scriptName, param::async_iterable<hstring> const& arguments) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->InvokeScriptAsync(*(void**)(&scriptName), *(void**)(&arguments), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Web_UI_IWebViewControl<D>::CapturePreviewToStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->CapturePreviewToStreamAsync(*(void**)(&stream), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::DataTransfer::DataPackage>) consume_Windows_Web_UI_IWebViewControl<D>::CaptureSelectedContentToDataPackageAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->CaptureSelectedContentToDataPackageAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::DataTransfer::DataPackage>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControl<D>::BuildLocalStreamUri(param::hstring const& contentIdentifier, param::hstring const& relativePath) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->BuildLocalStreamUri(*(void**)(&contentIdentifier), *(void**)(&relativePath), &result));
        return winrt::Windows::Foundation::Uri{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::GetDeferredPermissionRequestById(uint32_t id, winrt::Windows::Web::UI::WebViewControlDeferredPermissionRequest& result) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->GetDeferredPermissionRequestById(id, impl::bind_out(result)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::NavigationStarting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_NavigationStarting(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::NavigationStarting_revoker consume_Windows_Web_UI_IWebViewControl<D>::NavigationStarting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, NavigationStarting_revoker>(this, NavigationStarting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::NavigationStarting(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_NavigationStarting(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::ContentLoading(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlContentLoadingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_ContentLoading(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::ContentLoading_revoker consume_Windows_Web_UI_IWebViewControl<D>::ContentLoading(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlContentLoadingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ContentLoading_revoker>(this, ContentLoading(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::ContentLoading(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_ContentLoading(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::DOMContentLoaded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_DOMContentLoaded(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::DOMContentLoaded_revoker consume_Windows_Web_UI_IWebViewControl<D>::DOMContentLoaded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DOMContentLoaded_revoker>(this, DOMContentLoaded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::DOMContentLoaded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_DOMContentLoaded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::NavigationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_NavigationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::NavigationCompleted_revoker consume_Windows_Web_UI_IWebViewControl<D>::NavigationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, NavigationCompleted_revoker>(this, NavigationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::NavigationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_NavigationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationStarting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_FrameNavigationStarting(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationStarting_revoker consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationStarting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, FrameNavigationStarting_revoker>(this, FrameNavigationStarting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationStarting(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_FrameNavigationStarting(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::FrameContentLoading(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlContentLoadingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_FrameContentLoading(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::FrameContentLoading_revoker consume_Windows_Web_UI_IWebViewControl<D>::FrameContentLoading(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlContentLoadingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, FrameContentLoading_revoker>(this, FrameContentLoading(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::FrameContentLoading(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_FrameContentLoading(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::FrameDOMContentLoaded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_FrameDOMContentLoaded(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::FrameDOMContentLoaded_revoker consume_Windows_Web_UI_IWebViewControl<D>::FrameDOMContentLoaded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, FrameDOMContentLoaded_revoker>(this, FrameDOMContentLoaded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::FrameDOMContentLoaded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_FrameDOMContentLoaded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_FrameNavigationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationCompleted_revoker consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, FrameNavigationCompleted_revoker>(this, FrameNavigationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_FrameNavigationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::ScriptNotify(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlScriptNotifyEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_ScriptNotify(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::ScriptNotify_revoker consume_Windows_Web_UI_IWebViewControl<D>::ScriptNotify(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlScriptNotifyEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ScriptNotify_revoker>(this, ScriptNotify(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::ScriptNotify(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_ScriptNotify(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::LongRunningScriptDetected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlLongRunningScriptDetectedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_LongRunningScriptDetected(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::LongRunningScriptDetected_revoker consume_Windows_Web_UI_IWebViewControl<D>::LongRunningScriptDetected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlLongRunningScriptDetectedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, LongRunningScriptDetected_revoker>(this, LongRunningScriptDetected(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::LongRunningScriptDetected(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_LongRunningScriptDetected(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::UnsafeContentWarningDisplaying(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_UnsafeContentWarningDisplaying(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::UnsafeContentWarningDisplaying_revoker consume_Windows_Web_UI_IWebViewControl<D>::UnsafeContentWarningDisplaying(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, UnsafeContentWarningDisplaying_revoker>(this, UnsafeContentWarningDisplaying(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::UnsafeContentWarningDisplaying(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_UnsafeContentWarningDisplaying(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::UnviewableContentIdentified(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlUnviewableContentIdentifiedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_UnviewableContentIdentified(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::UnviewableContentIdentified_revoker consume_Windows_Web_UI_IWebViewControl<D>::UnviewableContentIdentified(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlUnviewableContentIdentifiedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, UnviewableContentIdentified_revoker>(this, UnviewableContentIdentified(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::UnviewableContentIdentified(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_UnviewableContentIdentified(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::PermissionRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlPermissionRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_PermissionRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::PermissionRequested_revoker consume_Windows_Web_UI_IWebViewControl<D>::PermissionRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlPermissionRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PermissionRequested_revoker>(this, PermissionRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::PermissionRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_PermissionRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::UnsupportedUriSchemeIdentified(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlUnsupportedUriSchemeIdentifiedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_UnsupportedUriSchemeIdentified(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::UnsupportedUriSchemeIdentified_revoker consume_Windows_Web_UI_IWebViewControl<D>::UnsupportedUriSchemeIdentified(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlUnsupportedUriSchemeIdentifiedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, UnsupportedUriSchemeIdentified_revoker>(this, UnsupportedUriSchemeIdentified(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::UnsupportedUriSchemeIdentified(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_UnsupportedUriSchemeIdentified(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::NewWindowRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNewWindowRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_NewWindowRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::NewWindowRequested_revoker consume_Windows_Web_UI_IWebViewControl<D>::NewWindowRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNewWindowRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, NewWindowRequested_revoker>(this, NewWindowRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::NewWindowRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_NewWindowRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::ContainsFullScreenElementChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_ContainsFullScreenElementChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::ContainsFullScreenElementChanged_revoker consume_Windows_Web_UI_IWebViewControl<D>::ContainsFullScreenElementChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ContainsFullScreenElementChanged_revoker>(this, ContainsFullScreenElementChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::ContainsFullScreenElementChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_ContainsFullScreenElementChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_UI_IWebViewControl<D>::WebResourceRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlWebResourceRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->add_WebResourceRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::WebResourceRequested_revoker consume_Windows_Web_UI_IWebViewControl<D>::WebResourceRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlWebResourceRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, WebResourceRequested_revoker>(this, WebResourceRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl<D>::WebResourceRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl)->remove_WebResourceRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControl2<D>::AddInitializeScript(param::hstring const& script) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControl2)->AddInitializeScript(*(void**)(&script)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControlContentLoadingEventArgs<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlContentLoadingEventArgs)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControlDOMContentLoadedEventArgs<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Web_UI_IWebViewControlDeferredPermissionRequest<D>::Id() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlDeferredPermissionRequest)->get_Id(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControlDeferredPermissionRequest<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlDeferredPermissionRequest)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::UI::WebViewControlPermissionType) consume_Windows_Web_UI_IWebViewControlDeferredPermissionRequest<D>::PermissionType() const
    {
        winrt::Windows::Web::UI::WebViewControlPermissionType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlDeferredPermissionRequest)->get_PermissionType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlDeferredPermissionRequest<D>::Allow() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlDeferredPermissionRequest)->Allow());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlDeferredPermissionRequest<D>::Deny() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlDeferredPermissionRequest)->Deny());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Web_UI_IWebViewControlLongRunningScriptDetectedEventArgs<D>::ExecutionTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs)->get_ExecutionTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_IWebViewControlLongRunningScriptDetectedEventArgs<D>::StopPageScriptExecution() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs)->get_StopPageScriptExecution(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlLongRunningScriptDetectedEventArgs<D>::StopPageScriptExecution(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs)->put_StopPageScriptExecution(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControlNavigationCompletedEventArgs<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_IWebViewControlNavigationCompletedEventArgs<D>::IsSuccess() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs)->get_IsSuccess(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::WebErrorStatus) consume_Windows_Web_UI_IWebViewControlNavigationCompletedEventArgs<D>::WebErrorStatus() const
    {
        winrt::Windows::Web::WebErrorStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs)->get_WebErrorStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControlNavigationStartingEventArgs<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlNavigationStartingEventArgs)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_IWebViewControlNavigationStartingEventArgs<D>::Cancel() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlNavigationStartingEventArgs)->get_Cancel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlNavigationStartingEventArgs<D>::Cancel(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlNavigationStartingEventArgs)->put_Cancel(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs<D>::Referrer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs)->get_Referrer(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::UI::IWebViewControl) consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs2<D>::NewWindow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2)->get_NewWindow(&value));
        return winrt::Windows::Web::UI::IWebViewControl{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs2<D>::NewWindow(winrt::Windows::Web::UI::IWebViewControl const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2)->put_NewWindow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs2<D>::GetDeferral() const
    {
        void* deferral{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2)->GetDeferral(&deferral));
        return winrt::Windows::Foundation::Deferral{ deferral, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::Id() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlPermissionRequest)->get_Id(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlPermissionRequest)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::UI::WebViewControlPermissionType) consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::PermissionType() const
    {
        winrt::Windows::Web::UI::WebViewControlPermissionType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlPermissionRequest)->get_PermissionType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::UI::WebViewControlPermissionState) consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::State() const
    {
        winrt::Windows::Web::UI::WebViewControlPermissionState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlPermissionRequest)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::Defer() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlPermissionRequest)->Defer());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::Allow() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlPermissionRequest)->Allow());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::Deny() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlPermissionRequest)->Deny());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::UI::WebViewControlPermissionRequest) consume_Windows_Web_UI_IWebViewControlPermissionRequestedEventArgs<D>::PermissionRequest() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs)->get_PermissionRequest(&value));
        return winrt::Windows::Web::UI::WebViewControlPermissionRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControlScriptNotifyEventArgs<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlScriptNotifyEventArgs)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_UI_IWebViewControlScriptNotifyEventArgs<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlScriptNotifyEventArgs)->get_Value(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlSettings<D>::IsJavaScriptEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlSettings)->put_IsJavaScriptEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_IWebViewControlSettings<D>::IsJavaScriptEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlSettings)->get_IsJavaScriptEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlSettings<D>::IsIndexedDBEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlSettings)->put_IsIndexedDBEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_IWebViewControlSettings<D>::IsIndexedDBEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlSettings)->get_IsIndexedDBEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlSettings<D>::IsScriptNotifyAllowed(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlSettings)->put_IsScriptNotifyAllowed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_IWebViewControlSettings<D>::IsScriptNotifyAllowed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlSettings)->get_IsScriptNotifyAllowed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_UI_IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControlUnviewableContentIdentifiedEventArgs<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_UI_IWebViewControlUnviewableContentIdentifiedEventArgs<D>::Referrer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs)->get_Referrer(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_UI_IWebViewControlUnviewableContentIdentifiedEventArgs<D>::MediaType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs)->get_MediaType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Web_UI_IWebViewControlWebResourceRequestedEventArgs<D>::GetDeferral() const
    {
        void* deferral{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs)->GetDeferral(&deferral));
        return winrt::Windows::Foundation::Deferral{ deferral, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Http::HttpRequestMessage) consume_Windows_Web_UI_IWebViewControlWebResourceRequestedEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs)->get_Request(&value));
        return winrt::Windows::Web::Http::HttpRequestMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_UI_IWebViewControlWebResourceRequestedEventArgs<D>::Response(winrt::Windows::Web::Http::HttpResponseMessage const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs)->put_Response(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Http::HttpResponseMessage) consume_Windows_Web_UI_IWebViewControlWebResourceRequestedEventArgs<D>::Response() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs)->get_Response(&value));
        return winrt::Windows::Web::Http::HttpResponseMessage{ value, take_ownership_from_abi };
    }
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControl> : produce_base<D, winrt::Windows::Web::UI::IWebViewControl>
    {
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Source(void* source) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Source(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentTitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DocumentTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanGoBack(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanGoBack());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanGoForward(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanGoForward());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DefaultBackgroundColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DefaultBackgroundColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DefaultBackgroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().DefaultBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContainsFullScreenElement(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ContainsFullScreenElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Settings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::UI::WebViewControlSettings>(this->shim().Settings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeferredPermissionRequests(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::UI::WebViewControlDeferredPermissionRequest>>(this->shim().DeferredPermissionRequests());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GoForward() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GoForward();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GoBack() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GoBack();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Refresh() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Refresh();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Navigate(void* source) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Navigate(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NavigateToString(void* text) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NavigateToString(*reinterpret_cast<hstring const*>(&text));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NavigateToLocalStreamUri(void* source, void* streamResolver) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NavigateToLocalStreamUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&source), *reinterpret_cast<winrt::Windows::Web::IUriToStreamResolver const*>(&streamResolver));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NavigateWithHttpRequestMessage(void* requestMessage) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NavigateWithHttpRequestMessage(*reinterpret_cast<winrt::Windows::Web::Http::HttpRequestMessage const*>(&requestMessage));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InvokeScriptAsync(void* scriptName, void* arguments, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().InvokeScriptAsync(*reinterpret_cast<hstring const*>(&scriptName), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&arguments)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CapturePreviewToStreamAsync(void* stream, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().CapturePreviewToStreamAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CaptureSelectedContentToDataPackageAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::DataTransfer::DataPackage>>(this->shim().CaptureSelectedContentToDataPackageAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall BuildLocalStreamUri(void* contentIdentifier, void* relativePath, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Uri>(this->shim().BuildLocalStreamUri(*reinterpret_cast<hstring const*>(&contentIdentifier), *reinterpret_cast<hstring const*>(&relativePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferredPermissionRequestById(uint32_t id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            this->shim().GetDeferredPermissionRequestById(id, *reinterpret_cast<winrt::Windows::Web::UI::WebViewControlDeferredPermissionRequest*>(result));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_NavigationStarting(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NavigationStarting(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NavigationStarting(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NavigationStarting(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ContentLoading(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ContentLoading(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlContentLoadingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ContentLoading(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentLoading(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DOMContentLoaded(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DOMContentLoaded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DOMContentLoaded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DOMContentLoaded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_NavigationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NavigationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NavigationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NavigationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_FrameNavigationStarting(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FrameNavigationStarting(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FrameNavigationStarting(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FrameNavigationStarting(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_FrameContentLoading(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FrameContentLoading(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlContentLoadingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FrameContentLoading(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FrameContentLoading(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_FrameDOMContentLoaded(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FrameDOMContentLoaded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FrameDOMContentLoaded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FrameDOMContentLoaded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_FrameNavigationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FrameNavigationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FrameNavigationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FrameNavigationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ScriptNotify(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ScriptNotify(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlScriptNotifyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ScriptNotify(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScriptNotify(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_LongRunningScriptDetected(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().LongRunningScriptDetected(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlLongRunningScriptDetectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LongRunningScriptDetected(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LongRunningScriptDetected(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_UnsafeContentWarningDisplaying(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().UnsafeContentWarningDisplaying(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_UnsafeContentWarningDisplaying(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnsafeContentWarningDisplaying(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_UnviewableContentIdentified(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().UnviewableContentIdentified(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlUnviewableContentIdentifiedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_UnviewableContentIdentified(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnviewableContentIdentified(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PermissionRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PermissionRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlPermissionRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PermissionRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PermissionRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_UnsupportedUriSchemeIdentified(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().UnsupportedUriSchemeIdentified(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlUnsupportedUriSchemeIdentifiedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_UnsupportedUriSchemeIdentified(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnsupportedUriSchemeIdentified(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_NewWindowRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NewWindowRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlNewWindowRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NewWindowRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NewWindowRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ContainsFullScreenElementChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ContainsFullScreenElementChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ContainsFullScreenElementChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContainsFullScreenElementChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_WebResourceRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().WebResourceRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::UI::IWebViewControl, winrt::Windows::Web::UI::WebViewControlWebResourceRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_WebResourceRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WebResourceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControl2> : produce_base<D, winrt::Windows::Web::UI::IWebViewControl2>
    {
        int32_t __stdcall AddInitializeScript(void* script) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInitializeScript(*reinterpret_cast<hstring const*>(&script));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlContentLoadingEventArgs> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlContentLoadingEventArgs>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlDeferredPermissionRequest> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlDeferredPermissionRequest>
    {
        int32_t __stdcall get_Id(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PermissionType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::UI::WebViewControlPermissionType>(this->shim().PermissionType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Allow() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Allow();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Deny() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Deny();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs>
    {
        int32_t __stdcall get_ExecutionTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().ExecutionTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StopPageScriptExecution(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().StopPageScriptExecution());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StopPageScriptExecution(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopPageScriptExecution(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSuccess(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSuccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WebErrorStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::WebErrorStatus>(this->shim().WebErrorStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlNavigationStartingEventArgs> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlNavigationStartingEventArgs>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
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
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Referrer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Referrer());
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
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2>
    {
        int32_t __stdcall get_NewWindow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::UI::IWebViewControl>(this->shim().NewWindow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NewWindow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NewWindow(*reinterpret_cast<winrt::Windows::Web::UI::IWebViewControl const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** deferral) noexcept final try
        {
            clear_abi(deferral);
            typename D::abi_guard guard(this->shim());
            *deferral = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlPermissionRequest> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlPermissionRequest>
    {
        int32_t __stdcall get_Id(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PermissionType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::UI::WebViewControlPermissionType>(this->shim().PermissionType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::UI::WebViewControlPermissionState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Defer() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Defer();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Allow() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Allow();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Deny() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Deny();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs>
    {
        int32_t __stdcall get_PermissionRequest(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::UI::WebViewControlPermissionRequest>(this->shim().PermissionRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlScriptNotifyEventArgs> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlScriptNotifyEventArgs>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Value(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlSettings> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlSettings>
    {
        int32_t __stdcall put_IsJavaScriptEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsJavaScriptEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsJavaScriptEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsJavaScriptEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsIndexedDBEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsIndexedDBEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsIndexedDBEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsIndexedDBEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsScriptNotifyAllowed(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsScriptNotifyAllowed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsScriptNotifyAllowed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsScriptNotifyAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
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
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Referrer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Referrer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MediaType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs> : produce_base<D, winrt::Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs>
    {
        int32_t __stdcall GetDeferral(void** deferral) noexcept final try
        {
            clear_abi(deferral);
            typename D::abi_guard guard(this->shim());
            *deferral = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Http::HttpRequestMessage>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Response(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Response(*reinterpret_cast<winrt::Windows::Web::Http::HttpResponseMessage const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Response(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Http::HttpResponseMessage>(this->shim().Response());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Web::UI
{
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControl2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlContentLoadingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlDeferredPermissionRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlNavigationStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlPermissionRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlScriptNotifyEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlContentLoadingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlDeferredPermissionRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlLongRunningScriptDetectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlNavigationStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlNewWindowRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlPermissionRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlPermissionRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlScriptNotifyEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlUnsupportedUriSchemeIdentifiedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlUnviewableContentIdentifiedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::UI::WebViewControlWebResourceRequestedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
