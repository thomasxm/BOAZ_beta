// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Capture_H
#define WINRT_Windows_Media_Capture_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Capture.Core.2.h"
#include "winrt/impl/Windows.Media.Capture.Frames.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Media.Devices.2.h"
#include "winrt/impl/Windows.Media.Effects.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Security.Authentication.Web.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.WindowManagement.2.h"
#include "winrt/impl/Windows.Media.Capture.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CapturedFrame) consume_Windows_Media_Capture_IAdvancedCapturedPhoto<D>::Frame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAdvancedCapturedPhoto)->get_Frame(&value));
        return winrt::Windows::Media::Capture::CapturedFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Devices::AdvancedPhotoMode) consume_Windows_Media_Capture_IAdvancedCapturedPhoto<D>::Mode() const
    {
        winrt::Windows::Media::Devices::AdvancedPhotoMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAdvancedCapturedPhoto)->get_Mode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_Media_Capture_IAdvancedCapturedPhoto<D>::Context() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAdvancedCapturedPhoto)->get_Context(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>) consume_Windows_Media_Capture_IAdvancedCapturedPhoto2<D>::FrameBoundsRelativeToReferencePhoto() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAdvancedCapturedPhoto2)->get_FrameBoundsRelativeToReferencePhoto(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::AdvancedCapturedPhoto>) consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::CaptureAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAdvancedPhotoCapture)->CaptureAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::AdvancedCapturedPhoto>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::AdvancedCapturedPhoto>) consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::CaptureAsync(winrt::Windows::Foundation::IInspectable const& context) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAdvancedPhotoCapture)->CaptureWithContextAsync(*(void**)(&context), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::AdvancedCapturedPhoto>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::OptionalReferencePhotoCaptured(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AdvancedPhotoCapture, winrt::Windows::Media::Capture::OptionalReferencePhotoCapturedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAdvancedPhotoCapture)->add_OptionalReferencePhotoCaptured(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::OptionalReferencePhotoCaptured_revoker consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::OptionalReferencePhotoCaptured(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AdvancedPhotoCapture, winrt::Windows::Media::Capture::OptionalReferencePhotoCapturedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, OptionalReferencePhotoCaptured_revoker>(this, OptionalReferencePhotoCaptured(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::OptionalReferencePhotoCaptured(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAdvancedPhotoCapture)->remove_OptionalReferencePhotoCaptured(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::AllPhotosCaptured(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AdvancedPhotoCapture, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAdvancedPhotoCapture)->add_AllPhotosCaptured(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::AllPhotosCaptured_revoker consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::AllPhotosCaptured(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AdvancedPhotoCapture, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, AllPhotosCaptured_revoker>(this, AllPhotosCaptured(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::AllPhotosCaptured(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAdvancedPhotoCapture)->remove_AllPhotosCaptured(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::FinishAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAdvancedPhotoCapture)->FinishAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::PlugInState(winrt::Windows::Media::Capture::AppBroadcastPlugInState const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->put_PlugInState(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastPlugInState) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::PlugInState() const
    {
        winrt::Windows::Media::Capture::AppBroadcastPlugInState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->get_PlugInState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::SignInInfo(winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->put_SignInInfo(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::SignInInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->get_SignInInfo(&value));
        return winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::StreamInfo(winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->put_StreamInfo(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::StreamInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->get_StreamInfo(&value));
        return winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::AppId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->get_AppId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::BroadcastTitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->get_BroadcastTitle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::ViewerCount(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->put_ViewerCount(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::ViewerCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->get_ViewerCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::TerminateBroadcast(winrt::Windows::Media::Capture::AppBroadcastTerminationReason const& reason, uint32_t providerSpecificReason) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->TerminateBroadcast(static_cast<int32_t>(reason), providerSpecificReason));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::HeartbeatRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundService, winrt::Windows::Media::Capture::AppBroadcastHeartbeatRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->add_HeartbeatRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::HeartbeatRequested_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::HeartbeatRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundService, winrt::Windows::Media::Capture::AppBroadcastHeartbeatRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, HeartbeatRequested_revoker>(this, HeartbeatRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::HeartbeatRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->remove_HeartbeatRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::TitleId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService)->get_TitleId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastTitle(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2)->put_BroadcastTitle(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastLanguage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2)->get_BroadcastLanguage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastLanguage(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2)->put_BroadcastLanguage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastChannel() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2)->get_BroadcastChannel(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastChannel(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2)->put_BroadcastChannel(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastTitleChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundService, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2)->add_BroadcastTitleChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastTitleChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastTitleChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundService, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, BroadcastTitleChanged_revoker>(this, BroadcastTitleChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastTitleChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2)->remove_BroadcastTitleChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastLanguageChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundService, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2)->add_BroadcastLanguageChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastLanguageChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastLanguageChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundService, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, BroadcastLanguageChanged_revoker>(this, BroadcastLanguageChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastLanguageChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2)->remove_BroadcastLanguageChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastChannelChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundService, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2)->add_BroadcastChannelChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastChannelChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastChannelChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundService, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, BroadcastChannelChanged_revoker>(this, BroadcastChannelChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastChannelChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2)->remove_BroadcastChannelChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastSignInState) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::SignInState() const
    {
        winrt::Windows::Media::Capture::AppBroadcastSignInState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->get_SignInState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::OAuthRequestUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->put_OAuthRequestUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::OAuthRequestUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->get_OAuthRequestUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::OAuthCallbackUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->put_OAuthCallbackUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::OAuthCallbackUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->get_OAuthCallbackUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::WebAuthenticationResult) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::AuthenticationResult() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->get_AuthenticationResult(&value));
        return winrt::Windows::Security::Authentication::Web::WebAuthenticationResult{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::UserName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->put_UserName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::UserName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->get_UserName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::SignInStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, winrt::Windows::Media::Capture::AppBroadcastSignInStateChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->add_SignInStateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::SignInStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::SignInStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, winrt::Windows::Media::Capture::AppBroadcastSignInStateChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SignInStateChanged_revoker>(this, SignInStateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::SignInStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->remove_SignInStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo2<D>::UserNameChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo2)->add_UserNameChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo2<D>::UserNameChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo2<D>::UserNameChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, UserNameChanged_revoker>(this, UserNameChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo2<D>::UserNameChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo2)->remove_UserNameChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastStreamState) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::StreamState() const
    {
        winrt::Windows::Media::Capture::AppBroadcastStreamState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->get_StreamState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::DesiredVideoEncodingBitrate(uint64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->put_DesiredVideoEncodingBitrate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::DesiredVideoEncodingBitrate() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->get_DesiredVideoEncodingBitrate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::BandwidthTestBitrate(uint64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->put_BandwidthTestBitrate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::BandwidthTestBitrate() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->get_BandwidthTestBitrate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::AudioCodec(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->put_AudioCodec(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::AudioCodec() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->get_AudioCodec(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastStreamReader) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::BroadcastStreamReader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->get_BroadcastStreamReader(&value));
        return winrt::Windows::Media::Capture::AppBroadcastStreamReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::StreamStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, winrt::Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->add_StreamStateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::StreamStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::StreamStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, winrt::Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StreamStateChanged_revoker>(this, StreamStateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::StreamStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->remove_StreamStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingResolutionChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->add_VideoEncodingResolutionChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingResolutionChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingResolutionChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, VideoEncodingResolutionChanged_revoker>(this, VideoEncodingResolutionChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingResolutionChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->remove_VideoEncodingResolutionChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingBitrateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->add_VideoEncodingBitrateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingBitrateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingBitrateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, VideoEncodingBitrateChanged_revoker>(this, VideoEncodingBitrateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingBitrateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->remove_VideoEncodingBitrateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo2<D>::ReportProblemWithStream() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo2)->ReportProblemWithStream());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastCameraCaptureState) consume_Windows_Media_Capture_IAppBroadcastCameraCaptureStateChangedEventArgs<D>::State() const
    {
        winrt::Windows::Media::Capture::AppBroadcastCameraCaptureState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastCameraCaptureStateChangedEventArgs)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastCameraCaptureStateChangedEventArgs<D>::ErrorCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastCameraCaptureStateChangedEventArgs)->get_ErrorCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsBroadcastEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsBroadcastEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsDisabledByPolicy() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsDisabledByPolicy(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsGpuConstrained() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsGpuConstrained(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::HasHardwareEncoder() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_HasHardwareEncoder(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsAudioCaptureEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_IsAudioCaptureEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsAudioCaptureEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsAudioCaptureEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsMicrophoneCaptureEnabledByDefault(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_IsMicrophoneCaptureEnabledByDefault(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsMicrophoneCaptureEnabledByDefault() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsMicrophoneCaptureEnabledByDefault(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsEchoCancellationEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_IsEchoCancellationEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsEchoCancellationEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsEchoCancellationEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::SystemAudioGain(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_SystemAudioGain(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::SystemAudioGain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_SystemAudioGain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::MicrophoneGain(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_MicrophoneGain(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::MicrophoneGain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_MicrophoneGain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsCameraCaptureEnabledByDefault(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_IsCameraCaptureEnabledByDefault(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsCameraCaptureEnabledByDefault() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsCameraCaptureEnabledByDefault(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::SelectedCameraId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_SelectedCameraId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::SelectedCameraId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_SelectedCameraId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::CameraOverlayLocation(winrt::Windows::Media::Capture::AppBroadcastCameraOverlayLocation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_CameraOverlayLocation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastCameraOverlayLocation) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::CameraOverlayLocation() const
    {
        winrt::Windows::Media::Capture::AppBroadcastCameraOverlayLocation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_CameraOverlayLocation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::CameraOverlaySize(winrt::Windows::Media::Capture::AppBroadcastCameraOverlaySize const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_CameraOverlaySize(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastCameraOverlaySize) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::CameraOverlaySize() const
    {
        winrt::Windows::Media::Capture::AppBroadcastCameraOverlaySize value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_CameraOverlaySize(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsCursorImageCaptureEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_IsCursorImageCaptureEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsCursorImageCaptureEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsCursorImageCaptureEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastHeartbeatRequestedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastHeartbeatRequestedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastHeartbeatRequestedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastHeartbeatRequestedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastGlobalSettings) consume_Windows_Media_Capture_IAppBroadcastManagerStatics<D>::GetGlobalSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastManagerStatics)->GetGlobalSettings(&value));
        return winrt::Windows::Media::Capture::AppBroadcastGlobalSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastManagerStatics<D>::ApplyGlobalSettings(winrt::Windows::Media::Capture::AppBroadcastGlobalSettings const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastManagerStatics)->ApplyGlobalSettings(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastProviderSettings) consume_Windows_Media_Capture_IAppBroadcastManagerStatics<D>::GetProviderSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastManagerStatics)->GetProviderSettings(&value));
        return winrt::Windows::Media::Capture::AppBroadcastProviderSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastManagerStatics<D>::ApplyProviderSettings(winrt::Windows::Media::Capture::AppBroadcastProviderSettings const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastManagerStatics)->ApplyProviderSettings(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastMicrophoneCaptureState) consume_Windows_Media_Capture_IAppBroadcastMicrophoneCaptureStateChangedEventArgs<D>::State() const
    {
        winrt::Windows::Media::Capture::AppBroadcastMicrophoneCaptureState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastMicrophoneCaptureStateChangedEventArgs)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastMicrophoneCaptureStateChangedEventArgs<D>::ErrorCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastMicrophoneCaptureStateChangedEventArgs)->get_ErrorCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastPlugIn<D>::AppId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPlugIn)->get_AppId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastProviderSettings) consume_Windows_Media_Capture_IAppBroadcastPlugIn<D>::ProviderSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPlugIn)->get_ProviderSettings(&value));
        return winrt::Windows::Media::Capture::AppBroadcastProviderSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_Media_Capture_IAppBroadcastPlugIn<D>::Logo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPlugIn)->get_Logo(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastPlugIn<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPlugIn)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastPlugInManager<D>::IsBroadcastProviderAvailable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPlugInManager)->get_IsBroadcastProviderAvailable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::AppBroadcastPlugIn>) consume_Windows_Media_Capture_IAppBroadcastPlugInManager<D>::PlugInList() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPlugInManager)->get_PlugInList(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::AppBroadcastPlugIn>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastPlugIn) consume_Windows_Media_Capture_IAppBroadcastPlugInManager<D>::DefaultPlugIn() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPlugInManager)->get_DefaultPlugIn(&value));
        return winrt::Windows::Media::Capture::AppBroadcastPlugIn{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastPlugInManager<D>::DefaultPlugIn(winrt::Windows::Media::Capture::AppBroadcastPlugIn const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPlugInManager)->put_DefaultPlugIn(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastPlugInManager) consume_Windows_Media_Capture_IAppBroadcastPlugInManagerStatics<D>::GetDefault() const
    {
        void* ppInstance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPlugInManagerStatics)->GetDefault(&ppInstance));
        return winrt::Windows::Media::Capture::AppBroadcastPlugInManager{ ppInstance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastPlugInManager) consume_Windows_Media_Capture_IAppBroadcastPlugInManagerStatics<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* ppInstance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPlugInManagerStatics)->GetForUser(*(void**)(&user), &ppInstance));
        return winrt::Windows::Media::Capture::AppBroadcastPlugInManager{ ppInstance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastPlugInState) consume_Windows_Media_Capture_IAppBroadcastPlugInStateChangedEventArgs<D>::PlugInState() const
    {
        winrt::Windows::Media::Capture::AppBroadcastPlugInState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPlugInStateChangedEventArgs)->get_PlugInState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastPreview<D>::StopPreview() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreview)->StopPreview());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastPreviewState) consume_Windows_Media_Capture_IAppBroadcastPreview<D>::PreviewState() const
    {
        winrt::Windows::Media::Capture::AppBroadcastPreviewState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreview)->get_PreviewState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Media_Capture_IAppBroadcastPreview<D>::ErrorCode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreview)->get_ErrorCode(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastPreview<D>::PreviewStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastPreview, winrt::Windows::Media::Capture::AppBroadcastPreviewStateChangedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreview)->add_PreviewStateChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastPreview<D>::PreviewStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastPreview<D>::PreviewStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastPreview, winrt::Windows::Media::Capture::AppBroadcastPreviewStateChangedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, PreviewStateChanged_revoker>(this, PreviewStateChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastPreview<D>::PreviewStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreview)->remove_PreviewStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastPreviewStreamReader) consume_Windows_Media_Capture_IAppBroadcastPreview<D>::PreviewStreamReader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreview)->get_PreviewStreamReader(&value));
        return winrt::Windows::Media::Capture::AppBroadcastPreviewStreamReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastPreviewState) consume_Windows_Media_Capture_IAppBroadcastPreviewStateChangedEventArgs<D>::PreviewState() const
    {
        winrt::Windows::Media::Capture::AppBroadcastPreviewState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStateChangedEventArgs)->get_PreviewState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastPreviewStateChangedEventArgs<D>::ErrorCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStateChangedEventArgs)->get_ErrorCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoWidth() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->get_VideoWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoHeight() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->get_VideoHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoStride() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->get_VideoStride(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Imaging::BitmapPixelFormat) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoBitmapPixelFormat() const
    {
        winrt::Windows::Graphics::Imaging::BitmapPixelFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->get_VideoBitmapPixelFormat(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Imaging::BitmapAlphaMode) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoBitmapAlphaMode() const
    {
        winrt::Windows::Graphics::Imaging::BitmapAlphaMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->get_VideoBitmapAlphaMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastPreviewStreamVideoFrame) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::TryGetNextVideoFrame() const
    {
        void* frame{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->TryGetNextVideoFrame(&frame));
        return winrt::Windows::Media::Capture::AppBroadcastPreviewStreamVideoFrame{ frame, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoFrameArrived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamReader, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->add_VideoFrameArrived(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoFrameArrived_revoker consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoFrameArrived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamReader, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, VideoFrameArrived_revoker>(this, VideoFrameArrived(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoFrameArrived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->remove_VideoFrameArrived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastPreviewStreamVideoHeader) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamVideoFrame<D>::VideoHeader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoFrame)->get_VideoHeader(&value));
        return winrt::Windows::Media::Capture::AppBroadcastPreviewStreamVideoHeader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamVideoFrame<D>::VideoBuffer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoFrame)->get_VideoBuffer(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamVideoHeader<D>::AbsoluteTimestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader)->get_AbsoluteTimestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamVideoHeader<D>::RelativeTimestamp() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader)->get_RelativeTimestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamVideoHeader<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Media_Capture_IAppBroadcastPreviewStreamVideoHeader<D>::FrameId() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader)->get_FrameId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::DefaultBroadcastTitle(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->put_DefaultBroadcastTitle(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::DefaultBroadcastTitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->get_DefaultBroadcastTitle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::AudioEncodingBitrate(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->put_AudioEncodingBitrate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::AudioEncodingBitrate() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->get_AudioEncodingBitrate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::CustomVideoEncodingBitrate(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->put_CustomVideoEncodingBitrate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::CustomVideoEncodingBitrate() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->get_CustomVideoEncodingBitrate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::CustomVideoEncodingHeight(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->put_CustomVideoEncodingHeight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::CustomVideoEncodingHeight() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->get_CustomVideoEncodingHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::CustomVideoEncodingWidth(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->put_CustomVideoEncodingWidth(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::CustomVideoEncodingWidth() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->get_CustomVideoEncodingWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::VideoEncodingBitrateMode(winrt::Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->put_VideoEncodingBitrateMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::VideoEncodingBitrateMode() const
    {
        winrt::Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->get_VideoEncodingBitrateMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::VideoEncodingResolutionMode(winrt::Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->put_VideoEncodingResolutionMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode) consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::VideoEncodingResolutionMode() const
    {
        winrt::Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastProviderSettings)->get_VideoEncodingResolutionMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastCaptureTargetType) consume_Windows_Media_Capture_IAppBroadcastServices<D>::CaptureTargetType() const
    {
        winrt::Windows::Media::Capture::AppBroadcastCaptureTargetType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->get_CaptureTargetType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastServices<D>::CaptureTargetType(winrt::Windows::Media::Capture::AppBroadcastCaptureTargetType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->put_CaptureTargetType(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastServices<D>::BroadcastTitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->get_BroadcastTitle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastServices<D>::BroadcastTitle(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->put_BroadcastTitle(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastServices<D>::BroadcastLanguage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->get_BroadcastLanguage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastServices<D>::BroadcastLanguage(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->put_BroadcastLanguage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IAppBroadcastServices<D>::UserName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->get_UserName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastServices<D>::CanCapture() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->get_CanCapture(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<uint32_t>) consume_Windows_Media_Capture_IAppBroadcastServices<D>::EnterBroadcastModeAsync(winrt::Windows::Media::Capture::AppBroadcastPlugIn const& plugIn) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->EnterBroadcastModeAsync(*(void**)(&plugIn), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<uint32_t>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastServices<D>::ExitBroadcastMode(winrt::Windows::Media::Capture::AppBroadcastExitBroadcastModeReason const& reason) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->ExitBroadcastMode(static_cast<int32_t>(reason)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastServices<D>::StartBroadcast() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->StartBroadcast());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastServices<D>::PauseBroadcast() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->PauseBroadcast());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastServices<D>::ResumeBroadcast() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->ResumeBroadcast());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastPreview) consume_Windows_Media_Capture_IAppBroadcastServices<D>::StartPreview(winrt::Windows::Foundation::Size const& desiredSize) const
    {
        void* preview{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->StartPreview(impl::bind_in(desiredSize), &preview));
        return winrt::Windows::Media::Capture::AppBroadcastPreview{ preview, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastState) consume_Windows_Media_Capture_IAppBroadcastServices<D>::State() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastServices)->get_State(&value));
        return winrt::Windows::Media::Capture::AppBroadcastState{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastSignInState) consume_Windows_Media_Capture_IAppBroadcastSignInStateChangedEventArgs<D>::SignInState() const
    {
        winrt::Windows::Media::Capture::AppBroadcastSignInState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastSignInStateChangedEventArgs)->get_SignInState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastSignInResult) consume_Windows_Media_Capture_IAppBroadcastSignInStateChangedEventArgs<D>::Result() const
    {
        winrt::Windows::Media::Capture::AppBroadcastSignInResult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastSignInStateChangedEventArgs)->get_Result(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastState<D>::IsCaptureTargetRunning() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_IsCaptureTargetRunning(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastState<D>::ViewerCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_ViewerCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastState<D>::ShouldCaptureMicrophone() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_ShouldCaptureMicrophone(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastState<D>::ShouldCaptureMicrophone(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->put_ShouldCaptureMicrophone(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastState<D>::RestartMicrophoneCapture() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->RestartMicrophoneCapture());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastState<D>::ShouldCaptureCamera() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_ShouldCaptureCamera(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastState<D>::ShouldCaptureCamera(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->put_ShouldCaptureCamera(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastState<D>::RestartCameraCapture() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->RestartCameraCapture());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_Media_Capture_IAppBroadcastState<D>::EncodedVideoSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_EncodedVideoSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastMicrophoneCaptureState) consume_Windows_Media_Capture_IAppBroadcastState<D>::MicrophoneCaptureState() const
    {
        winrt::Windows::Media::Capture::AppBroadcastMicrophoneCaptureState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_MicrophoneCaptureState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastState<D>::MicrophoneCaptureError() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_MicrophoneCaptureError(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastCameraCaptureState) consume_Windows_Media_Capture_IAppBroadcastState<D>::CameraCaptureState() const
    {
        winrt::Windows::Media::Capture::AppBroadcastCameraCaptureState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_CameraCaptureState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastState<D>::CameraCaptureError() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_CameraCaptureError(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastStreamState) consume_Windows_Media_Capture_IAppBroadcastState<D>::StreamState() const
    {
        winrt::Windows::Media::Capture::AppBroadcastStreamState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_StreamState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastPlugInState) consume_Windows_Media_Capture_IAppBroadcastState<D>::PlugInState() const
    {
        winrt::Windows::Media::Capture::AppBroadcastPlugInState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_PlugInState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Media_Capture_IAppBroadcastState<D>::OAuthRequestUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_OAuthRequestUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Media_Capture_IAppBroadcastState<D>::OAuthCallbackUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_OAuthCallbackUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::WebAuthenticationResult) consume_Windows_Media_Capture_IAppBroadcastState<D>::AuthenticationResult() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_AuthenticationResult(&value));
        return winrt::Windows::Security::Authentication::Web::WebAuthenticationResult{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastState<D>::AuthenticationResult(winrt::Windows::Security::Authentication::Web::WebAuthenticationResult const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->put_AuthenticationResult(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastState<D>::SignInState(winrt::Windows::Media::Capture::AppBroadcastSignInState const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->put_SignInState(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastSignInState) consume_Windows_Media_Capture_IAppBroadcastState<D>::SignInState() const
    {
        winrt::Windows::Media::Capture::AppBroadcastSignInState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_SignInState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastTerminationReason) consume_Windows_Media_Capture_IAppBroadcastState<D>::TerminationReason() const
    {
        winrt::Windows::Media::Capture::AppBroadcastTerminationReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_TerminationReason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastState<D>::TerminationReasonPlugInSpecific() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->get_TerminationReasonPlugInSpecific(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastState<D>::ViewerCountChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastViewerCountChangedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->add_ViewerCountChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastState<D>::ViewerCountChanged_revoker consume_Windows_Media_Capture_IAppBroadcastState<D>::ViewerCountChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastViewerCountChangedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, ViewerCountChanged_revoker>(this, ViewerCountChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastState<D>::ViewerCountChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->remove_ViewerCountChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastState<D>::MicrophoneCaptureStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastMicrophoneCaptureStateChangedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->add_MicrophoneCaptureStateChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastState<D>::MicrophoneCaptureStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastState<D>::MicrophoneCaptureStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastMicrophoneCaptureStateChangedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, MicrophoneCaptureStateChanged_revoker>(this, MicrophoneCaptureStateChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastState<D>::MicrophoneCaptureStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->remove_MicrophoneCaptureStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastState<D>::CameraCaptureStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastCameraCaptureStateChangedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->add_CameraCaptureStateChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastState<D>::CameraCaptureStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastState<D>::CameraCaptureStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastCameraCaptureStateChangedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, CameraCaptureStateChanged_revoker>(this, CameraCaptureStateChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastState<D>::CameraCaptureStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->remove_CameraCaptureStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastState<D>::PlugInStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastPlugInStateChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->add_PlugInStateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastState<D>::PlugInStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastState<D>::PlugInStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastPlugInStateChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PlugInStateChanged_revoker>(this, PlugInStateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastState<D>::PlugInStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->remove_PlugInStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastState<D>::StreamStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->add_StreamStateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastState<D>::StreamStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastState<D>::StreamStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StreamStateChanged_revoker>(this, StreamStateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastState<D>::StreamStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->remove_StreamStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastState<D>::CaptureTargetClosed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->add_CaptureTargetClosed(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastState<D>::CaptureTargetClosed_revoker consume_Windows_Media_Capture_IAppBroadcastState<D>::CaptureTargetClosed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, CaptureTargetClosed_revoker>(this, CaptureTargetClosed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastState<D>::CaptureTargetClosed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastState)->remove_CaptureTargetClosed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastStreamAudioHeader) consume_Windows_Media_Capture_IAppBroadcastStreamAudioFrame<D>::AudioHeader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamAudioFrame)->get_AudioHeader(&value));
        return winrt::Windows::Media::Capture::AppBroadcastStreamAudioHeader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Media_Capture_IAppBroadcastStreamAudioFrame<D>::AudioBuffer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamAudioFrame)->get_AudioBuffer(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Media_Capture_IAppBroadcastStreamAudioHeader<D>::AbsoluteTimestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamAudioHeader)->get_AbsoluteTimestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Capture_IAppBroadcastStreamAudioHeader<D>::RelativeTimestamp() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamAudioHeader)->get_RelativeTimestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Capture_IAppBroadcastStreamAudioHeader<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamAudioHeader)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastStreamAudioHeader<D>::HasDiscontinuity() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamAudioHeader)->get_HasDiscontinuity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Media_Capture_IAppBroadcastStreamAudioHeader<D>::FrameId() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamAudioHeader)->get_FrameId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioChannels() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamReader)->get_AudioChannels(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioSampleRate() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamReader)->get_AudioSampleRate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioAacSequence() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamReader)->get_AudioAacSequence(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioBitrate() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamReader)->get_AudioBitrate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastStreamAudioFrame) consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::TryGetNextAudioFrame() const
    {
        void* frame{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamReader)->TryGetNextAudioFrame(&frame));
        return winrt::Windows::Media::Capture::AppBroadcastStreamAudioFrame{ frame, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoWidth() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamReader)->get_VideoWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoHeight() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamReader)->get_VideoHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoBitrate() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamReader)->get_VideoBitrate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastStreamVideoFrame) consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::TryGetNextVideoFrame() const
    {
        void* frame{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamReader)->TryGetNextVideoFrame(&frame));
        return winrt::Windows::Media::Capture::AppBroadcastStreamVideoFrame{ frame, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioFrameArrived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastStreamReader, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamReader)->add_AudioFrameArrived(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioFrameArrived_revoker consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioFrameArrived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastStreamReader, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, AudioFrameArrived_revoker>(this, AudioFrameArrived(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioFrameArrived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamReader)->remove_AudioFrameArrived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoFrameArrived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastStreamReader, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamReader)->add_VideoFrameArrived(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoFrameArrived_revoker consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoFrameArrived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastStreamReader, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, VideoFrameArrived_revoker>(this, VideoFrameArrived(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoFrameArrived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamReader)->remove_VideoFrameArrived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastStreamState) consume_Windows_Media_Capture_IAppBroadcastStreamStateChangedEventArgs<D>::StreamState() const
    {
        winrt::Windows::Media::Capture::AppBroadcastStreamState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamStateChangedEventArgs)->get_StreamState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastStreamVideoHeader) consume_Windows_Media_Capture_IAppBroadcastStreamVideoFrame<D>::VideoHeader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamVideoFrame)->get_VideoHeader(&value));
        return winrt::Windows::Media::Capture::AppBroadcastStreamVideoHeader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Media_Capture_IAppBroadcastStreamVideoFrame<D>::VideoBuffer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamVideoFrame)->get_VideoBuffer(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Media_Capture_IAppBroadcastStreamVideoHeader<D>::AbsoluteTimestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamVideoHeader)->get_AbsoluteTimestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Capture_IAppBroadcastStreamVideoHeader<D>::RelativeTimestamp() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamVideoHeader)->get_RelativeTimestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Capture_IAppBroadcastStreamVideoHeader<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamVideoHeader)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastStreamVideoHeader<D>::IsKeyFrame() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamVideoHeader)->get_IsKeyFrame(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppBroadcastStreamVideoHeader<D>::HasDiscontinuity() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamVideoHeader)->get_HasDiscontinuity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Media_Capture_IAppBroadcastStreamVideoHeader<D>::FrameId() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastStreamVideoHeader)->get_FrameId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastBackgroundService) consume_Windows_Media_Capture_IAppBroadcastTriggerDetails<D>::BackgroundService() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastTriggerDetails)->get_BackgroundService(&value));
        return winrt::Windows::Media::Capture::AppBroadcastBackgroundService{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppBroadcastViewerCountChangedEventArgs<D>::ViewerCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppBroadcastViewerCountChangedEventArgs)->get_ViewerCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCapture<D>::IsCapturingAudio() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCapture)->get_IsCapturingAudio(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCapture<D>::IsCapturingVideo() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCapture)->get_IsCapturingVideo(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppCapture<D>::CapturingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCapture, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCapture)->add_CapturingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppCapture<D>::CapturingChanged_revoker consume_Windows_Media_Capture_IAppCapture<D>::CapturingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCapture, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, CapturingChanged_revoker>(this, CapturingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCapture<D>::CapturingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCapture)->remove_CapturingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleGameBarKey(winrt::Windows::System::VirtualKey const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_ToggleGameBarKey(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleGameBarKey() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_ToggleGameBarKey(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleGameBarKeyModifiers(winrt::Windows::System::VirtualKeyModifiers const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_ToggleGameBarKeyModifiers(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKeyModifiers) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleGameBarKeyModifiers() const
    {
        winrt::Windows::System::VirtualKeyModifiers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_ToggleGameBarKeyModifiers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::SaveHistoricalVideoKey(winrt::Windows::System::VirtualKey const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_SaveHistoricalVideoKey(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::SaveHistoricalVideoKey() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_SaveHistoricalVideoKey(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::SaveHistoricalVideoKeyModifiers(winrt::Windows::System::VirtualKeyModifiers const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_SaveHistoricalVideoKeyModifiers(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKeyModifiers) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::SaveHistoricalVideoKeyModifiers() const
    {
        winrt::Windows::System::VirtualKeyModifiers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_SaveHistoricalVideoKeyModifiers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingKey(winrt::Windows::System::VirtualKey const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_ToggleRecordingKey(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingKey() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_ToggleRecordingKey(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingKeyModifiers(winrt::Windows::System::VirtualKeyModifiers const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_ToggleRecordingKeyModifiers(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKeyModifiers) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingKeyModifiers() const
    {
        winrt::Windows::System::VirtualKeyModifiers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_ToggleRecordingKeyModifiers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::TakeScreenshotKey(winrt::Windows::System::VirtualKey const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_TakeScreenshotKey(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::TakeScreenshotKey() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_TakeScreenshotKey(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::TakeScreenshotKeyModifiers(winrt::Windows::System::VirtualKeyModifiers const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_TakeScreenshotKeyModifiers(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKeyModifiers) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::TakeScreenshotKeyModifiers() const
    {
        winrt::Windows::System::VirtualKeyModifiers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_TakeScreenshotKeyModifiers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingIndicatorKey(winrt::Windows::System::VirtualKey const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_ToggleRecordingIndicatorKey(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingIndicatorKey() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_ToggleRecordingIndicatorKey(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingIndicatorKeyModifiers(winrt::Windows::System::VirtualKeyModifiers const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_ToggleRecordingIndicatorKeyModifiers(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKeyModifiers) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingIndicatorKeyModifiers() const
    {
        winrt::Windows::System::VirtualKeyModifiers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_ToggleRecordingIndicatorKeyModifiers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys2<D>::ToggleMicrophoneCaptureKey(winrt::Windows::System::VirtualKey const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2)->put_ToggleMicrophoneCaptureKey(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys2<D>::ToggleMicrophoneCaptureKey() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2)->get_ToggleMicrophoneCaptureKey(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys2<D>::ToggleMicrophoneCaptureKeyModifiers(winrt::Windows::System::VirtualKeyModifiers const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2)->put_ToggleMicrophoneCaptureKeyModifiers(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKeyModifiers) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys2<D>::ToggleMicrophoneCaptureKeyModifiers() const
    {
        winrt::Windows::System::VirtualKeyModifiers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2)->get_ToggleMicrophoneCaptureKeyModifiers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleCameraCaptureKey(winrt::Windows::System::VirtualKey const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->put_ToggleCameraCaptureKey(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleCameraCaptureKey() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->get_ToggleCameraCaptureKey(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleCameraCaptureKeyModifiers(winrt::Windows::System::VirtualKeyModifiers const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->put_ToggleCameraCaptureKeyModifiers(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKeyModifiers) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleCameraCaptureKeyModifiers() const
    {
        winrt::Windows::System::VirtualKeyModifiers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->get_ToggleCameraCaptureKeyModifiers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleBroadcastKey(winrt::Windows::System::VirtualKey const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->put_ToggleBroadcastKey(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleBroadcastKey() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->get_ToggleBroadcastKey(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleBroadcastKeyModifiers(winrt::Windows::System::VirtualKeyModifiers const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->put_ToggleBroadcastKeyModifiers(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKeyModifiers) consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleBroadcastKeyModifiers() const
    {
        winrt::Windows::System::VirtualKeyModifiers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->get_ToggleBroadcastKeyModifiers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Capture_IAppCaptureDurationGeneratedEventArgs<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureDurationGeneratedEventArgs)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFile) consume_Windows_Media_Capture_IAppCaptureFileGeneratedEventArgs<D>::File() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureFileGeneratedEventArgs)->get_File(&value));
        return winrt::Windows::Storage::StorageFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureSettings) consume_Windows_Media_Capture_IAppCaptureManagerStatics<D>::GetCurrentSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureManagerStatics)->GetCurrentSettings(&value));
        return winrt::Windows::Media::Capture::AppCaptureSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureManagerStatics<D>::ApplySettings(winrt::Windows::Media::Capture::AppCaptureSettings const& appCaptureSettings) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureManagerStatics)->ApplySettings(*(void**)(&appCaptureSettings)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::AddStringEvent(param::hstring const& name, param::hstring const& value, winrt::Windows::Media::Capture::AppCaptureMetadataPriority const& priority) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureMetadataWriter)->AddStringEvent(*(void**)(&name), *(void**)(&value), static_cast<int32_t>(priority)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::AddInt32Event(param::hstring const& name, int32_t value, winrt::Windows::Media::Capture::AppCaptureMetadataPriority const& priority) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureMetadataWriter)->AddInt32Event(*(void**)(&name), value, static_cast<int32_t>(priority)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::AddDoubleEvent(param::hstring const& name, double value, winrt::Windows::Media::Capture::AppCaptureMetadataPriority const& priority) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureMetadataWriter)->AddDoubleEvent(*(void**)(&name), value, static_cast<int32_t>(priority)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::StartStringState(param::hstring const& name, param::hstring const& value, winrt::Windows::Media::Capture::AppCaptureMetadataPriority const& priority) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureMetadataWriter)->StartStringState(*(void**)(&name), *(void**)(&value), static_cast<int32_t>(priority)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::StartInt32State(param::hstring const& name, int32_t value, winrt::Windows::Media::Capture::AppCaptureMetadataPriority const& priority) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureMetadataWriter)->StartInt32State(*(void**)(&name), value, static_cast<int32_t>(priority)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::StartDoubleState(param::hstring const& name, double value, winrt::Windows::Media::Capture::AppCaptureMetadataPriority const& priority) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureMetadataWriter)->StartDoubleState(*(void**)(&name), value, static_cast<int32_t>(priority)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::StopState(param::hstring const& name) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureMetadataWriter)->StopState(*(void**)(&name)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::StopAllStates() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureMetadataWriter)->StopAllStates());
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::RemainingStorageBytesAvailable() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureMetadataWriter)->get_RemainingStorageBytesAvailable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::MetadataPurged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureMetadataWriter, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureMetadataWriter)->add_MetadataPurged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::MetadataPurged_revoker consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::MetadataPurged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureMetadataWriter, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, MetadataPurged_revoker>(this, MetadataPurged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::MetadataPurged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureMetadataWriter)->remove_MetadataPurged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureMicrophoneCaptureState) consume_Windows_Media_Capture_IAppCaptureMicrophoneCaptureStateChangedEventArgs<D>::State() const
    {
        winrt::Windows::Media::Capture::AppCaptureMicrophoneCaptureState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureMicrophoneCaptureStateChangedEventArgs)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppCaptureMicrophoneCaptureStateChangedEventArgs<D>::ErrorCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureMicrophoneCaptureStateChangedEventArgs)->get_ErrorCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::StopRecording() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordOperation)->StopRecording());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureRecordingState) consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::State() const
    {
        winrt::Windows::Media::Capture::AppCaptureRecordingState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordOperation)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::ErrorCode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordOperation)->get_ErrorCode(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::Duration() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordOperation)->get_Duration(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFile) consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::File() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordOperation)->get_File(&value));
        return winrt::Windows::Storage::StorageFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<bool>) consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::IsFileTruncated() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordOperation)->get_IsFileTruncated(&value));
        return winrt::Windows::Foundation::IReference<bool>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::StateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureRecordOperation, winrt::Windows::Media::Capture::AppCaptureRecordingStateChangedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordOperation)->add_StateChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::StateChanged_revoker consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::StateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureRecordOperation, winrt::Windows::Media::Capture::AppCaptureRecordingStateChangedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::StateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordOperation)->remove_StateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::DurationGenerated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureRecordOperation, winrt::Windows::Media::Capture::AppCaptureDurationGeneratedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordOperation)->add_DurationGenerated(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::DurationGenerated_revoker consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::DurationGenerated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureRecordOperation, winrt::Windows::Media::Capture::AppCaptureDurationGeneratedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, DurationGenerated_revoker>(this, DurationGenerated(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::DurationGenerated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordOperation)->remove_DurationGenerated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::FileGenerated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureRecordOperation, winrt::Windows::Media::Capture::AppCaptureFileGeneratedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordOperation)->add_FileGenerated(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::FileGenerated_revoker consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::FileGenerated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureRecordOperation, winrt::Windows::Media::Capture::AppCaptureFileGeneratedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, FileGenerated_revoker>(this, FileGenerated(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::FileGenerated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordOperation)->remove_FileGenerated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureRecordingState) consume_Windows_Media_Capture_IAppCaptureRecordingStateChangedEventArgs<D>::State() const
    {
        winrt::Windows::Media::Capture::AppCaptureRecordingState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordingStateChangedEventArgs)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppCaptureRecordingStateChangedEventArgs<D>::ErrorCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureRecordingStateChangedEventArgs)->get_ErrorCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureRecordOperation) consume_Windows_Media_Capture_IAppCaptureServices<D>::Record() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureServices)->Record(&operation));
        return winrt::Windows::Media::Capture::AppCaptureRecordOperation{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureRecordOperation) consume_Windows_Media_Capture_IAppCaptureServices<D>::RecordTimeSpan(winrt::Windows::Foundation::DateTime const& startTime, winrt::Windows::Foundation::TimeSpan const& duration) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureServices)->RecordTimeSpan(impl::bind_in(startTime), impl::bind_in(duration), &operation));
        return winrt::Windows::Media::Capture::AppCaptureRecordOperation{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureServices<D>::CanCapture() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureServices)->get_CanCapture(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureState) consume_Windows_Media_Capture_IAppCaptureServices<D>::State() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureServices)->get_State(&value));
        return winrt::Windows::Media::Capture::AppCaptureState{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::AppCaptureDestinationFolder(winrt::Windows::Storage::StorageFolder const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_AppCaptureDestinationFolder(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Media_Capture_IAppCaptureSettings<D>::AppCaptureDestinationFolder() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_AppCaptureDestinationFolder(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::AudioEncodingBitrate(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_AudioEncodingBitrate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppCaptureSettings<D>::AudioEncodingBitrate() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_AudioEncodingBitrate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsAudioCaptureEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_IsAudioCaptureEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsAudioCaptureEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_IsAudioCaptureEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::CustomVideoEncodingBitrate(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_CustomVideoEncodingBitrate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppCaptureSettings<D>::CustomVideoEncodingBitrate() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_CustomVideoEncodingBitrate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::CustomVideoEncodingHeight(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_CustomVideoEncodingHeight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppCaptureSettings<D>::CustomVideoEncodingHeight() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_CustomVideoEncodingHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::CustomVideoEncodingWidth(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_CustomVideoEncodingWidth(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppCaptureSettings<D>::CustomVideoEncodingWidth() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_CustomVideoEncodingWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::HistoricalBufferLength(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_HistoricalBufferLength(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppCaptureSettings<D>::HistoricalBufferLength() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_HistoricalBufferLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::HistoricalBufferLengthUnit(winrt::Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_HistoricalBufferLengthUnit(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit) consume_Windows_Media_Capture_IAppCaptureSettings<D>::HistoricalBufferLengthUnit() const
    {
        winrt::Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_HistoricalBufferLengthUnit(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsHistoricalCaptureEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_IsHistoricalCaptureEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsHistoricalCaptureEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_IsHistoricalCaptureEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsHistoricalCaptureOnBatteryAllowed(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_IsHistoricalCaptureOnBatteryAllowed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsHistoricalCaptureOnBatteryAllowed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_IsHistoricalCaptureOnBatteryAllowed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsHistoricalCaptureOnWirelessDisplayAllowed(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_IsHistoricalCaptureOnWirelessDisplayAllowed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsHistoricalCaptureOnWirelessDisplayAllowed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_IsHistoricalCaptureOnWirelessDisplayAllowed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::MaximumRecordLength(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_MaximumRecordLength(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Capture_IAppCaptureSettings<D>::MaximumRecordLength() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_MaximumRecordLength(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::ScreenshotDestinationFolder(winrt::Windows::Storage::StorageFolder const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_ScreenshotDestinationFolder(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Media_Capture_IAppCaptureSettings<D>::ScreenshotDestinationFolder() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_ScreenshotDestinationFolder(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::VideoEncodingBitrateMode(winrt::Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_VideoEncodingBitrateMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode) consume_Windows_Media_Capture_IAppCaptureSettings<D>::VideoEncodingBitrateMode() const
    {
        winrt::Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_VideoEncodingBitrateMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::VideoEncodingResolutionMode(winrt::Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_VideoEncodingResolutionMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode) consume_Windows_Media_Capture_IAppCaptureSettings<D>::VideoEncodingResolutionMode() const
    {
        winrt::Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_VideoEncodingResolutionMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsAppCaptureEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->put_IsAppCaptureEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsAppCaptureEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_IsAppCaptureEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsCpuConstrained() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_IsCpuConstrained(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsDisabledByPolicy() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_IsDisabledByPolicy(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsMemoryConstrained() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_IsMemoryConstrained(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings<D>::HasHardwareEncoder() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings)->get_HasHardwareEncoder(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings2<D>::IsGpuConstrained() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings2)->get_IsGpuConstrained(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureAlternateShortcutKeys) consume_Windows_Media_Capture_IAppCaptureSettings2<D>::AlternateShortcutKeys() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings2)->get_AlternateShortcutKeys(&value));
        return winrt::Windows::Media::Capture::AppCaptureAlternateShortcutKeys{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings3<D>::IsMicrophoneCaptureEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings3)->put_IsMicrophoneCaptureEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings3<D>::IsMicrophoneCaptureEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings3)->get_IsMicrophoneCaptureEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings4<D>::IsMicrophoneCaptureEnabledByDefault(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings4)->put_IsMicrophoneCaptureEnabledByDefault(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings4<D>::IsMicrophoneCaptureEnabledByDefault() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings4)->get_IsMicrophoneCaptureEnabledByDefault(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings4<D>::SystemAudioGain(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings4)->put_SystemAudioGain(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Capture_IAppCaptureSettings4<D>::SystemAudioGain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings4)->get_SystemAudioGain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings4<D>::MicrophoneGain(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings4)->put_MicrophoneGain(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Capture_IAppCaptureSettings4<D>::MicrophoneGain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings4)->get_MicrophoneGain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings4<D>::VideoEncodingFrameRateMode(winrt::Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings4)->put_VideoEncodingFrameRateMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode) consume_Windows_Media_Capture_IAppCaptureSettings4<D>::VideoEncodingFrameRateMode() const
    {
        winrt::Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings4)->get_VideoEncodingFrameRateMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings5<D>::IsEchoCancellationEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings5)->put_IsEchoCancellationEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings5<D>::IsEchoCancellationEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings5)->get_IsEchoCancellationEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureSettings5<D>::IsCursorImageCaptureEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings5)->put_IsCursorImageCaptureEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureSettings5<D>::IsCursorImageCaptureEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureSettings5)->get_IsCursorImageCaptureEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureState<D>::IsTargetRunning() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureState)->get_IsTargetRunning(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureState<D>::IsHistoricalCaptureEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureState)->get_IsHistoricalCaptureEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IAppCaptureState<D>::ShouldCaptureMicrophone() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureState)->get_ShouldCaptureMicrophone(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureState<D>::ShouldCaptureMicrophone(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureState)->put_ShouldCaptureMicrophone(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureState<D>::RestartMicrophoneCapture() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureState)->RestartMicrophoneCapture());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureMicrophoneCaptureState) consume_Windows_Media_Capture_IAppCaptureState<D>::MicrophoneCaptureState() const
    {
        winrt::Windows::Media::Capture::AppCaptureMicrophoneCaptureState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureState)->get_MicrophoneCaptureState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IAppCaptureState<D>::MicrophoneCaptureError() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureState)->get_MicrophoneCaptureError(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppCaptureState<D>::MicrophoneCaptureStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureState, winrt::Windows::Media::Capture::AppCaptureMicrophoneCaptureStateChangedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureState)->add_MicrophoneCaptureStateChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppCaptureState<D>::MicrophoneCaptureStateChanged_revoker consume_Windows_Media_Capture_IAppCaptureState<D>::MicrophoneCaptureStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureState, winrt::Windows::Media::Capture::AppCaptureMicrophoneCaptureStateChangedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, MicrophoneCaptureStateChanged_revoker>(this, MicrophoneCaptureStateChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureState<D>::MicrophoneCaptureStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureState)->remove_MicrophoneCaptureStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IAppCaptureState<D>::CaptureTargetClosed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureState, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureState)->add_CaptureTargetClosed(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IAppCaptureState<D>::CaptureTargetClosed_revoker consume_Windows_Media_Capture_IAppCaptureState<D>::CaptureTargetClosed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureState, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, CaptureTargetClosed_revoker>(this, CaptureTargetClosed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IAppCaptureState<D>::CaptureTargetClosed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureState)->remove_CaptureTargetClosed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCapture) consume_Windows_Media_Capture_IAppCaptureStatics<D>::GetForCurrentView() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureStatics)->GetForCurrentView(&value));
        return winrt::Windows::Media::Capture::AppCapture{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IAppCaptureStatics2<D>::SetAllowedAsync(bool allowed) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IAppCaptureStatics2)->SetAllowedAsync(allowed, &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CameraCaptureUIPhotoCaptureSettings) consume_Windows_Media_Capture_ICameraCaptureUI<D>::PhotoSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUI)->get_PhotoSettings(&value));
        return winrt::Windows::Media::Capture::CameraCaptureUIPhotoCaptureSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CameraCaptureUIVideoCaptureSettings) consume_Windows_Media_Capture_ICameraCaptureUI<D>::VideoSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUI)->get_VideoSettings(&value));
        return winrt::Windows::Media::Capture::CameraCaptureUIVideoCaptureSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Media_Capture_ICameraCaptureUI<D>::CaptureFileAsync(winrt::Windows::Media::Capture::CameraCaptureUIMode const& mode) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUI)->CaptureFileAsync(static_cast<int32_t>(mode), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CameraCaptureUIPhotoFormat) consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::Format() const
    {
        winrt::Windows::Media::Capture::CameraCaptureUIPhotoFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->get_Format(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::Format(winrt::Windows::Media::Capture::CameraCaptureUIPhotoFormat const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->put_Format(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution) consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::MaxResolution() const
    {
        winrt::Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->get_MaxResolution(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::MaxResolution(winrt::Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->put_MaxResolution(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::CroppedSizeInPixels() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->get_CroppedSizeInPixels(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::CroppedSizeInPixels(winrt::Windows::Foundation::Size const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->put_CroppedSizeInPixels(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::CroppedAspectRatio() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->get_CroppedAspectRatio(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::CroppedAspectRatio(winrt::Windows::Foundation::Size const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->put_CroppedAspectRatio(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::AllowCropping() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->get_AllowCropping(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::AllowCropping(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->put_AllowCropping(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CameraCaptureUIVideoFormat) consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::Format() const
    {
        winrt::Windows::Media::Capture::CameraCaptureUIVideoFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->get_Format(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::Format(winrt::Windows::Media::Capture::CameraCaptureUIVideoFormat const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->put_Format(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CameraCaptureUIMaxVideoResolution) consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::MaxResolution() const
    {
        winrt::Windows::Media::Capture::CameraCaptureUIMaxVideoResolution value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->get_MaxResolution(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::MaxResolution(winrt::Windows::Media::Capture::CameraCaptureUIMaxVideoResolution const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->put_MaxResolution(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::MaxDurationInSeconds() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->get_MaxDurationInSeconds(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::MaxDurationInSeconds(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->put_MaxDurationInSeconds(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::AllowTrimming() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->get_AllowTrimming(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::AllowTrimming(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->put_AllowTrimming(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_ICameraOptionsUIStatics<D>::Show(winrt::Windows::Media::Capture::MediaCapture const& mediaCapture) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICameraOptionsUIStatics)->Show(*(void**)(&mediaCapture)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_ICapturedFrame<D>::Width() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrame)->get_Width(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_ICapturedFrame<D>::Height() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrame)->get_Height(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CapturedFrameControlValues) consume_Windows_Media_Capture_ICapturedFrame2<D>::ControlValues() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrame2)->get_ControlValues(&value));
        return winrt::Windows::Media::Capture::CapturedFrameControlValues{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Imaging::BitmapPropertySet) consume_Windows_Media_Capture_ICapturedFrame2<D>::BitmapProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrame2)->get_BitmapProperties(&value));
        return winrt::Windows::Graphics::Imaging::BitmapPropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::Exposure() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues)->get_Exposure(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<float>) consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::ExposureCompensation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues)->get_ExposureCompensation(&value));
        return winrt::Windows::Foundation::IReference<float>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::IsoSpeed() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues)->get_IsoSpeed(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::Focus() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues)->get_Focus(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Media::Devices::CaptureSceneMode>) consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::SceneMode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues)->get_SceneMode(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Media::Devices::CaptureSceneMode>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<bool>) consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::Flashed() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues)->get_Flashed(&value));
        return winrt::Windows::Foundation::IReference<bool>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<float>) consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::FlashPowerPercent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues)->get_FlashPowerPercent(&value));
        return winrt::Windows::Foundation::IReference<float>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::WhiteBalance() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues)->get_WhiteBalance(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<float>) consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::ZoomFactor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues)->get_ZoomFactor(&value));
        return winrt::Windows::Foundation::IReference<float>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Media::Devices::MediaCaptureFocusState>) consume_Windows_Media_Capture_ICapturedFrameControlValues2<D>::FocusState() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues2)->get_FocusState(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Media::Devices::MediaCaptureFocusState>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) consume_Windows_Media_Capture_ICapturedFrameControlValues2<D>::IsoDigitalGain() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues2)->get_IsoDigitalGain(&value));
        return winrt::Windows::Foundation::IReference<double>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) consume_Windows_Media_Capture_ICapturedFrameControlValues2<D>::IsoAnalogGain() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues2)->get_IsoAnalogGain(&value));
        return winrt::Windows::Foundation::IReference<double>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaRatio) consume_Windows_Media_Capture_ICapturedFrameControlValues2<D>::SensorFrameRate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues2)->get_SensorFrameRate(&value));
        return winrt::Windows::Media::MediaProperties::MediaRatio{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Media::Capture::WhiteBalanceGain>) consume_Windows_Media_Capture_ICapturedFrameControlValues2<D>::WhiteBalanceGain() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameControlValues2)->get_WhiteBalanceGain(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Media::Capture::WhiteBalanceGain>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Imaging::SoftwareBitmap) consume_Windows_Media_Capture_ICapturedFrameWithSoftwareBitmap<D>::SoftwareBitmap() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedFrameWithSoftwareBitmap)->get_SoftwareBitmap(&value));
        return winrt::Windows::Graphics::Imaging::SoftwareBitmap{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CapturedFrame) consume_Windows_Media_Capture_ICapturedPhoto<D>::Frame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedPhoto)->get_Frame(&value));
        return winrt::Windows::Media::Capture::CapturedFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CapturedFrame) consume_Windows_Media_Capture_ICapturedPhoto<D>::Thumbnail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ICapturedPhoto)->get_Thumbnail(&value));
        return winrt::Windows::Media::Capture::CapturedFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::GameBarTargetCapturePolicy) consume_Windows_Media_Capture_IGameBarServices<D>::TargetCapturePolicy() const
    {
        winrt::Windows::Media::Capture::GameBarTargetCapturePolicy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServices)->get_TargetCapturePolicy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IGameBarServices<D>::EnableCapture() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServices)->EnableCapture());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IGameBarServices<D>::DisableCapture() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServices)->DisableCapture());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::GameBarServicesTargetInfo) consume_Windows_Media_Capture_IGameBarServices<D>::TargetInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServices)->get_TargetInfo(&value));
        return winrt::Windows::Media::Capture::GameBarServicesTargetInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IGameBarServices<D>::SessionId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServices)->get_SessionId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppBroadcastServices) consume_Windows_Media_Capture_IGameBarServices<D>::AppBroadcastServices() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServices)->get_AppBroadcastServices(&value));
        return winrt::Windows::Media::Capture::AppBroadcastServices{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::AppCaptureServices) consume_Windows_Media_Capture_IGameBarServices<D>::AppCaptureServices() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServices)->get_AppCaptureServices(&value));
        return winrt::Windows::Media::Capture::AppCaptureServices{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IGameBarServices<D>::CommandReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::GameBarServices, winrt::Windows::Media::Capture::GameBarServicesCommandEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServices)->add_CommandReceived(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IGameBarServices<D>::CommandReceived_revoker consume_Windows_Media_Capture_IGameBarServices<D>::CommandReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::GameBarServices, winrt::Windows::Media::Capture::GameBarServicesCommandEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, CommandReceived_revoker>(this, CommandReceived(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IGameBarServices<D>::CommandReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServices)->remove_CommandReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::GameBarCommand) consume_Windows_Media_Capture_IGameBarServicesCommandEventArgs<D>::Command() const
    {
        winrt::Windows::Media::Capture::GameBarCommand value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServicesCommandEventArgs)->get_Command(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::GameBarCommandOrigin) consume_Windows_Media_Capture_IGameBarServicesCommandEventArgs<D>::Origin() const
    {
        winrt::Windows::Media::Capture::GameBarCommandOrigin value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServicesCommandEventArgs)->get_Origin(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IGameBarServicesManager<D>::GameBarServicesCreated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::GameBarServicesManager, winrt::Windows::Media::Capture::GameBarServicesManagerGameBarServicesCreatedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServicesManager)->add_GameBarServicesCreated(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IGameBarServicesManager<D>::GameBarServicesCreated_revoker consume_Windows_Media_Capture_IGameBarServicesManager<D>::GameBarServicesCreated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::GameBarServicesManager, winrt::Windows::Media::Capture::GameBarServicesManagerGameBarServicesCreatedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, GameBarServicesCreated_revoker>(this, GameBarServicesCreated(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IGameBarServicesManager<D>::GameBarServicesCreated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServicesManager)->remove_GameBarServicesCreated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::GameBarServices) consume_Windows_Media_Capture_IGameBarServicesManagerGameBarServicesCreatedEventArgs<D>::GameBarServices() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServicesManagerGameBarServicesCreatedEventArgs)->get_GameBarServices(&value));
        return winrt::Windows::Media::Capture::GameBarServices{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::GameBarServicesManager) consume_Windows_Media_Capture_IGameBarServicesManagerStatics<D>::GetDefault() const
    {
        void* ppInstance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServicesManagerStatics)->GetDefault(&ppInstance));
        return winrt::Windows::Media::Capture::GameBarServicesManager{ ppInstance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IGameBarServicesTargetInfo<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServicesTargetInfo)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IGameBarServicesTargetInfo<D>::AppId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServicesTargetInfo)->get_AppId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IGameBarServicesTargetInfo<D>::TitleId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServicesTargetInfo)->get_TitleId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::GameBarServicesDisplayMode) consume_Windows_Media_Capture_IGameBarServicesTargetInfo<D>::DisplayMode() const
    {
        winrt::Windows::Media::Capture::GameBarServicesDisplayMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IGameBarServicesTargetInfo)->get_DisplayMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_ILowLagMediaRecording<D>::StartAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagMediaRecording)->StartAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_ILowLagMediaRecording<D>::StopAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagMediaRecording)->StopAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_ILowLagMediaRecording<D>::FinishAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagMediaRecording)->FinishAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_ILowLagMediaRecording2<D>::PauseAsync(winrt::Windows::Media::Devices::MediaCapturePauseBehavior const& behavior) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagMediaRecording2)->PauseAsync(static_cast<int32_t>(behavior), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_ILowLagMediaRecording2<D>::ResumeAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagMediaRecording2)->ResumeAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::MediaCapturePauseResult>) consume_Windows_Media_Capture_ILowLagMediaRecording3<D>::PauseWithResultAsync(winrt::Windows::Media::Devices::MediaCapturePauseBehavior const& behavior) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagMediaRecording3)->PauseWithResultAsync(static_cast<int32_t>(behavior), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::MediaCapturePauseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::MediaCaptureStopResult>) consume_Windows_Media_Capture_ILowLagMediaRecording3<D>::StopWithResultAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagMediaRecording3)->StopWithResultAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::MediaCaptureStopResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::CapturedPhoto>) consume_Windows_Media_Capture_ILowLagPhotoCapture<D>::CaptureAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagPhotoCapture)->CaptureAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::CapturedPhoto>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_ILowLagPhotoCapture<D>::FinishAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagPhotoCapture)->FinishAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::StartAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagPhotoSequenceCapture)->StartAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::StopAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagPhotoSequenceCapture)->StopAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::FinishAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagPhotoSequenceCapture)->FinishAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::PhotoCaptured(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::LowLagPhotoSequenceCapture, winrt::Windows::Media::Capture::PhotoCapturedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagPhotoSequenceCapture)->add_PhotoCaptured(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::PhotoCaptured_revoker consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::PhotoCaptured(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::LowLagPhotoSequenceCapture, winrt::Windows::Media::Capture::PhotoCapturedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PhotoCaptured_revoker>(this, PhotoCaptured(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::PhotoCaptured(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::ILowLagPhotoSequenceCapture)->remove_PhotoCaptured(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture<D>::InitializeAsync() const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->InitializeAsync(&asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture<D>::InitializeAsync(winrt::Windows::Media::Capture::MediaCaptureInitializationSettings const& mediaCaptureInitializationSettings) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->InitializeWithSettingsAsync(*(void**)(&mediaCaptureInitializationSettings), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture<D>::StartRecordToStorageFileAsync(winrt::Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->StartRecordToStorageFileAsync(*(void**)(&encodingProfile), *(void**)(&file), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture<D>::StartRecordToStreamAsync(winrt::Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, winrt::Windows::Storage::Streams::IRandomAccessStream const& stream) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->StartRecordToStreamAsync(*(void**)(&encodingProfile), *(void**)(&stream), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture<D>::StartRecordToCustomSinkAsync(winrt::Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, winrt::Windows::Media::IMediaExtension const& customMediaSink) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->StartRecordToCustomSinkAsync(*(void**)(&encodingProfile), *(void**)(&customMediaSink), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture<D>::StartRecordToCustomSinkAsync(winrt::Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, param::hstring const& customSinkActivationId, winrt::Windows::Foundation::Collections::IPropertySet const& customSinkSettings) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->StartRecordToCustomSinkIdAsync(*(void**)(&encodingProfile), *(void**)(&customSinkActivationId), *(void**)(&customSinkSettings), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture<D>::StopRecordAsync() const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->StopRecordAsync(&asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture<D>::CapturePhotoToStorageFileAsync(winrt::Windows::Media::MediaProperties::ImageEncodingProperties const& type, winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->CapturePhotoToStorageFileAsync(*(void**)(&type), *(void**)(&file), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture<D>::CapturePhotoToStreamAsync(winrt::Windows::Media::MediaProperties::ImageEncodingProperties const& type, winrt::Windows::Storage::Streams::IRandomAccessStream const& stream) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->CapturePhotoToStreamAsync(*(void**)(&type), *(void**)(&stream), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture<D>::AddEffectAsync(winrt::Windows::Media::Capture::MediaStreamType const& mediaStreamType, param::hstring const& effectActivationID, winrt::Windows::Foundation::Collections::IPropertySet const& effectSettings) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->AddEffectAsync(static_cast<int32_t>(mediaStreamType), *(void**)(&effectActivationID), *(void**)(&effectSettings), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture<D>::ClearEffectsAsync(winrt::Windows::Media::Capture::MediaStreamType const& mediaStreamType) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->ClearEffectsAsync(static_cast<int32_t>(mediaStreamType), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCapture<D>::SetEncoderProperty(winrt::Windows::Media::Capture::MediaStreamType const& mediaStreamType, winrt::guid const& propertyId, winrt::Windows::Foundation::IInspectable const& propertyValue) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->SetEncoderProperty(static_cast<int32_t>(mediaStreamType), impl::bind_in(propertyId), *(void**)(&propertyValue)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_Media_Capture_IMediaCapture<D>::GetEncoderProperty(winrt::Windows::Media::Capture::MediaStreamType const& mediaStreamType, winrt::guid const& propertyId) const
    {
        void* propertyValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->GetEncoderProperty(static_cast<int32_t>(mediaStreamType), impl::bind_in(propertyId), &propertyValue));
        return winrt::Windows::Foundation::IInspectable{ propertyValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IMediaCapture<D>::Failed(winrt::Windows::Media::Capture::MediaCaptureFailedEventHandler const& errorEventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->add_Failed(*(void**)(&errorEventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Media_Capture_IMediaCapture<D>::Failed_revoker consume_Windows_Media_Capture_IMediaCapture<D>::Failed(auto_revoke_t, winrt::Windows::Media::Capture::MediaCaptureFailedEventHandler const& errorEventHandler) const
    {
        return impl::make_event_revoker<D, Failed_revoker>(this, Failed(errorEventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCapture<D>::Failed(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->remove_Failed(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IMediaCapture<D>::RecordLimitationExceeded(winrt::Windows::Media::Capture::RecordLimitationExceededEventHandler const& recordLimitationExceededEventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->add_RecordLimitationExceeded(*(void**)(&recordLimitationExceededEventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Media_Capture_IMediaCapture<D>::RecordLimitationExceeded_revoker consume_Windows_Media_Capture_IMediaCapture<D>::RecordLimitationExceeded(auto_revoke_t, winrt::Windows::Media::Capture::RecordLimitationExceededEventHandler const& recordLimitationExceededEventHandler) const
    {
        return impl::make_event_revoker<D, RecordLimitationExceeded_revoker>(this, RecordLimitationExceeded(recordLimitationExceededEventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCapture<D>::RecordLimitationExceeded(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->remove_RecordLimitationExceeded(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::MediaCaptureSettings) consume_Windows_Media_Capture_IMediaCapture<D>::MediaCaptureSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->get_MediaCaptureSettings(&value));
        return winrt::Windows::Media::Capture::MediaCaptureSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Devices::AudioDeviceController) consume_Windows_Media_Capture_IMediaCapture<D>::AudioDeviceController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->get_AudioDeviceController(&value));
        return winrt::Windows::Media::Devices::AudioDeviceController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Devices::VideoDeviceController) consume_Windows_Media_Capture_IMediaCapture<D>::VideoDeviceController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->get_VideoDeviceController(&value));
        return winrt::Windows::Media::Devices::VideoDeviceController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCapture<D>::SetPreviewMirroring(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->SetPreviewMirroring(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IMediaCapture<D>::GetPreviewMirroring() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->GetPreviewMirroring(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCapture<D>::SetPreviewRotation(winrt::Windows::Media::Capture::VideoRotation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->SetPreviewRotation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::VideoRotation) consume_Windows_Media_Capture_IMediaCapture<D>::GetPreviewRotation() const
    {
        winrt::Windows::Media::Capture::VideoRotation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->GetPreviewRotation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCapture<D>::SetRecordRotation(winrt::Windows::Media::Capture::VideoRotation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->SetRecordRotation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::VideoRotation) consume_Windows_Media_Capture_IMediaCapture<D>::GetRecordRotation() const
    {
        winrt::Windows::Media::Capture::VideoRotation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture)->GetRecordRotation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagMediaRecording>) consume_Windows_Media_Capture_IMediaCapture2<D>::PrepareLowLagRecordToStorageFileAsync(winrt::Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture2)->PrepareLowLagRecordToStorageFileAsync(*(void**)(&encodingProfile), *(void**)(&file), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagMediaRecording>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagMediaRecording>) consume_Windows_Media_Capture_IMediaCapture2<D>::PrepareLowLagRecordToStreamAsync(winrt::Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, winrt::Windows::Storage::Streams::IRandomAccessStream const& stream) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture2)->PrepareLowLagRecordToStreamAsync(*(void**)(&encodingProfile), *(void**)(&stream), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagMediaRecording>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagMediaRecording>) consume_Windows_Media_Capture_IMediaCapture2<D>::PrepareLowLagRecordToCustomSinkAsync(winrt::Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, winrt::Windows::Media::IMediaExtension const& customMediaSink) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture2)->PrepareLowLagRecordToCustomSinkAsync(*(void**)(&encodingProfile), *(void**)(&customMediaSink), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagMediaRecording>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagMediaRecording>) consume_Windows_Media_Capture_IMediaCapture2<D>::PrepareLowLagRecordToCustomSinkAsync(winrt::Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, param::hstring const& customSinkActivationId, winrt::Windows::Foundation::Collections::IPropertySet const& customSinkSettings) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture2)->PrepareLowLagRecordToCustomSinkIdAsync(*(void**)(&encodingProfile), *(void**)(&customSinkActivationId), *(void**)(&customSinkSettings), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagMediaRecording>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagPhotoCapture>) consume_Windows_Media_Capture_IMediaCapture2<D>::PrepareLowLagPhotoCaptureAsync(winrt::Windows::Media::MediaProperties::ImageEncodingProperties const& type) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture2)->PrepareLowLagPhotoCaptureAsync(*(void**)(&type), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagPhotoCapture>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagPhotoSequenceCapture>) consume_Windows_Media_Capture_IMediaCapture2<D>::PrepareLowLagPhotoSequenceCaptureAsync(winrt::Windows::Media::MediaProperties::ImageEncodingProperties const& type) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture2)->PrepareLowLagPhotoSequenceCaptureAsync(*(void**)(&type), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagPhotoSequenceCapture>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture2<D>::SetEncodingPropertiesAsync(winrt::Windows::Media::Capture::MediaStreamType const& mediaStreamType, winrt::Windows::Media::MediaProperties::IMediaEncodingProperties const& mediaEncodingProperties, winrt::Windows::Media::MediaProperties::MediaPropertySet const& encoderProperties) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture2)->SetEncodingPropertiesAsync(static_cast<int32_t>(mediaStreamType), *(void**)(&mediaEncodingProperties), *(void**)(&encoderProperties), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Core::VariablePhotoSequenceCapture>) consume_Windows_Media_Capture_IMediaCapture3<D>::PrepareVariablePhotoSequenceCaptureAsync(winrt::Windows::Media::MediaProperties::ImageEncodingProperties const& type) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture3)->PrepareVariablePhotoSequenceCaptureAsync(*(void**)(&type), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Core::VariablePhotoSequenceCapture>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IMediaCapture3<D>::FocusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Media::Capture::MediaCaptureFocusChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture3)->add_FocusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IMediaCapture3<D>::FocusChanged_revoker consume_Windows_Media_Capture_IMediaCapture3<D>::FocusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Media::Capture::MediaCaptureFocusChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, FocusChanged_revoker>(this, FocusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCapture3<D>::FocusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture3)->remove_FocusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IMediaCapture3<D>::PhotoConfirmationCaptured(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Media::Capture::PhotoConfirmationCapturedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture3)->add_PhotoConfirmationCaptured(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IMediaCapture3<D>::PhotoConfirmationCaptured_revoker consume_Windows_Media_Capture_IMediaCapture3<D>::PhotoConfirmationCaptured(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Media::Capture::PhotoConfirmationCapturedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PhotoConfirmationCaptured_revoker>(this, PhotoConfirmationCaptured(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCapture3<D>::PhotoConfirmationCaptured(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture3)->remove_PhotoConfirmationCaptured(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::IMediaExtension>) consume_Windows_Media_Capture_IMediaCapture4<D>::AddAudioEffectAsync(winrt::Windows::Media::Effects::IAudioEffectDefinition const& definition) const
    {
        void* op{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture4)->AddAudioEffectAsync(*(void**)(&definition), &op));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::IMediaExtension>{ op, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::IMediaExtension>) consume_Windows_Media_Capture_IMediaCapture4<D>::AddVideoEffectAsync(winrt::Windows::Media::Effects::IVideoEffectDefinition const& definition, winrt::Windows::Media::Capture::MediaStreamType const& mediaStreamType) const
    {
        void* op{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture4)->AddVideoEffectAsync(*(void**)(&definition), static_cast<int32_t>(mediaStreamType), &op));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::IMediaExtension>{ op, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture4<D>::PauseRecordAsync(winrt::Windows::Media::Devices::MediaCapturePauseBehavior const& behavior) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture4)->PauseRecordAsync(static_cast<int32_t>(behavior), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture4<D>::ResumeRecordAsync() const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture4)->ResumeRecordAsync(&asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IMediaCapture4<D>::CameraStreamStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture4)->add_CameraStreamStateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IMediaCapture4<D>::CameraStreamStateChanged_revoker consume_Windows_Media_Capture_IMediaCapture4<D>::CameraStreamStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, CameraStreamStateChanged_revoker>(this, CameraStreamStateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCapture4<D>::CameraStreamStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture4)->remove_CameraStreamStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Devices::CameraStreamState) consume_Windows_Media_Capture_IMediaCapture4<D>::CameraStreamState() const
    {
        winrt::Windows::Media::Devices::CameraStreamState streamState{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture4)->get_CameraStreamState(reinterpret_cast<int32_t*>(&streamState)));
        return streamState;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::VideoFrame>) consume_Windows_Media_Capture_IMediaCapture4<D>::GetPreviewFrameAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture4)->GetPreviewFrameAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::VideoFrame>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::VideoFrame>) consume_Windows_Media_Capture_IMediaCapture4<D>::GetPreviewFrameAsync(winrt::Windows::Media::VideoFrame const& destination) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture4)->GetPreviewFrameCopyAsync(*(void**)(&destination), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::VideoFrame>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IMediaCapture4<D>::ThermalStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture4)->add_ThermalStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IMediaCapture4<D>::ThermalStatusChanged_revoker consume_Windows_Media_Capture_IMediaCapture4<D>::ThermalStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ThermalStatusChanged_revoker>(this, ThermalStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCapture4<D>::ThermalStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture4)->remove_ThermalStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::MediaCaptureThermalStatus) consume_Windows_Media_Capture_IMediaCapture4<D>::ThermalStatus() const
    {
        winrt::Windows::Media::Capture::MediaCaptureThermalStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture4)->get_ThermalStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::AdvancedPhotoCapture>) consume_Windows_Media_Capture_IMediaCapture4<D>::PrepareAdvancedPhotoCaptureAsync(winrt::Windows::Media::MediaProperties::ImageEncodingProperties const& encodingProperties) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture4)->PrepareAdvancedPhotoCaptureAsync(*(void**)(&encodingProperties), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::AdvancedPhotoCapture>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCapture5<D>::RemoveEffectAsync(winrt::Windows::Media::IMediaExtension const& effect) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture5)->RemoveEffectAsync(*(void**)(&effect), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::MediaCapturePauseResult>) consume_Windows_Media_Capture_IMediaCapture5<D>::PauseRecordWithResultAsync(winrt::Windows::Media::Devices::MediaCapturePauseBehavior const& behavior) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture5)->PauseRecordWithResultAsync(static_cast<int32_t>(behavior), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::MediaCapturePauseResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::MediaCaptureStopResult>) consume_Windows_Media_Capture_IMediaCapture5<D>::StopRecordWithResultAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture5)->StopRecordWithResultAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::MediaCaptureStopResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Media::Capture::Frames::MediaFrameSource>) consume_Windows_Media_Capture_IMediaCapture5<D>::FrameSources() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture5)->get_FrameSources(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Media::Capture::Frames::MediaFrameSource>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameReader>) consume_Windows_Media_Capture_IMediaCapture5<D>::CreateFrameReaderAsync(winrt::Windows::Media::Capture::Frames::MediaFrameSource const& inputSource) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture5)->CreateFrameReaderAsync(*(void**)(&inputSource), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameReader>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameReader>) consume_Windows_Media_Capture_IMediaCapture5<D>::CreateFrameReaderAsync(winrt::Windows::Media::Capture::Frames::MediaFrameSource const& inputSource, param::hstring const& outputSubtype) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture5)->CreateFrameReaderWithSubtypeAsync(*(void**)(&inputSource), *(void**)(&outputSubtype), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameReader>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameReader>) consume_Windows_Media_Capture_IMediaCapture5<D>::CreateFrameReaderAsync(winrt::Windows::Media::Capture::Frames::MediaFrameSource const& inputSource, param::hstring const& outputSubtype, winrt::Windows::Graphics::Imaging::BitmapSize const& outputSize) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture5)->CreateFrameReaderWithSubtypeAndSizeAsync(*(void**)(&inputSource), *(void**)(&outputSubtype), impl::bind_in(outputSize), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameReader>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IMediaCapture6<D>::CaptureDeviceExclusiveControlStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatusChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture6)->add_CaptureDeviceExclusiveControlStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IMediaCapture6<D>::CaptureDeviceExclusiveControlStatusChanged_revoker consume_Windows_Media_Capture_IMediaCapture6<D>::CaptureDeviceExclusiveControlStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatusChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CaptureDeviceExclusiveControlStatusChanged_revoker>(this, CaptureDeviceExclusiveControlStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCapture6<D>::CaptureDeviceExclusiveControlStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture6)->remove_CaptureDeviceExclusiveControlStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReader>) consume_Windows_Media_Capture_IMediaCapture6<D>::CreateMultiSourceFrameReaderAsync(param::async_iterable<winrt::Windows::Media::Capture::Frames::MediaFrameSource> const& inputSources) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture6)->CreateMultiSourceFrameReaderAsync(*(void**)(&inputSources), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReader>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::MediaCaptureRelativePanelWatcher) consume_Windows_Media_Capture_IMediaCapture7<D>::CreateRelativePanelWatcher(winrt::Windows::Media::Capture::StreamingCaptureMode const& captureMode, winrt::Windows::UI::WindowManagement::DisplayRegion const& displayRegion) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapture7)->CreateRelativePanelWatcher(static_cast<int32_t>(captureMode), *(void**)(&displayRegion), &result));
        return winrt::Windows::Media::Capture::MediaCaptureRelativePanelWatcher{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatus) consume_Windows_Media_Capture_IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs<D>::Status() const
    {
        winrt::Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IMediaCaptureFailedEventArgs<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureFailedEventArgs)->get_Message(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IMediaCaptureFailedEventArgs<D>::Code() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureFailedEventArgs)->get_Code(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Devices::MediaCaptureFocusState) consume_Windows_Media_Capture_IMediaCaptureFocusChangedEventArgs<D>::FocusState() const
    {
        winrt::Windows::Media::Devices::MediaCaptureFocusState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureFocusChangedEventArgs)->get_FocusState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::AudioDeviceId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings)->put_AudioDeviceId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::AudioDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings)->get_AudioDeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::VideoDeviceId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings)->put_VideoDeviceId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::VideoDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings)->get_VideoDeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::StreamingCaptureMode(winrt::Windows::Media::Capture::StreamingCaptureMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings)->put_StreamingCaptureMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::StreamingCaptureMode) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::StreamingCaptureMode() const
    {
        winrt::Windows::Media::Capture::StreamingCaptureMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings)->get_StreamingCaptureMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::PhotoCaptureSource(winrt::Windows::Media::Capture::PhotoCaptureSource const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings)->put_PhotoCaptureSource(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::PhotoCaptureSource) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::PhotoCaptureSource() const
    {
        winrt::Windows::Media::Capture::PhotoCaptureSource value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings)->get_PhotoCaptureSource(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings2<D>::MediaCategory(winrt::Windows::Media::Capture::MediaCategory const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings2)->put_MediaCategory(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::MediaCategory) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings2<D>::MediaCategory() const
    {
        winrt::Windows::Media::Capture::MediaCategory value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings2)->get_MediaCategory(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings2<D>::AudioProcessing(winrt::Windows::Media::AudioProcessing const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings2)->put_AudioProcessing(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AudioProcessing) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings2<D>::AudioProcessing() const
    {
        winrt::Windows::Media::AudioProcessing value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings2)->get_AudioProcessing(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings3<D>::AudioSource(winrt::Windows::Media::Core::IMediaSource const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings3)->put_AudioSource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::IMediaSource) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings3<D>::AudioSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings3)->get_AudioSource(&value));
        return winrt::Windows::Media::Core::IMediaSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings3<D>::VideoSource(winrt::Windows::Media::Core::IMediaSource const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings3)->put_VideoSource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::IMediaSource) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings3<D>::VideoSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings3)->get_VideoSource(&value));
        return winrt::Windows::Media::Core::IMediaSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::MediaCaptureVideoProfile) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::VideoProfile() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings4)->get_VideoProfile(&value));
        return winrt::Windows::Media::Capture::MediaCaptureVideoProfile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::VideoProfile(winrt::Windows::Media::Capture::MediaCaptureVideoProfile const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings4)->put_VideoProfile(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::PreviewMediaDescription() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings4)->get_PreviewMediaDescription(&value));
        return winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::PreviewMediaDescription(winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings4)->put_PreviewMediaDescription(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::RecordMediaDescription() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings4)->get_RecordMediaDescription(&value));
        return winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::RecordMediaDescription(winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings4)->put_RecordMediaDescription(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::PhotoMediaDescription() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings4)->get_PhotoMediaDescription(&value));
        return winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::PhotoMediaDescription(winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings4)->put_PhotoMediaDescription(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings5<D>::SourceGroup() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings5)->get_SourceGroup(&value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings5<D>::SourceGroup(winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings5)->put_SourceGroup(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::MediaCaptureSharingMode) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings5<D>::SharingMode() const
    {
        winrt::Windows::Media::Capture::MediaCaptureSharingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings5)->get_SharingMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings5<D>::SharingMode(winrt::Windows::Media::Capture::MediaCaptureSharingMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings5)->put_SharingMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::MediaCaptureMemoryPreference) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings5<D>::MemoryPreference() const
    {
        winrt::Windows::Media::Capture::MediaCaptureMemoryPreference value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings5)->get_MemoryPreference(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings5<D>::MemoryPreference(winrt::Windows::Media::Capture::MediaCaptureMemoryPreference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings5)->put_MemoryPreference(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings6<D>::AlwaysPlaySystemShutterSound() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings6)->get_AlwaysPlaySystemShutterSound(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings6<D>::AlwaysPlaySystemShutterSound(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings6)->put_AlwaysPlaySystemShutterSound(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings7<D>::DeviceUriPasswordCredential() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings7)->get_DeviceUriPasswordCredential(&value));
        return winrt::Windows::Security::Credentials::PasswordCredential{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings7<D>::DeviceUriPasswordCredential(winrt::Windows::Security::Credentials::PasswordCredential const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings7)->put_DeviceUriPasswordCredential(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings7<D>::DeviceUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings7)->get_DeviceUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureInitializationSettings7<D>::DeviceUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings7)->put_DeviceUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoFrame) consume_Windows_Media_Capture_IMediaCapturePauseResult<D>::LastFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapturePauseResult)->get_LastFrame(&value));
        return winrt::Windows::Media::VideoFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Capture_IMediaCapturePauseResult<D>::RecordDuration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCapturePauseResult)->get_RecordDuration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::Panel) consume_Windows_Media_Capture_IMediaCaptureRelativePanelWatcher<D>::RelativePanel() const
    {
        winrt::Windows::Devices::Enumeration::Panel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureRelativePanelWatcher)->get_RelativePanel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_IMediaCaptureRelativePanelWatcher<D>::Changed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCaptureRelativePanelWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureRelativePanelWatcher)->add_Changed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_IMediaCaptureRelativePanelWatcher<D>::Changed_revoker consume_Windows_Media_Capture_IMediaCaptureRelativePanelWatcher<D>::Changed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCaptureRelativePanelWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureRelativePanelWatcher<D>::Changed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureRelativePanelWatcher)->remove_Changed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureRelativePanelWatcher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureRelativePanelWatcher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_IMediaCaptureRelativePanelWatcher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureRelativePanelWatcher)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IMediaCaptureSettings<D>::AudioDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings)->get_AudioDeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IMediaCaptureSettings<D>::VideoDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings)->get_VideoDeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::StreamingCaptureMode) consume_Windows_Media_Capture_IMediaCaptureSettings<D>::StreamingCaptureMode() const
    {
        winrt::Windows::Media::Capture::StreamingCaptureMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings)->get_StreamingCaptureMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::PhotoCaptureSource) consume_Windows_Media_Capture_IMediaCaptureSettings<D>::PhotoCaptureSource() const
    {
        winrt::Windows::Media::Capture::PhotoCaptureSource value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings)->get_PhotoCaptureSource(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::VideoDeviceCharacteristic) consume_Windows_Media_Capture_IMediaCaptureSettings<D>::VideoDeviceCharacteristic() const
    {
        winrt::Windows::Media::Capture::VideoDeviceCharacteristic value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings)->get_VideoDeviceCharacteristic(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::ConcurrentRecordAndPhotoSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings2)->get_ConcurrentRecordAndPhotoSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::ConcurrentRecordAndPhotoSequenceSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings2)->get_ConcurrentRecordAndPhotoSequenceSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::CameraSoundRequiredForRegion() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings2)->get_CameraSoundRequiredForRegion(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::Horizontal35mmEquivalentFocalLength() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings2)->get_Horizontal35mmEquivalentFocalLength(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::PitchOffsetDegrees() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings2)->get_PitchOffsetDegrees(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::Vertical35mmEquivalentFocalLength() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings2)->get_Vertical35mmEquivalentFocalLength(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::MediaCategory) consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::MediaCategory() const
    {
        winrt::Windows::Media::Capture::MediaCategory value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings2)->get_MediaCategory(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AudioProcessing) consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::AudioProcessing() const
    {
        winrt::Windows::Media::AudioProcessing value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings2)->get_AudioProcessing(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice) consume_Windows_Media_Capture_IMediaCaptureSettings3<D>::Direct3D11Device() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureSettings3)->get_Direct3D11Device(&value));
        return winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IMediaCaptureStatics<D>::IsVideoProfileSupported(param::hstring const& videoDeviceId) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureStatics)->IsVideoProfileSupported(*(void**)(&videoDeviceId), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfile>) consume_Windows_Media_Capture_IMediaCaptureStatics<D>::FindAllVideoProfiles(param::hstring const& videoDeviceId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureStatics)->FindAllVideoProfiles(*(void**)(&videoDeviceId), &value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfile>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfile>) consume_Windows_Media_Capture_IMediaCaptureStatics<D>::FindConcurrentProfiles(param::hstring const& videoDeviceId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureStatics)->FindConcurrentProfiles(*(void**)(&videoDeviceId), &value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfile>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfile>) consume_Windows_Media_Capture_IMediaCaptureStatics<D>::FindKnownVideoProfiles(param::hstring const& videoDeviceId, winrt::Windows::Media::Capture::KnownVideoProfile const& name) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureStatics)->FindKnownVideoProfiles(*(void**)(&videoDeviceId), static_cast<int32_t>(name), &value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfile>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoFrame) consume_Windows_Media_Capture_IMediaCaptureStopResult<D>::LastFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureStopResult)->get_LastFrame(&value));
        return winrt::Windows::Media::VideoFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Capture_IMediaCaptureStopResult<D>::RecordDuration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureStopResult)->get_RecordDuration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCaptureVideoPreview<D>::StartPreviewAsync() const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoPreview)->StartPreviewAsync(&asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCaptureVideoPreview<D>::StartPreviewToCustomSinkAsync(winrt::Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, winrt::Windows::Media::IMediaExtension const& customMediaSink) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoPreview)->StartPreviewToCustomSinkAsync(*(void**)(&encodingProfile), *(void**)(&customMediaSink), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCaptureVideoPreview<D>::StartPreviewToCustomSinkAsync(winrt::Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, param::hstring const& customSinkActivationId, winrt::Windows::Foundation::Collections::IPropertySet const& customSinkSettings) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoPreview)->StartPreviewToCustomSinkIdAsync(*(void**)(&encodingProfile), *(void**)(&customSinkActivationId), *(void**)(&customSinkSettings), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_IMediaCaptureVideoPreview<D>::StopPreviewAsync() const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoPreview)->StopPreviewAsync(&asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IMediaCaptureVideoProfile<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfile)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IMediaCaptureVideoProfile<D>::VideoDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfile)->get_VideoDeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>) consume_Windows_Media_Capture_IMediaCaptureVideoProfile<D>::SupportedPreviewMediaDescription() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfile)->get_SupportedPreviewMediaDescription(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>) consume_Windows_Media_Capture_IMediaCaptureVideoProfile<D>::SupportedRecordMediaDescription() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfile)->get_SupportedRecordMediaDescription(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>) consume_Windows_Media_Capture_IMediaCaptureVideoProfile<D>::SupportedPhotoMediaDescription() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfile)->get_SupportedPhotoMediaDescription(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfile>) consume_Windows_Media_Capture_IMediaCaptureVideoProfile<D>::GetConcurrency() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfile)->GetConcurrency(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfile>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::Frames::MediaFrameSourceInfo>) consume_Windows_Media_Capture_IMediaCaptureVideoProfile2<D>::FrameSourceInfos() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfile2)->get_FrameSourceInfos(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::Frames::MediaFrameSourceInfo>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>) consume_Windows_Media_Capture_IMediaCaptureVideoProfile2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfile2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription<D>::Width() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription)->get_Width(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription<D>::Height() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription)->get_Height(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription<D>::FrameRate() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription)->get_FrameRate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription<D>::IsVariablePhotoSequenceSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription)->get_IsVariablePhotoSequenceSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription<D>::IsHdrVideoSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription)->get_IsHdrVideoSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription2<D>::Subtype() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription2)->get_Subtype(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>) consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CapturedFrame) consume_Windows_Media_Capture_IOptionalReferencePhotoCapturedEventArgs<D>::Frame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IOptionalReferencePhotoCapturedEventArgs)->get_Frame(&value));
        return winrt::Windows::Media::Capture::CapturedFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_Media_Capture_IOptionalReferencePhotoCapturedEventArgs<D>::Context() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IOptionalReferencePhotoCapturedEventArgs)->get_Context(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CapturedFrame) consume_Windows_Media_Capture_IPhotoCapturedEventArgs<D>::Frame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IPhotoCapturedEventArgs)->get_Frame(&value));
        return winrt::Windows::Media::Capture::CapturedFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CapturedFrame) consume_Windows_Media_Capture_IPhotoCapturedEventArgs<D>::Thumbnail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IPhotoCapturedEventArgs)->get_Thumbnail(&value));
        return winrt::Windows::Media::Capture::CapturedFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Capture_IPhotoCapturedEventArgs<D>::CaptureTimeOffset() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IPhotoCapturedEventArgs)->get_CaptureTimeOffset(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CapturedFrame) consume_Windows_Media_Capture_IPhotoConfirmationCapturedEventArgs<D>::Frame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IPhotoConfirmationCapturedEventArgs)->get_Frame(&value));
        return winrt::Windows::Media::Capture::CapturedFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Capture_IPhotoConfirmationCapturedEventArgs<D>::CaptureTimeOffset() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IPhotoConfirmationCapturedEventArgs)->get_CaptureTimeOffset(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::VideoEncodingProperties) consume_Windows_Media_Capture_IVideoStreamConfiguration<D>::InputProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IVideoStreamConfiguration)->get_InputProperties(&value));
        return winrt::Windows::Media::MediaProperties::VideoEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::VideoEncodingProperties) consume_Windows_Media_Capture_IVideoStreamConfiguration<D>::OutputProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::IVideoStreamConfiguration)->get_OutputProperties(&value));
        return winrt::Windows::Media::MediaProperties::VideoEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename H> struct delegate<winrt::Windows::Media::Capture::MediaCaptureFailedEventHandler, H> final : implements_delegate<winrt::Windows::Media::Capture::MediaCaptureFailedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Media::Capture::MediaCaptureFailedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* errorEventArgs) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCapture const*>(&sender), *reinterpret_cast<winrt::Windows::Media::Capture::MediaCaptureFailedEventArgs const*>(&errorEventArgs));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::Media::Capture::RecordLimitationExceededEventHandler, H> final : implements_delegate<winrt::Windows::Media::Capture::RecordLimitationExceededEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Media::Capture::RecordLimitationExceededEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCapture const*>(&sender));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAdvancedCapturedPhoto> : produce_base<D, winrt::Windows::Media::Capture::IAdvancedCapturedPhoto>
    {
        int32_t __stdcall get_Frame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CapturedFrame>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Devices::AdvancedPhotoMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Context(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Context());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAdvancedCapturedPhoto2> : produce_base<D, winrt::Windows::Media::Capture::IAdvancedCapturedPhoto2>
    {
        int32_t __stdcall get_FrameBoundsRelativeToReferencePhoto(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>>(this->shim().FrameBoundsRelativeToReferencePhoto());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAdvancedPhotoCapture> : produce_base<D, winrt::Windows::Media::Capture::IAdvancedPhotoCapture>
    {
        int32_t __stdcall CaptureAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::AdvancedCapturedPhoto>>(this->shim().CaptureAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CaptureWithContextAsync(void* context, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::AdvancedCapturedPhoto>>(this->shim().CaptureAsync(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_OptionalReferencePhotoCaptured(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().OptionalReferencePhotoCaptured(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AdvancedPhotoCapture, winrt::Windows::Media::Capture::OptionalReferencePhotoCapturedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_OptionalReferencePhotoCaptured(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OptionalReferencePhotoCaptured(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AllPhotosCaptured(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AllPhotosCaptured(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AdvancedPhotoCapture, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AllPhotosCaptured(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllPhotosCaptured(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall FinishAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().FinishAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastBackgroundService> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastBackgroundService>
    {
        int32_t __stdcall put_PlugInState(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlugInState(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastPlugInState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlugInState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastPlugInState>(this->shim().PlugInState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SignInInfo(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SignInInfo(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SignInInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo>(this->shim().SignInInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StreamInfo(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StreamInfo(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StreamInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo>(this->shim().StreamInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BroadcastTitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BroadcastTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ViewerCount(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ViewerCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ViewerCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ViewerCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TerminateBroadcast(int32_t reason, uint32_t providerSpecificReason) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TerminateBroadcast(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastTerminationReason const*>(&reason), providerSpecificReason);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_HeartbeatRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().HeartbeatRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundService, winrt::Windows::Media::Capture::AppBroadcastHeartbeatRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_HeartbeatRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HeartbeatRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_TitleId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TitleId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2>
    {
        int32_t __stdcall put_BroadcastTitle(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BroadcastTitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BroadcastLanguage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BroadcastLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BroadcastLanguage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BroadcastLanguage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BroadcastChannel(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BroadcastChannel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BroadcastChannel(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BroadcastChannel(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_BroadcastTitleChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BroadcastTitleChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundService, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BroadcastTitleChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BroadcastTitleChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_BroadcastLanguageChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BroadcastLanguageChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundService, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BroadcastLanguageChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BroadcastLanguageChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_BroadcastChannelChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BroadcastChannelChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundService, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BroadcastChannelChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BroadcastChannelChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo>
    {
        int32_t __stdcall get_SignInState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastSignInState>(this->shim().SignInState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OAuthRequestUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OAuthRequestUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OAuthRequestUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().OAuthRequestUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OAuthCallbackUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OAuthCallbackUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OAuthCallbackUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().OAuthCallbackUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AuthenticationResult(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Authentication::Web::WebAuthenticationResult>(this->shim().AuthenticationResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UserName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UserName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SignInStateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SignInStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, winrt::Windows::Media::Capture::AppBroadcastSignInStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SignInStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SignInStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo2> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo2>
    {
        int32_t __stdcall add_UserNameChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().UserNameChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_UserNameChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UserNameChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo>
    {
        int32_t __stdcall get_StreamState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastStreamState>(this->shim().StreamState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredVideoEncodingBitrate(uint64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredVideoEncodingBitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredVideoEncodingBitrate(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().DesiredVideoEncodingBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BandwidthTestBitrate(uint64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BandwidthTestBitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BandwidthTestBitrate(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().BandwidthTestBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudioCodec(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioCodec(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioCodec(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioCodec());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BroadcastStreamReader(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastStreamReader>(this->shim().BroadcastStreamReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StreamStateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StreamStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, winrt::Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StreamStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StreamStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_VideoEncodingResolutionChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().VideoEncodingResolutionChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_VideoEncodingResolutionChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoEncodingResolutionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_VideoEncodingBitrateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().VideoEncodingBitrateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_VideoEncodingBitrateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoEncodingBitrateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo2> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo2>
    {
        int32_t __stdcall ReportProblemWithStream() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportProblemWithStream();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastCameraCaptureStateChangedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastCameraCaptureStateChangedEventArgs>
    {
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastCameraCaptureState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings>
    {
        int32_t __stdcall get_IsBroadcastEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBroadcastEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDisabledByPolicy(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDisabledByPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsGpuConstrained(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsGpuConstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasHardwareEncoder(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasHardwareEncoder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAudioCaptureEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAudioCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAudioCaptureEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAudioCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsMicrophoneCaptureEnabledByDefault(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsMicrophoneCaptureEnabledByDefault(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMicrophoneCaptureEnabledByDefault(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMicrophoneCaptureEnabledByDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsEchoCancellationEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEchoCancellationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsEchoCancellationEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEchoCancellationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SystemAudioGain(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SystemAudioGain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemAudioGain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().SystemAudioGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MicrophoneGain(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MicrophoneGain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MicrophoneGain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MicrophoneGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsCameraCaptureEnabledByDefault(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsCameraCaptureEnabledByDefault(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCameraCaptureEnabledByDefault(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCameraCaptureEnabledByDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectedCameraId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedCameraId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedCameraId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SelectedCameraId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CameraOverlayLocation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CameraOverlayLocation(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastCameraOverlayLocation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CameraOverlayLocation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastCameraOverlayLocation>(this->shim().CameraOverlayLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CameraOverlaySize(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CameraOverlaySize(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastCameraOverlaySize const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CameraOverlaySize(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastCameraOverlaySize>(this->shim().CameraOverlaySize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsCursorImageCaptureEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsCursorImageCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCursorImageCaptureEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCursorImageCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastHeartbeatRequestedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastHeartbeatRequestedEventArgs>
    {
        int32_t __stdcall put_Handled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Handled(value);
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
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastManagerStatics> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastManagerStatics>
    {
        int32_t __stdcall GetGlobalSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastGlobalSettings>(this->shim().GetGlobalSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ApplyGlobalSettings(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ApplyGlobalSettings(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastGlobalSettings const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetProviderSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastProviderSettings>(this->shim().GetProviderSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ApplyProviderSettings(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ApplyProviderSettings(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastProviderSettings const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastMicrophoneCaptureStateChangedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastMicrophoneCaptureStateChangedEventArgs>
    {
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastMicrophoneCaptureState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastPlugIn> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastPlugIn>
    {
        int32_t __stdcall get_AppId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProviderSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastProviderSettings>(this->shim().ProviderSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Logo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastPlugInManager> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastPlugInManager>
    {
        int32_t __stdcall get_IsBroadcastProviderAvailable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBroadcastProviderAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlugInList(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::AppBroadcastPlugIn>>(this->shim().PlugInList());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DefaultPlugIn(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastPlugIn>(this->shim().DefaultPlugIn());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DefaultPlugIn(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DefaultPlugIn(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastPlugIn const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastPlugInManagerStatics> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastPlugInManagerStatics>
    {
        int32_t __stdcall GetDefault(void** ppInstance) noexcept final try
        {
            clear_abi(ppInstance);
            typename D::abi_guard guard(this->shim());
            *ppInstance = detach_from<winrt::Windows::Media::Capture::AppBroadcastPlugInManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForUser(void* user, void** ppInstance) noexcept final try
        {
            clear_abi(ppInstance);
            typename D::abi_guard guard(this->shim());
            *ppInstance = detach_from<winrt::Windows::Media::Capture::AppBroadcastPlugInManager>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastPlugInStateChangedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastPlugInStateChangedEventArgs>
    {
        int32_t __stdcall get_PlugInState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastPlugInState>(this->shim().PlugInState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastPreview> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastPreview>
    {
        int32_t __stdcall StopPreview() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopPreview();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreviewState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastPreviewState>(this->shim().PreviewState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorCode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_PreviewStateChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PreviewStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastPreview, winrt::Windows::Media::Capture::AppBroadcastPreviewStateChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PreviewStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreviewStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_PreviewStreamReader(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamReader>(this->shim().PreviewStreamReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastPreviewStateChangedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastPreviewStateChangedEventArgs>
    {
        int32_t __stdcall get_PreviewState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastPreviewState>(this->shim().PreviewState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamReader> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamReader>
    {
        int32_t __stdcall get_VideoWidth(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().VideoWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoHeight(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().VideoHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoStride(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().VideoStride());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoBitmapPixelFormat(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Imaging::BitmapPixelFormat>(this->shim().VideoBitmapPixelFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoBitmapAlphaMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Imaging::BitmapAlphaMode>(this->shim().VideoBitmapAlphaMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetNextVideoFrame(void** frame) noexcept final try
        {
            clear_abi(frame);
            typename D::abi_guard guard(this->shim());
            *frame = detach_from<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamVideoFrame>(this->shim().TryGetNextVideoFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_VideoFrameArrived(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().VideoFrameArrived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamReader, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_VideoFrameArrived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoFrameArrived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoFrame> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoFrame>
    {
        int32_t __stdcall get_VideoHeader(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamVideoHeader>(this->shim().VideoHeader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoBuffer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().VideoBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader>
    {
        int32_t __stdcall get_AbsoluteTimestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().AbsoluteTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RelativeTimestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().RelativeTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Duration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameId(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().FrameId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastProviderSettings> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastProviderSettings>
    {
        int32_t __stdcall put_DefaultBroadcastTitle(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DefaultBroadcastTitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DefaultBroadcastTitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DefaultBroadcastTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudioEncodingBitrate(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioEncodingBitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioEncodingBitrate(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().AudioEncodingBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CustomVideoEncodingBitrate(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CustomVideoEncodingBitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomVideoEncodingBitrate(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CustomVideoEncodingBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CustomVideoEncodingHeight(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CustomVideoEncodingHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomVideoEncodingHeight(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CustomVideoEncodingHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CustomVideoEncodingWidth(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CustomVideoEncodingWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomVideoEncodingWidth(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CustomVideoEncodingWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VideoEncodingBitrateMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoEncodingBitrateMode(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoEncodingBitrateMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode>(this->shim().VideoEncodingBitrateMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VideoEncodingResolutionMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoEncodingResolutionMode(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoEncodingResolutionMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode>(this->shim().VideoEncodingResolutionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastServices> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastServices>
    {
        int32_t __stdcall get_CaptureTargetType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastCaptureTargetType>(this->shim().CaptureTargetType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CaptureTargetType(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CaptureTargetType(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastCaptureTargetType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BroadcastTitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BroadcastTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BroadcastTitle(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BroadcastTitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BroadcastLanguage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BroadcastLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BroadcastLanguage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BroadcastLanguage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanCapture(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanCapture());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnterBroadcastModeAsync(void* plugIn, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().EnterBroadcastModeAsync(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastPlugIn const*>(&plugIn)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ExitBroadcastMode(int32_t reason) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExitBroadcastMode(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastExitBroadcastModeReason const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartBroadcast() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartBroadcast();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PauseBroadcast() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PauseBroadcast();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResumeBroadcast() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResumeBroadcast();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartPreview(winrt::Windows::Foundation::Size desiredSize, void** preview) noexcept final try
        {
            clear_abi(preview);
            typename D::abi_guard guard(this->shim());
            *preview = detach_from<winrt::Windows::Media::Capture::AppBroadcastPreview>(this->shim().StartPreview(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&desiredSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_State(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastSignInStateChangedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastSignInStateChangedEventArgs>
    {
        int32_t __stdcall get_SignInState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastSignInState>(this->shim().SignInState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Result(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastSignInResult>(this->shim().Result());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastState> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastState>
    {
        int32_t __stdcall get_IsCaptureTargetRunning(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCaptureTargetRunning());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ViewerCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ViewerCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShouldCaptureMicrophone(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShouldCaptureMicrophone());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShouldCaptureMicrophone(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShouldCaptureMicrophone(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RestartMicrophoneCapture() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RestartMicrophoneCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShouldCaptureCamera(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShouldCaptureCamera());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShouldCaptureCamera(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShouldCaptureCamera(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RestartCameraCapture() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RestartCameraCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EncodedVideoSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().EncodedVideoSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MicrophoneCaptureState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastMicrophoneCaptureState>(this->shim().MicrophoneCaptureState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MicrophoneCaptureError(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MicrophoneCaptureError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CameraCaptureState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastCameraCaptureState>(this->shim().CameraCaptureState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CameraCaptureError(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CameraCaptureError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StreamState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastStreamState>(this->shim().StreamState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlugInState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastPlugInState>(this->shim().PlugInState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OAuthRequestUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().OAuthRequestUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OAuthCallbackUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().OAuthCallbackUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AuthenticationResult(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Authentication::Web::WebAuthenticationResult>(this->shim().AuthenticationResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AuthenticationResult(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AuthenticationResult(*reinterpret_cast<winrt::Windows::Security::Authentication::Web::WebAuthenticationResult const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SignInState(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SignInState(*reinterpret_cast<winrt::Windows::Media::Capture::AppBroadcastSignInState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SignInState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastSignInState>(this->shim().SignInState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TerminationReason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastTerminationReason>(this->shim().TerminationReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TerminationReasonPlugInSpecific(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TerminationReasonPlugInSpecific());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ViewerCountChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ViewerCountChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastViewerCountChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ViewerCountChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ViewerCountChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_MicrophoneCaptureStateChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MicrophoneCaptureStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastMicrophoneCaptureStateChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MicrophoneCaptureStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MicrophoneCaptureStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CameraCaptureStateChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CameraCaptureStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastCameraCaptureStateChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CameraCaptureStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CameraCaptureStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PlugInStateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PlugInStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastPlugInStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PlugInStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlugInStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_StreamStateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StreamStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StreamStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StreamStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CaptureTargetClosed(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CaptureTargetClosed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastState, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CaptureTargetClosed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CaptureTargetClosed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastStreamAudioFrame> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastStreamAudioFrame>
    {
        int32_t __stdcall get_AudioHeader(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastStreamAudioHeader>(this->shim().AudioHeader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioBuffer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().AudioBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastStreamAudioHeader> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastStreamAudioHeader>
    {
        int32_t __stdcall get_AbsoluteTimestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().AbsoluteTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RelativeTimestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().RelativeTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Duration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasDiscontinuity(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasDiscontinuity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameId(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().FrameId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastStreamReader> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastStreamReader>
    {
        int32_t __stdcall get_AudioChannels(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().AudioChannels());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioSampleRate(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().AudioSampleRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioAacSequence(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().AudioAacSequence());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioBitrate(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().AudioBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetNextAudioFrame(void** frame) noexcept final try
        {
            clear_abi(frame);
            typename D::abi_guard guard(this->shim());
            *frame = detach_from<winrt::Windows::Media::Capture::AppBroadcastStreamAudioFrame>(this->shim().TryGetNextAudioFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoWidth(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().VideoWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoHeight(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().VideoHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoBitrate(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().VideoBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetNextVideoFrame(void** frame) noexcept final try
        {
            clear_abi(frame);
            typename D::abi_guard guard(this->shim());
            *frame = detach_from<winrt::Windows::Media::Capture::AppBroadcastStreamVideoFrame>(this->shim().TryGetNextVideoFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_AudioFrameArrived(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AudioFrameArrived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastStreamReader, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AudioFrameArrived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioFrameArrived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_VideoFrameArrived(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().VideoFrameArrived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppBroadcastStreamReader, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_VideoFrameArrived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoFrameArrived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastStreamStateChangedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastStreamStateChangedEventArgs>
    {
        int32_t __stdcall get_StreamState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastStreamState>(this->shim().StreamState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastStreamVideoFrame> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastStreamVideoFrame>
    {
        int32_t __stdcall get_VideoHeader(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastStreamVideoHeader>(this->shim().VideoHeader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoBuffer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().VideoBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastStreamVideoHeader> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastStreamVideoHeader>
    {
        int32_t __stdcall get_AbsoluteTimestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().AbsoluteTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RelativeTimestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().RelativeTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Duration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsKeyFrame(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsKeyFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasDiscontinuity(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasDiscontinuity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameId(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().FrameId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastTriggerDetails> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastTriggerDetails>
    {
        int32_t __stdcall get_BackgroundService(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastBackgroundService>(this->shim().BackgroundService());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppBroadcastViewerCountChangedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IAppBroadcastViewerCountChangedEventArgs>
    {
        int32_t __stdcall get_ViewerCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ViewerCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCapture> : produce_base<D, winrt::Windows::Media::Capture::IAppCapture>
    {
        int32_t __stdcall get_IsCapturingAudio(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCapturingAudio());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCapturingVideo(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCapturingVideo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_CapturingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CapturingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCapture, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CapturingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CapturingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys>
    {
        int32_t __stdcall put_ToggleGameBarKey(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToggleGameBarKey(*reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToggleGameBarKey(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().ToggleGameBarKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ToggleGameBarKeyModifiers(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToggleGameBarKeyModifiers(*reinterpret_cast<winrt::Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToggleGameBarKeyModifiers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKeyModifiers>(this->shim().ToggleGameBarKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SaveHistoricalVideoKey(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SaveHistoricalVideoKey(*reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SaveHistoricalVideoKey(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().SaveHistoricalVideoKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SaveHistoricalVideoKeyModifiers(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SaveHistoricalVideoKeyModifiers(*reinterpret_cast<winrt::Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SaveHistoricalVideoKeyModifiers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKeyModifiers>(this->shim().SaveHistoricalVideoKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ToggleRecordingKey(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToggleRecordingKey(*reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToggleRecordingKey(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().ToggleRecordingKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ToggleRecordingKeyModifiers(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToggleRecordingKeyModifiers(*reinterpret_cast<winrt::Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToggleRecordingKeyModifiers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKeyModifiers>(this->shim().ToggleRecordingKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TakeScreenshotKey(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TakeScreenshotKey(*reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TakeScreenshotKey(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().TakeScreenshotKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TakeScreenshotKeyModifiers(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TakeScreenshotKeyModifiers(*reinterpret_cast<winrt::Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TakeScreenshotKeyModifiers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKeyModifiers>(this->shim().TakeScreenshotKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ToggleRecordingIndicatorKey(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToggleRecordingIndicatorKey(*reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToggleRecordingIndicatorKey(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().ToggleRecordingIndicatorKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ToggleRecordingIndicatorKeyModifiers(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToggleRecordingIndicatorKeyModifiers(*reinterpret_cast<winrt::Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToggleRecordingIndicatorKeyModifiers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKeyModifiers>(this->shim().ToggleRecordingIndicatorKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2>
    {
        int32_t __stdcall put_ToggleMicrophoneCaptureKey(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToggleMicrophoneCaptureKey(*reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToggleMicrophoneCaptureKey(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().ToggleMicrophoneCaptureKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ToggleMicrophoneCaptureKeyModifiers(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToggleMicrophoneCaptureKeyModifiers(*reinterpret_cast<winrt::Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToggleMicrophoneCaptureKeyModifiers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKeyModifiers>(this->shim().ToggleMicrophoneCaptureKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3>
    {
        int32_t __stdcall put_ToggleCameraCaptureKey(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToggleCameraCaptureKey(*reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToggleCameraCaptureKey(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().ToggleCameraCaptureKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ToggleCameraCaptureKeyModifiers(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToggleCameraCaptureKeyModifiers(*reinterpret_cast<winrt::Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToggleCameraCaptureKeyModifiers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKeyModifiers>(this->shim().ToggleCameraCaptureKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ToggleBroadcastKey(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToggleBroadcastKey(*reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToggleBroadcastKey(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().ToggleBroadcastKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ToggleBroadcastKeyModifiers(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToggleBroadcastKeyModifiers(*reinterpret_cast<winrt::Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToggleBroadcastKeyModifiers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKeyModifiers>(this->shim().ToggleBroadcastKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureDurationGeneratedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureDurationGeneratedEventArgs>
    {
        int32_t __stdcall get_Duration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureFileGeneratedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureFileGeneratedEventArgs>
    {
        int32_t __stdcall get_File(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureManagerStatics> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureManagerStatics>
    {
        int32_t __stdcall GetCurrentSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppCaptureSettings>(this->shim().GetCurrentSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ApplySettings(void* appCaptureSettings) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ApplySettings(*reinterpret_cast<winrt::Windows::Media::Capture::AppCaptureSettings const*>(&appCaptureSettings));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureMetadataWriter> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureMetadataWriter>
    {
        int32_t __stdcall AddStringEvent(void* name, void* value, int32_t priority) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddStringEvent(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value), *reinterpret_cast<winrt::Windows::Media::Capture::AppCaptureMetadataPriority const*>(&priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddInt32Event(void* name, int32_t value, int32_t priority) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddInt32Event(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Media::Capture::AppCaptureMetadataPriority const*>(&priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDoubleEvent(void* name, double value, int32_t priority) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDoubleEvent(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Media::Capture::AppCaptureMetadataPriority const*>(&priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartStringState(void* name, void* value, int32_t priority) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartStringState(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value), *reinterpret_cast<winrt::Windows::Media::Capture::AppCaptureMetadataPriority const*>(&priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartInt32State(void* name, int32_t value, int32_t priority) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartInt32State(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Media::Capture::AppCaptureMetadataPriority const*>(&priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartDoubleState(void* name, double value, int32_t priority) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartDoubleState(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<winrt::Windows::Media::Capture::AppCaptureMetadataPriority const*>(&priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopState(void* name) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopState(*reinterpret_cast<hstring const*>(&name));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopAllStates() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopAllStates();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemainingStorageBytesAvailable(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().RemainingStorageBytesAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_MetadataPurged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MetadataPurged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureMetadataWriter, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MetadataPurged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MetadataPurged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureMicrophoneCaptureStateChangedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureMicrophoneCaptureStateChangedEventArgs>
    {
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppCaptureMicrophoneCaptureState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureRecordOperation> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureRecordOperation>
    {
        int32_t __stdcall StopRecording() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopRecording();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppCaptureRecordingState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorCode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Duration(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_File(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsFileTruncated(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<bool>>(this->shim().IsFileTruncated());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StateChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureRecordOperation, winrt::Windows::Media::Capture::AppCaptureRecordingStateChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DurationGenerated(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DurationGenerated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureRecordOperation, winrt::Windows::Media::Capture::AppCaptureDurationGeneratedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DurationGenerated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DurationGenerated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_FileGenerated(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FileGenerated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureRecordOperation, winrt::Windows::Media::Capture::AppCaptureFileGeneratedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FileGenerated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FileGenerated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureRecordingStateChangedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureRecordingStateChangedEventArgs>
    {
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppCaptureRecordingState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureServices> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureServices>
    {
        int32_t __stdcall Record(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Media::Capture::AppCaptureRecordOperation>(this->shim().Record());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RecordTimeSpan(int64_t startTime, int64_t duration, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Media::Capture::AppCaptureRecordOperation>(this->shim().RecordTimeSpan(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanCapture(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanCapture());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_State(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppCaptureState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureSettings> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureSettings>
    {
        int32_t __stdcall put_AppCaptureDestinationFolder(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppCaptureDestinationFolder(*reinterpret_cast<winrt::Windows::Storage::StorageFolder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppCaptureDestinationFolder(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().AppCaptureDestinationFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudioEncodingBitrate(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioEncodingBitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioEncodingBitrate(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().AudioEncodingBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAudioCaptureEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAudioCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAudioCaptureEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAudioCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CustomVideoEncodingBitrate(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CustomVideoEncodingBitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomVideoEncodingBitrate(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CustomVideoEncodingBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CustomVideoEncodingHeight(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CustomVideoEncodingHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomVideoEncodingHeight(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CustomVideoEncodingHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CustomVideoEncodingWidth(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CustomVideoEncodingWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomVideoEncodingWidth(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CustomVideoEncodingWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HistoricalBufferLength(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HistoricalBufferLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HistoricalBufferLength(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().HistoricalBufferLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HistoricalBufferLengthUnit(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HistoricalBufferLengthUnit(*reinterpret_cast<winrt::Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HistoricalBufferLengthUnit(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit>(this->shim().HistoricalBufferLengthUnit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsHistoricalCaptureEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsHistoricalCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHistoricalCaptureEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHistoricalCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsHistoricalCaptureOnBatteryAllowed(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsHistoricalCaptureOnBatteryAllowed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHistoricalCaptureOnBatteryAllowed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHistoricalCaptureOnBatteryAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsHistoricalCaptureOnWirelessDisplayAllowed(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsHistoricalCaptureOnWirelessDisplayAllowed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHistoricalCaptureOnWirelessDisplayAllowed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHistoricalCaptureOnWirelessDisplayAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaximumRecordLength(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaximumRecordLength(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaximumRecordLength(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().MaximumRecordLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScreenshotDestinationFolder(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScreenshotDestinationFolder(*reinterpret_cast<winrt::Windows::Storage::StorageFolder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScreenshotDestinationFolder(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().ScreenshotDestinationFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VideoEncodingBitrateMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoEncodingBitrateMode(*reinterpret_cast<winrt::Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoEncodingBitrateMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode>(this->shim().VideoEncodingBitrateMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VideoEncodingResolutionMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoEncodingResolutionMode(*reinterpret_cast<winrt::Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoEncodingResolutionMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode>(this->shim().VideoEncodingResolutionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAppCaptureEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAppCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAppCaptureEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAppCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCpuConstrained(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCpuConstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDisabledByPolicy(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDisabledByPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMemoryConstrained(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMemoryConstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasHardwareEncoder(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasHardwareEncoder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureSettings2> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureSettings2>
    {
        int32_t __stdcall get_IsGpuConstrained(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsGpuConstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AlternateShortcutKeys(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppCaptureAlternateShortcutKeys>(this->shim().AlternateShortcutKeys());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureSettings3> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureSettings3>
    {
        int32_t __stdcall put_IsMicrophoneCaptureEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsMicrophoneCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMicrophoneCaptureEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMicrophoneCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureSettings4> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureSettings4>
    {
        int32_t __stdcall put_IsMicrophoneCaptureEnabledByDefault(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsMicrophoneCaptureEnabledByDefault(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMicrophoneCaptureEnabledByDefault(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMicrophoneCaptureEnabledByDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SystemAudioGain(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SystemAudioGain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemAudioGain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().SystemAudioGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MicrophoneGain(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MicrophoneGain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MicrophoneGain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MicrophoneGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VideoEncodingFrameRateMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoEncodingFrameRateMode(*reinterpret_cast<winrt::Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoEncodingFrameRateMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode>(this->shim().VideoEncodingFrameRateMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureSettings5> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureSettings5>
    {
        int32_t __stdcall put_IsEchoCancellationEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEchoCancellationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsEchoCancellationEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEchoCancellationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsCursorImageCaptureEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsCursorImageCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCursorImageCaptureEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCursorImageCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureState> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureState>
    {
        int32_t __stdcall get_IsTargetRunning(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTargetRunning());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHistoricalCaptureEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHistoricalCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShouldCaptureMicrophone(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShouldCaptureMicrophone());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShouldCaptureMicrophone(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShouldCaptureMicrophone(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RestartMicrophoneCapture() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RestartMicrophoneCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MicrophoneCaptureState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppCaptureMicrophoneCaptureState>(this->shim().MicrophoneCaptureState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MicrophoneCaptureError(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MicrophoneCaptureError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_MicrophoneCaptureStateChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MicrophoneCaptureStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureState, winrt::Windows::Media::Capture::AppCaptureMicrophoneCaptureStateChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MicrophoneCaptureStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MicrophoneCaptureStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CaptureTargetClosed(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CaptureTargetClosed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::AppCaptureState, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CaptureTargetClosed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CaptureTargetClosed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureStatics> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureStatics>
    {
        int32_t __stdcall GetForCurrentView(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppCapture>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IAppCaptureStatics2> : produce_base<D, winrt::Windows::Media::Capture::IAppCaptureStatics2>
    {
        int32_t __stdcall SetAllowedAsync(bool allowed, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetAllowedAsync(allowed));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ICameraCaptureUI> : produce_base<D, winrt::Windows::Media::Capture::ICameraCaptureUI>
    {
        int32_t __stdcall get_PhotoSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CameraCaptureUIPhotoCaptureSettings>(this->shim().PhotoSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CameraCaptureUIVideoCaptureSettings>(this->shim().VideoSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CaptureFileAsync(int32_t mode, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().CaptureFileAsync(*reinterpret_cast<winrt::Windows::Media::Capture::CameraCaptureUIMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings> : produce_base<D, winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings>
    {
        int32_t __stdcall get_Format(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CameraCaptureUIPhotoFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Format(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Format(*reinterpret_cast<winrt::Windows::Media::Capture::CameraCaptureUIPhotoFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxResolution(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution>(this->shim().MaxResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxResolution(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxResolution(*reinterpret_cast<winrt::Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CroppedSizeInPixels(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().CroppedSizeInPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CroppedSizeInPixels(winrt::Windows::Foundation::Size value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CroppedSizeInPixels(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CroppedAspectRatio(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().CroppedAspectRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CroppedAspectRatio(winrt::Windows::Foundation::Size value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CroppedAspectRatio(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowCropping(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowCropping());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowCropping(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowCropping(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings> : produce_base<D, winrt::Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings>
    {
        int32_t __stdcall get_Format(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CameraCaptureUIVideoFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Format(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Format(*reinterpret_cast<winrt::Windows::Media::Capture::CameraCaptureUIVideoFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxResolution(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CameraCaptureUIMaxVideoResolution>(this->shim().MaxResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxResolution(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxResolution(*reinterpret_cast<winrt::Windows::Media::Capture::CameraCaptureUIMaxVideoResolution const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxDurationInSeconds(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().MaxDurationInSeconds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxDurationInSeconds(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxDurationInSeconds(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowTrimming(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowTrimming());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowTrimming(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowTrimming(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ICameraOptionsUIStatics> : produce_base<D, winrt::Windows::Media::Capture::ICameraOptionsUIStatics>
    {
        int32_t __stdcall Show(void* mediaCapture) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Show(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCapture const*>(&mediaCapture));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ICapturedFrame> : produce_base<D, winrt::Windows::Media::Capture::ICapturedFrame>
    {
        int32_t __stdcall get_Width(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Height(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ICapturedFrame2> : produce_base<D, winrt::Windows::Media::Capture::ICapturedFrame2>
    {
        int32_t __stdcall get_ControlValues(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CapturedFrameControlValues>(this->shim().ControlValues());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BitmapProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Imaging::BitmapPropertySet>(this->shim().BitmapProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ICapturedFrameControlValues> : produce_base<D, winrt::Windows::Media::Capture::ICapturedFrameControlValues>
    {
        int32_t __stdcall get_Exposure(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().Exposure());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExposureCompensation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<float>>(this->shim().ExposureCompensation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsoSpeed(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().IsoSpeed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Focus(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().Focus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SceneMode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Media::Devices::CaptureSceneMode>>(this->shim().SceneMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Flashed(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<bool>>(this->shim().Flashed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FlashPowerPercent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<float>>(this->shim().FlashPowerPercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WhiteBalance(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().WhiteBalance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZoomFactor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<float>>(this->shim().ZoomFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ICapturedFrameControlValues2> : produce_base<D, winrt::Windows::Media::Capture::ICapturedFrameControlValues2>
    {
        int32_t __stdcall get_FocusState(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Media::Devices::MediaCaptureFocusState>>(this->shim().FocusState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsoDigitalGain(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<double>>(this->shim().IsoDigitalGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsoAnalogGain(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<double>>(this->shim().IsoAnalogGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SensorFrameRate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaRatio>(this->shim().SensorFrameRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WhiteBalanceGain(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Media::Capture::WhiteBalanceGain>>(this->shim().WhiteBalanceGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ICapturedFrameWithSoftwareBitmap> : produce_base<D, winrt::Windows::Media::Capture::ICapturedFrameWithSoftwareBitmap>
    {
        int32_t __stdcall get_SoftwareBitmap(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().SoftwareBitmap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ICapturedPhoto> : produce_base<D, winrt::Windows::Media::Capture::ICapturedPhoto>
    {
        int32_t __stdcall get_Frame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CapturedFrame>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Thumbnail(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CapturedFrame>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IGameBarServices> : produce_base<D, winrt::Windows::Media::Capture::IGameBarServices>
    {
        int32_t __stdcall get_TargetCapturePolicy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::GameBarTargetCapturePolicy>(this->shim().TargetCapturePolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableCapture() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DisableCapture() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisableCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TargetInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::GameBarServicesTargetInfo>(this->shim().TargetInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SessionId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SessionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppBroadcastServices(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppBroadcastServices>(this->shim().AppBroadcastServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppCaptureServices(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::AppCaptureServices>(this->shim().AppCaptureServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_CommandReceived(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CommandReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::GameBarServices, winrt::Windows::Media::Capture::GameBarServicesCommandEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CommandReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CommandReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IGameBarServicesCommandEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IGameBarServicesCommandEventArgs>
    {
        int32_t __stdcall get_Command(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::GameBarCommand>(this->shim().Command());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Origin(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::GameBarCommandOrigin>(this->shim().Origin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IGameBarServicesManager> : produce_base<D, winrt::Windows::Media::Capture::IGameBarServicesManager>
    {
        int32_t __stdcall add_GameBarServicesCreated(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GameBarServicesCreated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::GameBarServicesManager, winrt::Windows::Media::Capture::GameBarServicesManagerGameBarServicesCreatedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_GameBarServicesCreated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GameBarServicesCreated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IGameBarServicesManagerGameBarServicesCreatedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IGameBarServicesManagerGameBarServicesCreatedEventArgs>
    {
        int32_t __stdcall get_GameBarServices(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::GameBarServices>(this->shim().GameBarServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IGameBarServicesManagerStatics> : produce_base<D, winrt::Windows::Media::Capture::IGameBarServicesManagerStatics>
    {
        int32_t __stdcall GetDefault(void** ppInstance) noexcept final try
        {
            clear_abi(ppInstance);
            typename D::abi_guard guard(this->shim());
            *ppInstance = detach_from<winrt::Windows::Media::Capture::GameBarServicesManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IGameBarServicesTargetInfo> : produce_base<D, winrt::Windows::Media::Capture::IGameBarServicesTargetInfo>
    {
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TitleId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TitleId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::GameBarServicesDisplayMode>(this->shim().DisplayMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ILowLagMediaRecording> : produce_base<D, winrt::Windows::Media::Capture::ILowLagMediaRecording>
    {
        int32_t __stdcall StartAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FinishAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().FinishAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ILowLagMediaRecording2> : produce_base<D, winrt::Windows::Media::Capture::ILowLagMediaRecording2>
    {
        int32_t __stdcall PauseAsync(int32_t behavior, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().PauseAsync(*reinterpret_cast<winrt::Windows::Media::Devices::MediaCapturePauseBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResumeAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ResumeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ILowLagMediaRecording3> : produce_base<D, winrt::Windows::Media::Capture::ILowLagMediaRecording3>
    {
        int32_t __stdcall PauseWithResultAsync(int32_t behavior, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::MediaCapturePauseResult>>(this->shim().PauseWithResultAsync(*reinterpret_cast<winrt::Windows::Media::Devices::MediaCapturePauseBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopWithResultAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::MediaCaptureStopResult>>(this->shim().StopWithResultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ILowLagPhotoCapture> : produce_base<D, winrt::Windows::Media::Capture::ILowLagPhotoCapture>
    {
        int32_t __stdcall CaptureAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::CapturedPhoto>>(this->shim().CaptureAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FinishAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().FinishAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::ILowLagPhotoSequenceCapture> : produce_base<D, winrt::Windows::Media::Capture::ILowLagPhotoSequenceCapture>
    {
        int32_t __stdcall StartAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FinishAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().FinishAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_PhotoCaptured(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PhotoCaptured(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::LowLagPhotoSequenceCapture, winrt::Windows::Media::Capture::PhotoCapturedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PhotoCaptured(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PhotoCaptured(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCapture> : produce_base<D, winrt::Windows::Media::Capture::IMediaCapture>
    {
        int32_t __stdcall InitializeAsync(void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().InitializeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InitializeWithSettingsAsync(void* mediaCaptureInitializationSettings, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().InitializeAsync(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCaptureInitializationSettings const*>(&mediaCaptureInitializationSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartRecordToStorageFileAsync(void* encodingProfile, void* file, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartRecordToStorageFileAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartRecordToStreamAsync(void* encodingProfile, void* stream, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartRecordToStreamAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartRecordToCustomSinkAsync(void* encodingProfile, void* customMediaSink, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartRecordToCustomSinkAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<winrt::Windows::Media::IMediaExtension const*>(&customMediaSink)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartRecordToCustomSinkIdAsync(void* encodingProfile, void* customSinkActivationId, void* customSinkSettings, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartRecordToCustomSinkAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<hstring const*>(&customSinkActivationId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&customSinkSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopRecordAsync(void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StopRecordAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CapturePhotoToStorageFileAsync(void* type, void* file, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().CapturePhotoToStorageFileAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::ImageEncodingProperties const*>(&type), *reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CapturePhotoToStreamAsync(void* type, void* stream, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().CapturePhotoToStreamAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::ImageEncodingProperties const*>(&type), *reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddEffectAsync(int32_t mediaStreamType, void* effectActivationID, void* effectSettings, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AddEffectAsync(*reinterpret_cast<winrt::Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType), *reinterpret_cast<hstring const*>(&effectActivationID), *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&effectSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearEffectsAsync(int32_t mediaStreamType, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ClearEffectsAsync(*reinterpret_cast<winrt::Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetEncoderProperty(int32_t mediaStreamType, winrt::guid propertyId, void* propertyValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetEncoderProperty(*reinterpret_cast<winrt::Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType), *reinterpret_cast<winrt::guid const*>(&propertyId), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&propertyValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetEncoderProperty(int32_t mediaStreamType, winrt::guid propertyId, void** propertyValue) noexcept final try
        {
            clear_abi(propertyValue);
            typename D::abi_guard guard(this->shim());
            *propertyValue = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetEncoderProperty(*reinterpret_cast<winrt::Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType), *reinterpret_cast<winrt::guid const*>(&propertyId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Failed(void* errorEventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().Failed(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCaptureFailedEventHandler const*>(&errorEventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Failed(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Failed(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
        int32_t __stdcall add_RecordLimitationExceeded(void* recordLimitationExceededEventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().RecordLimitationExceeded(*reinterpret_cast<winrt::Windows::Media::Capture::RecordLimitationExceededEventHandler const*>(&recordLimitationExceededEventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RecordLimitationExceeded(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RecordLimitationExceeded(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
        int32_t __stdcall get_MediaCaptureSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::MediaCaptureSettings>(this->shim().MediaCaptureSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioDeviceController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Devices::AudioDeviceController>(this->shim().AudioDeviceController());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoDeviceController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Devices::VideoDeviceController>(this->shim().VideoDeviceController());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPreviewMirroring(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPreviewMirroring(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPreviewMirroring(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().GetPreviewMirroring());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPreviewRotation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPreviewRotation(*reinterpret_cast<winrt::Windows::Media::Capture::VideoRotation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPreviewRotation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::VideoRotation>(this->shim().GetPreviewRotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetRecordRotation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetRecordRotation(*reinterpret_cast<winrt::Windows::Media::Capture::VideoRotation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRecordRotation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::VideoRotation>(this->shim().GetRecordRotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCapture2> : produce_base<D, winrt::Windows::Media::Capture::IMediaCapture2>
    {
        int32_t __stdcall PrepareLowLagRecordToStorageFileAsync(void* encodingProfile, void* file, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagMediaRecording>>(this->shim().PrepareLowLagRecordToStorageFileAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrepareLowLagRecordToStreamAsync(void* encodingProfile, void* stream, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagMediaRecording>>(this->shim().PrepareLowLagRecordToStreamAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrepareLowLagRecordToCustomSinkAsync(void* encodingProfile, void* customMediaSink, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagMediaRecording>>(this->shim().PrepareLowLagRecordToCustomSinkAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<winrt::Windows::Media::IMediaExtension const*>(&customMediaSink)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrepareLowLagRecordToCustomSinkIdAsync(void* encodingProfile, void* customSinkActivationId, void* customSinkSettings, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagMediaRecording>>(this->shim().PrepareLowLagRecordToCustomSinkAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<hstring const*>(&customSinkActivationId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&customSinkSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrepareLowLagPhotoCaptureAsync(void* type, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagPhotoCapture>>(this->shim().PrepareLowLagPhotoCaptureAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::ImageEncodingProperties const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrepareLowLagPhotoSequenceCaptureAsync(void* type, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::LowLagPhotoSequenceCapture>>(this->shim().PrepareLowLagPhotoSequenceCaptureAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::ImageEncodingProperties const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetEncodingPropertiesAsync(int32_t mediaStreamType, void* mediaEncodingProperties, void* encoderProperties, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetEncodingPropertiesAsync(*reinterpret_cast<winrt::Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType), *reinterpret_cast<winrt::Windows::Media::MediaProperties::IMediaEncodingProperties const*>(&mediaEncodingProperties), *reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaPropertySet const*>(&encoderProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCapture3> : produce_base<D, winrt::Windows::Media::Capture::IMediaCapture3>
    {
        int32_t __stdcall PrepareVariablePhotoSequenceCaptureAsync(void* type, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Core::VariablePhotoSequenceCapture>>(this->shim().PrepareVariablePhotoSequenceCaptureAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::ImageEncodingProperties const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_FocusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FocusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Media::Capture::MediaCaptureFocusChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FocusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FocusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PhotoConfirmationCaptured(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PhotoConfirmationCaptured(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Media::Capture::PhotoConfirmationCapturedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PhotoConfirmationCaptured(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PhotoConfirmationCaptured(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCapture4> : produce_base<D, winrt::Windows::Media::Capture::IMediaCapture4>
    {
        int32_t __stdcall AddAudioEffectAsync(void* definition, void** op) noexcept final try
        {
            clear_abi(op);
            typename D::abi_guard guard(this->shim());
            *op = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::IMediaExtension>>(this->shim().AddAudioEffectAsync(*reinterpret_cast<winrt::Windows::Media::Effects::IAudioEffectDefinition const*>(&definition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddVideoEffectAsync(void* definition, int32_t mediaStreamType, void** op) noexcept final try
        {
            clear_abi(op);
            typename D::abi_guard guard(this->shim());
            *op = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::IMediaExtension>>(this->shim().AddVideoEffectAsync(*reinterpret_cast<winrt::Windows::Media::Effects::IVideoEffectDefinition const*>(&definition), *reinterpret_cast<winrt::Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PauseRecordAsync(int32_t behavior, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().PauseRecordAsync(*reinterpret_cast<winrt::Windows::Media::Devices::MediaCapturePauseBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResumeRecordAsync(void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ResumeRecordAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_CameraStreamStateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CameraStreamStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CameraStreamStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CameraStreamStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_CameraStreamState(int32_t* streamState) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *streamState = detach_from<winrt::Windows::Media::Devices::CameraStreamState>(this->shim().CameraStreamState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPreviewFrameAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::VideoFrame>>(this->shim().GetPreviewFrameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPreviewFrameCopyAsync(void* destination, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::VideoFrame>>(this->shim().GetPreviewFrameAsync(*reinterpret_cast<winrt::Windows::Media::VideoFrame const*>(&destination)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ThermalStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ThermalStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ThermalStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ThermalStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_ThermalStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::MediaCaptureThermalStatus>(this->shim().ThermalStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrepareAdvancedPhotoCaptureAsync(void* encodingProperties, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::AdvancedPhotoCapture>>(this->shim().PrepareAdvancedPhotoCaptureAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::ImageEncodingProperties const*>(&encodingProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCapture5> : produce_base<D, winrt::Windows::Media::Capture::IMediaCapture5>
    {
        int32_t __stdcall RemoveEffectAsync(void* effect, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RemoveEffectAsync(*reinterpret_cast<winrt::Windows::Media::IMediaExtension const*>(&effect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PauseRecordWithResultAsync(int32_t behavior, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::MediaCapturePauseResult>>(this->shim().PauseRecordWithResultAsync(*reinterpret_cast<winrt::Windows::Media::Devices::MediaCapturePauseBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopRecordWithResultAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::MediaCaptureStopResult>>(this->shim().StopRecordWithResultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameSources(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Media::Capture::Frames::MediaFrameSource>>(this->shim().FrameSources());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFrameReaderAsync(void* inputSource, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameReader>>(this->shim().CreateFrameReaderAsync(*reinterpret_cast<winrt::Windows::Media::Capture::Frames::MediaFrameSource const*>(&inputSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFrameReaderWithSubtypeAsync(void* inputSource, void* outputSubtype, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameReader>>(this->shim().CreateFrameReaderAsync(*reinterpret_cast<winrt::Windows::Media::Capture::Frames::MediaFrameSource const*>(&inputSource), *reinterpret_cast<hstring const*>(&outputSubtype)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFrameReaderWithSubtypeAndSizeAsync(void* inputSource, void* outputSubtype, struct struct_Windows_Graphics_Imaging_BitmapSize outputSize, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameReader>>(this->shim().CreateFrameReaderAsync(*reinterpret_cast<winrt::Windows::Media::Capture::Frames::MediaFrameSource const*>(&inputSource), *reinterpret_cast<hstring const*>(&outputSubtype), *reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapSize const*>(&outputSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCapture6> : produce_base<D, winrt::Windows::Media::Capture::IMediaCapture6>
    {
        int32_t __stdcall add_CaptureDeviceExclusiveControlStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CaptureDeviceExclusiveControlStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCapture, winrt::Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatusChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CaptureDeviceExclusiveControlStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CaptureDeviceExclusiveControlStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall CreateMultiSourceFrameReaderAsync(void* inputSources, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReader>>(this->shim().CreateMultiSourceFrameReaderAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Media::Capture::Frames::MediaFrameSource> const*>(&inputSources)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCapture7> : produce_base<D, winrt::Windows::Media::Capture::IMediaCapture7>
    {
        int32_t __stdcall CreateRelativePanelWatcher(int32_t captureMode, void* displayRegion, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Capture::MediaCaptureRelativePanelWatcher>(this->shim().CreateRelativePanelWatcher(*reinterpret_cast<winrt::Windows::Media::Capture::StreamingCaptureMode const*>(&captureMode), *reinterpret_cast<winrt::Windows::UI::WindowManagement::DisplayRegion const*>(&displayRegion)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureFailedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureFailedEventArgs>
    {
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Code(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Code());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureFocusChangedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureFocusChangedEventArgs>
    {
        int32_t __stdcall get_FocusState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Devices::MediaCaptureFocusState>(this->shim().FocusState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings>
    {
        int32_t __stdcall put_AudioDeviceId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioDeviceId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VideoDeviceId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoDeviceId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StreamingCaptureMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StreamingCaptureMode(*reinterpret_cast<winrt::Windows::Media::Capture::StreamingCaptureMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StreamingCaptureMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::StreamingCaptureMode>(this->shim().StreamingCaptureMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PhotoCaptureSource(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PhotoCaptureSource(*reinterpret_cast<winrt::Windows::Media::Capture::PhotoCaptureSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PhotoCaptureSource(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::PhotoCaptureSource>(this->shim().PhotoCaptureSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings2> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings2>
    {
        int32_t __stdcall put_MediaCategory(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MediaCategory(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCategory const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaCategory(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::MediaCategory>(this->shim().MediaCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudioProcessing(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioProcessing(*reinterpret_cast<winrt::Windows::Media::AudioProcessing const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioProcessing(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::AudioProcessing>(this->shim().AudioProcessing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings3> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings3>
    {
        int32_t __stdcall put_AudioSource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioSource(*reinterpret_cast<winrt::Windows::Media::Core::IMediaSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::IMediaSource>(this->shim().AudioSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VideoSource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoSource(*reinterpret_cast<winrt::Windows::Media::Core::IMediaSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::IMediaSource>(this->shim().VideoSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings4> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings4>
    {
        int32_t __stdcall get_VideoProfile(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::MediaCaptureVideoProfile>(this->shim().VideoProfile());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VideoProfile(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoProfile(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCaptureVideoProfile const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreviewMediaDescription(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>(this->shim().PreviewMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PreviewMediaDescription(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreviewMediaDescription(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecordMediaDescription(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>(this->shim().RecordMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RecordMediaDescription(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RecordMediaDescription(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PhotoMediaDescription(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>(this->shim().PhotoMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PhotoMediaDescription(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PhotoMediaDescription(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings5> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings5>
    {
        int32_t __stdcall get_SourceGroup(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup>(this->shim().SourceGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SourceGroup(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceGroup(*reinterpret_cast<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SharingMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::MediaCaptureSharingMode>(this->shim().SharingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SharingMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SharingMode(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCaptureSharingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MemoryPreference(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::MediaCaptureMemoryPreference>(this->shim().MemoryPreference());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MemoryPreference(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MemoryPreference(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCaptureMemoryPreference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings6> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings6>
    {
        int32_t __stdcall get_AlwaysPlaySystemShutterSound(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AlwaysPlaySystemShutterSound());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AlwaysPlaySystemShutterSound(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AlwaysPlaySystemShutterSound(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings7> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings7>
    {
        int32_t __stdcall get_DeviceUriPasswordCredential(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::PasswordCredential>(this->shim().DeviceUriPasswordCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DeviceUriPasswordCredential(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeviceUriPasswordCredential(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().DeviceUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DeviceUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeviceUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCapturePauseResult> : produce_base<D, winrt::Windows::Media::Capture::IMediaCapturePauseResult>
    {
        int32_t __stdcall get_LastFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::VideoFrame>(this->shim().LastFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecordDuration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().RecordDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureRelativePanelWatcher> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureRelativePanelWatcher>
    {
        int32_t __stdcall get_RelativePanel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::Panel>(this->shim().RelativePanel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Changed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::MediaCaptureRelativePanelWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Changed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureSettings> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureSettings>
    {
        int32_t __stdcall get_AudioDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StreamingCaptureMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::StreamingCaptureMode>(this->shim().StreamingCaptureMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PhotoCaptureSource(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::PhotoCaptureSource>(this->shim().PhotoCaptureSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoDeviceCharacteristic(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::VideoDeviceCharacteristic>(this->shim().VideoDeviceCharacteristic());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureSettings2> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureSettings2>
    {
        int32_t __stdcall get_ConcurrentRecordAndPhotoSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ConcurrentRecordAndPhotoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConcurrentRecordAndPhotoSequenceSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ConcurrentRecordAndPhotoSequenceSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CameraSoundRequiredForRegion(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CameraSoundRequiredForRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Horizontal35mmEquivalentFocalLength(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().Horizontal35mmEquivalentFocalLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PitchOffsetDegrees(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().PitchOffsetDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Vertical35mmEquivalentFocalLength(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().Vertical35mmEquivalentFocalLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaCategory(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::MediaCategory>(this->shim().MediaCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioProcessing(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::AudioProcessing>(this->shim().AudioProcessing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureSettings3> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureSettings3>
    {
        int32_t __stdcall get_Direct3D11Device(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice>(this->shim().Direct3D11Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureStatics> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureStatics>
    {
        int32_t __stdcall IsVideoProfileSupported(void* videoDeviceId, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsVideoProfileSupported(*reinterpret_cast<hstring const*>(&videoDeviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllVideoProfiles(void* videoDeviceId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfile>>(this->shim().FindAllVideoProfiles(*reinterpret_cast<hstring const*>(&videoDeviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindConcurrentProfiles(void* videoDeviceId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfile>>(this->shim().FindConcurrentProfiles(*reinterpret_cast<hstring const*>(&videoDeviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindKnownVideoProfiles(void* videoDeviceId, int32_t name, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfile>>(this->shim().FindKnownVideoProfiles(*reinterpret_cast<hstring const*>(&videoDeviceId), *reinterpret_cast<winrt::Windows::Media::Capture::KnownVideoProfile const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureStopResult> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureStopResult>
    {
        int32_t __stdcall get_LastFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::VideoFrame>(this->shim().LastFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecordDuration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().RecordDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureVideoPreview> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureVideoPreview>
    {
        int32_t __stdcall StartPreviewAsync(void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartPreviewAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartPreviewToCustomSinkAsync(void* encodingProfile, void* customMediaSink, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartPreviewToCustomSinkAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<winrt::Windows::Media::IMediaExtension const*>(&customMediaSink)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartPreviewToCustomSinkIdAsync(void* encodingProfile, void* customSinkActivationId, void* customSinkSettings, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartPreviewToCustomSinkAsync(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<hstring const*>(&customSinkActivationId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&customSinkSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopPreviewAsync(void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StopPreviewAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureVideoProfile> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureVideoProfile>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedPreviewMediaDescription(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>>(this->shim().SupportedPreviewMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedRecordMediaDescription(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>>(this->shim().SupportedRecordMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedPhotoMediaDescription(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>>(this->shim().SupportedPhotoMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConcurrency(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfile>>(this->shim().GetConcurrency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureVideoProfile2> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureVideoProfile2>
    {
        int32_t __stdcall get_FrameSourceInfos(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::Frames::MediaFrameSourceInfo>>(this->shim().FrameSourceInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription>
    {
        int32_t __stdcall get_Width(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Height(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameRate(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FrameRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsVariablePhotoSequenceSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsVariablePhotoSequenceSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHdrVideoSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHdrVideoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription2> : produce_base<D, winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription2>
    {
        int32_t __stdcall get_Subtype(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Subtype());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IOptionalReferencePhotoCapturedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IOptionalReferencePhotoCapturedEventArgs>
    {
        int32_t __stdcall get_Frame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CapturedFrame>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Context(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Context());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IPhotoCapturedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IPhotoCapturedEventArgs>
    {
        int32_t __stdcall get_Frame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CapturedFrame>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Thumbnail(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CapturedFrame>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CaptureTimeOffset(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().CaptureTimeOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IPhotoConfirmationCapturedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::IPhotoConfirmationCapturedEventArgs>
    {
        int32_t __stdcall get_Frame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CapturedFrame>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CaptureTimeOffset(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().CaptureTimeOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::IVideoStreamConfiguration> : produce_base<D, winrt::Windows::Media::Capture::IVideoStreamConfiguration>
    {
        int32_t __stdcall get_InputProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().InputProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutputProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().OutputProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::Capture
{
    inline auto AppBroadcastManager::GetGlobalSettings()
    {
        return impl::call_factory_cast<winrt::Windows::Media::Capture::AppBroadcastGlobalSettings(*)(IAppBroadcastManagerStatics const&), AppBroadcastManager, IAppBroadcastManagerStatics>([](IAppBroadcastManagerStatics const& f) { return f.GetGlobalSettings(); });
    }
    inline auto AppBroadcastManager::ApplyGlobalSettings(winrt::Windows::Media::Capture::AppBroadcastGlobalSettings const& value)
    {
        impl::call_factory<AppBroadcastManager, IAppBroadcastManagerStatics>([&](IAppBroadcastManagerStatics const& f) { return f.ApplyGlobalSettings(value); });
    }
    inline auto AppBroadcastManager::GetProviderSettings()
    {
        return impl::call_factory_cast<winrt::Windows::Media::Capture::AppBroadcastProviderSettings(*)(IAppBroadcastManagerStatics const&), AppBroadcastManager, IAppBroadcastManagerStatics>([](IAppBroadcastManagerStatics const& f) { return f.GetProviderSettings(); });
    }
    inline auto AppBroadcastManager::ApplyProviderSettings(winrt::Windows::Media::Capture::AppBroadcastProviderSettings const& value)
    {
        impl::call_factory<AppBroadcastManager, IAppBroadcastManagerStatics>([&](IAppBroadcastManagerStatics const& f) { return f.ApplyProviderSettings(value); });
    }
    inline auto AppBroadcastPlugInManager::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Media::Capture::AppBroadcastPlugInManager(*)(IAppBroadcastPlugInManagerStatics const&), AppBroadcastPlugInManager, IAppBroadcastPlugInManagerStatics>([](IAppBroadcastPlugInManagerStatics const& f) { return f.GetDefault(); });
    }
    inline auto AppBroadcastPlugInManager::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<AppBroadcastPlugInManager, IAppBroadcastPlugInManagerStatics>([&](IAppBroadcastPlugInManagerStatics const& f) { return f.GetForUser(user); });
    }
    inline auto AppCapture::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::Media::Capture::AppCapture(*)(IAppCaptureStatics const&), AppCapture, IAppCaptureStatics>([](IAppCaptureStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto AppCapture::SetAllowedAsync(bool allowed)
    {
        return impl::call_factory<AppCapture, IAppCaptureStatics2>([&](IAppCaptureStatics2 const& f) { return f.SetAllowedAsync(allowed); });
    }
    inline auto AppCaptureManager::GetCurrentSettings()
    {
        return impl::call_factory_cast<winrt::Windows::Media::Capture::AppCaptureSettings(*)(IAppCaptureManagerStatics const&), AppCaptureManager, IAppCaptureManagerStatics>([](IAppCaptureManagerStatics const& f) { return f.GetCurrentSettings(); });
    }
    inline auto AppCaptureManager::ApplySettings(winrt::Windows::Media::Capture::AppCaptureSettings const& appCaptureSettings)
    {
        impl::call_factory<AppCaptureManager, IAppCaptureManagerStatics>([&](IAppCaptureManagerStatics const& f) { return f.ApplySettings(appCaptureSettings); });
    }
    inline AppCaptureMetadataWriter::AppCaptureMetadataWriter() :
        AppCaptureMetadataWriter(impl::call_factory_cast<AppCaptureMetadataWriter(*)(winrt::Windows::Foundation::IActivationFactory const&), AppCaptureMetadataWriter>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AppCaptureMetadataWriter>(); }))
    {
    }
    inline CameraCaptureUI::CameraCaptureUI() :
        CameraCaptureUI(impl::call_factory_cast<CameraCaptureUI(*)(winrt::Windows::Foundation::IActivationFactory const&), CameraCaptureUI>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CameraCaptureUI>(); }))
    {
    }
    inline auto CameraOptionsUI::Show(winrt::Windows::Media::Capture::MediaCapture const& mediaCapture)
    {
        impl::call_factory<CameraOptionsUI, ICameraOptionsUIStatics>([&](ICameraOptionsUIStatics const& f) { return f.Show(mediaCapture); });
    }
    inline auto GameBarServicesManager::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Media::Capture::GameBarServicesManager(*)(IGameBarServicesManagerStatics const&), GameBarServicesManager, IGameBarServicesManagerStatics>([](IGameBarServicesManagerStatics const& f) { return f.GetDefault(); });
    }
    inline MediaCapture::MediaCapture() :
        MediaCapture(impl::call_factory_cast<MediaCapture(*)(winrt::Windows::Foundation::IActivationFactory const&), MediaCapture>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MediaCapture>(); }))
    {
    }
    inline auto MediaCapture::IsVideoProfileSupported(param::hstring const& videoDeviceId)
    {
        return impl::call_factory<MediaCapture, IMediaCaptureStatics>([&](IMediaCaptureStatics const& f) { return f.IsVideoProfileSupported(videoDeviceId); });
    }
    inline auto MediaCapture::FindAllVideoProfiles(param::hstring const& videoDeviceId)
    {
        return impl::call_factory<MediaCapture, IMediaCaptureStatics>([&](IMediaCaptureStatics const& f) { return f.FindAllVideoProfiles(videoDeviceId); });
    }
    inline auto MediaCapture::FindConcurrentProfiles(param::hstring const& videoDeviceId)
    {
        return impl::call_factory<MediaCapture, IMediaCaptureStatics>([&](IMediaCaptureStatics const& f) { return f.FindConcurrentProfiles(videoDeviceId); });
    }
    inline auto MediaCapture::FindKnownVideoProfiles(param::hstring const& videoDeviceId, winrt::Windows::Media::Capture::KnownVideoProfile const& name)
    {
        return impl::call_factory<MediaCapture, IMediaCaptureStatics>([&](IMediaCaptureStatics const& f) { return f.FindKnownVideoProfiles(videoDeviceId, name); });
    }
    inline MediaCaptureInitializationSettings::MediaCaptureInitializationSettings() :
        MediaCaptureInitializationSettings(impl::call_factory_cast<MediaCaptureInitializationSettings(*)(winrt::Windows::Foundation::IActivationFactory const&), MediaCaptureInitializationSettings>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MediaCaptureInitializationSettings>(); }))
    {
    }
    template <typename L> MediaCaptureFailedEventHandler::MediaCaptureFailedEventHandler(L handler) :
        MediaCaptureFailedEventHandler(impl::make_delegate<MediaCaptureFailedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> MediaCaptureFailedEventHandler::MediaCaptureFailedEventHandler(F* handler) :
        MediaCaptureFailedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> MediaCaptureFailedEventHandler::MediaCaptureFailedEventHandler(O* object, M method) :
        MediaCaptureFailedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> MediaCaptureFailedEventHandler::MediaCaptureFailedEventHandler(com_ptr<O>&& object, M method) :
        MediaCaptureFailedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> MediaCaptureFailedEventHandler::MediaCaptureFailedEventHandler(weak_ref<O>&& object, M method) :
        MediaCaptureFailedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto MediaCaptureFailedEventHandler::operator()(winrt::Windows::Media::Capture::MediaCapture const& sender, winrt::Windows::Media::Capture::MediaCaptureFailedEventArgs const& errorEventArgs) const
    {
        check_hresult((*(impl::abi_t<MediaCaptureFailedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&errorEventArgs)));
    }
    template <typename L> RecordLimitationExceededEventHandler::RecordLimitationExceededEventHandler(L handler) :
        RecordLimitationExceededEventHandler(impl::make_delegate<RecordLimitationExceededEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> RecordLimitationExceededEventHandler::RecordLimitationExceededEventHandler(F* handler) :
        RecordLimitationExceededEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> RecordLimitationExceededEventHandler::RecordLimitationExceededEventHandler(O* object, M method) :
        RecordLimitationExceededEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> RecordLimitationExceededEventHandler::RecordLimitationExceededEventHandler(com_ptr<O>&& object, M method) :
        RecordLimitationExceededEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> RecordLimitationExceededEventHandler::RecordLimitationExceededEventHandler(weak_ref<O>&& object, M method) :
        RecordLimitationExceededEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto RecordLimitationExceededEventHandler::operator()(winrt::Windows::Media::Capture::MediaCapture const& sender) const
    {
        check_hresult((*(impl::abi_t<RecordLimitationExceededEventHandler>**)this)->Invoke(*(void**)(&sender)));
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::Capture::IAdvancedCapturedPhoto> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAdvancedCapturedPhoto2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAdvancedPhotoCapture> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastBackgroundService> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastCameraCaptureStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastHeartbeatRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastMicrophoneCaptureStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPlugIn> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPlugInManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPlugInManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPlugInStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPreviewStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastProviderSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastServices> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastSignInStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastStreamAudioFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastStreamAudioHeader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastStreamReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastStreamStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastStreamVideoFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastStreamVideoHeader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastViewerCountChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCapture> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureDurationGeneratedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureFileGeneratedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureMetadataWriter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureMicrophoneCaptureStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureRecordOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureRecordingStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureServices> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureSettings2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureSettings3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureSettings4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureSettings5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ICameraCaptureUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ICameraOptionsUIStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ICapturedFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ICapturedFrame2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ICapturedFrameControlValues> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ICapturedFrameControlValues2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ICapturedFrameWithSoftwareBitmap> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ICapturedPhoto> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IGameBarServices> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IGameBarServicesCommandEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IGameBarServicesManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IGameBarServicesManagerGameBarServicesCreatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IGameBarServicesManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IGameBarServicesTargetInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ILowLagMediaRecording> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ILowLagMediaRecording2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ILowLagMediaRecording3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ILowLagPhotoCapture> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::ILowLagPhotoSequenceCapture> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCapture> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCapture2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCapture3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCapture4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCapture5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCapture6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCapture7> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureFocusChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings7> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCapturePauseResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureRelativePanelWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureSettings2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureSettings3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureStopResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureVideoPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureVideoProfile> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureVideoProfile2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IOptionalReferencePhotoCapturedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IPhotoCapturedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IPhotoConfirmationCapturedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::IVideoStreamConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AdvancedCapturedPhoto> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AdvancedPhotoCapture> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastBackgroundService> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastCameraCaptureStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastGlobalSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastHeartbeatRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastMicrophoneCaptureStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPlugIn> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPlugInManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPlugInStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPreviewStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamVideoFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamVideoHeader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastProviderSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastServices> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastSignInStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastStreamAudioFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastStreamAudioHeader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastStreamReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastStreamVideoFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastStreamVideoHeader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastViewerCountChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppCapture> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppCaptureAlternateShortcutKeys> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppCaptureDurationGeneratedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppCaptureFileGeneratedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppCaptureManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppCaptureMetadataWriter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppCaptureMicrophoneCaptureStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppCaptureRecordOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppCaptureRecordingStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppCaptureServices> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppCaptureSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::AppCaptureState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::CameraCaptureUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::CameraCaptureUIPhotoCaptureSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::CameraCaptureUIVideoCaptureSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::CameraOptionsUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::CapturedFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::CapturedFrameControlValues> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::CapturedPhoto> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::GameBarServices> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::GameBarServicesCommandEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::GameBarServicesManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::GameBarServicesManagerGameBarServicesCreatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::GameBarServicesTargetInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::LowLagMediaRecording> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::LowLagPhotoCapture> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::LowLagPhotoSequenceCapture> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::MediaCapture> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatusChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureFocusChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureInitializationSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::MediaCapturePauseResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureRelativePanelWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureStopResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureVideoProfile> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::OptionalReferencePhotoCapturedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::PhotoCapturedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::PhotoConfirmationCapturedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::VideoStreamConfiguration> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
