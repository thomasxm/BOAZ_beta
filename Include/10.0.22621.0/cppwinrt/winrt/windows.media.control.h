// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Control_H
#define WINRT_Windows_Media_Control_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Media.Control.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::SourceAppUserModelId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->get_SourceAppUserModelId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryGetMediaPropertiesAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryGetMediaPropertiesAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::GetTimelineProperties() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->GetTimelineProperties(&result));
        return winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::GetPlaybackInfo() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->GetPlaybackInfo(&result));
        return winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryPlayAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryPlayAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryPauseAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryPauseAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryStopAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryStopAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryRecordAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryRecordAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryFastForwardAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryFastForwardAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryRewindAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryRewindAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TrySkipNextAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TrySkipNextAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TrySkipPreviousAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TrySkipPreviousAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryChangeChannelUpAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryChangeChannelUpAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryChangeChannelDownAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryChangeChannelDownAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryTogglePlayPauseAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryTogglePlayPauseAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryChangeAutoRepeatModeAsync(winrt::Windows::Media::MediaPlaybackAutoRepeatMode const& requestedAutoRepeatMode) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryChangeAutoRepeatModeAsync(static_cast<int32_t>(requestedAutoRepeatMode), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryChangePlaybackRateAsync(double requestedPlaybackRate) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryChangePlaybackRateAsync(requestedPlaybackRate, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryChangeShuffleActiveAsync(bool requestedShuffleState) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryChangeShuffleActiveAsync(requestedShuffleState, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryChangePlaybackPositionAsync(int64_t requestedPlaybackPosition) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryChangePlaybackPositionAsync(requestedPlaybackPosition, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TimelinePropertiesChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession, winrt::Windows::Media::Control::TimelinePropertiesChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->add_TimelinePropertiesChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TimelinePropertiesChanged_revoker consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TimelinePropertiesChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession, winrt::Windows::Media::Control::TimelinePropertiesChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TimelinePropertiesChanged_revoker>(this, TimelinePropertiesChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TimelinePropertiesChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->remove_TimelinePropertiesChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::PlaybackInfoChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession, winrt::Windows::Media::Control::PlaybackInfoChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->add_PlaybackInfoChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::PlaybackInfoChanged_revoker consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::PlaybackInfoChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession, winrt::Windows::Media::Control::PlaybackInfoChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PlaybackInfoChanged_revoker>(this, PlaybackInfoChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::PlaybackInfoChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->remove_PlaybackInfoChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::MediaPropertiesChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession, winrt::Windows::Media::Control::MediaPropertiesChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->add_MediaPropertiesChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::MediaPropertiesChanged_revoker consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::MediaPropertiesChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession, winrt::Windows::Media::Control::MediaPropertiesChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, MediaPropertiesChanged_revoker>(this, MediaPropertiesChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::MediaPropertiesChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->remove_MediaPropertiesChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::GetCurrentSession() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager)->GetCurrentSession(&result));
        return winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::GetSessions() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager)->GetSessions(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::CurrentSessionChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, winrt::Windows::Media::Control::CurrentSessionChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager)->add_CurrentSessionChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::CurrentSessionChanged_revoker consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::CurrentSessionChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, winrt::Windows::Media::Control::CurrentSessionChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CurrentSessionChanged_revoker>(this, CurrentSessionChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::CurrentSessionChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager)->remove_CurrentSessionChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::SessionsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, winrt::Windows::Media::Control::SessionsChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager)->add_SessionsChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::SessionsChanged_revoker consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::SessionsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, winrt::Windows::Media::Control::SessionsChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SessionsChanged_revoker>(this, SessionsChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::SessionsChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager)->remove_SessionsChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManagerStatics<D>::RequestAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics)->RequestAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::Subtitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_Subtitle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::AlbumArtist() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_AlbumArtist(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::Artist() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_Artist(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::AlbumTitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_AlbumTitle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::TrackNumber() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_TrackNumber(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::Genres() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_Genres(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::AlbumTrackCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_AlbumTrackCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Media::MediaPlaybackType>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::PlaybackType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_PlaybackType(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Media::MediaPlaybackType>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::Thumbnail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_Thumbnail(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsPlayEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsPlayEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsPauseEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsPauseEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsStopEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsStopEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsRecordEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsRecordEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsFastForwardEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsFastForwardEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsRewindEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsRewindEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsNextEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsNextEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsPreviousEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsPreviousEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsChannelUpEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsChannelUpEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsChannelDownEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsChannelDownEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsPlayPauseToggleEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsPlayPauseToggleEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsShuffleEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsShuffleEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsRepeatEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsRepeatEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsPlaybackRateEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsPlaybackRateEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsPlaybackPositionEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsPlaybackPositionEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo<D>::Controls() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo)->get_Controls(&value));
        return winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackStatus) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo<D>::PlaybackStatus() const
    {
        winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo)->get_PlaybackStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Media::MediaPlaybackType>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo<D>::PlaybackType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo)->get_PlaybackType(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Media::MediaPlaybackType>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Media::MediaPlaybackAutoRepeatMode>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo<D>::AutoRepeatMode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo)->get_AutoRepeatMode(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Media::MediaPlaybackAutoRepeatMode>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo<D>::PlaybackRate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo)->get_PlaybackRate(&value));
        return winrt::Windows::Foundation::IReference<double>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<bool>) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo<D>::IsShuffleActive() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo)->get_IsShuffleActive(&value));
        return winrt::Windows::Foundation::IReference<bool>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties<D>::StartTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties)->get_StartTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties<D>::EndTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties)->get_EndTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties<D>::MinSeekTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties)->get_MinSeekTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties<D>::MaxSeekTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties)->get_MaxSeekTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties<D>::Position() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties<D>::LastUpdatedTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties)->get_LastUpdatedTime(put_abi(value)));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Control::ICurrentSessionChangedEventArgs> : produce_base<D, winrt::Windows::Media::Control::ICurrentSessionChangedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession> : produce_base<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession>
    {
        int32_t __stdcall get_SourceAppUserModelId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SourceAppUserModelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetMediaPropertiesAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties>>(this->shim().TryGetMediaPropertiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTimelineProperties(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties>(this->shim().GetTimelineProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPlaybackInfo(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo>(this->shim().GetPlaybackInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryPlayAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryPlayAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryPauseAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryPauseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryStopAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryStopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryRecordAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRecordAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryFastForwardAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryFastForwardAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryRewindAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRewindAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySkipNextAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySkipNextAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySkipPreviousAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySkipPreviousAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryChangeChannelUpAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryChangeChannelUpAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryChangeChannelDownAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryChangeChannelDownAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryTogglePlayPauseAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryTogglePlayPauseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryChangeAutoRepeatModeAsync(int32_t requestedAutoRepeatMode, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryChangeAutoRepeatModeAsync(*reinterpret_cast<winrt::Windows::Media::MediaPlaybackAutoRepeatMode const*>(&requestedAutoRepeatMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryChangePlaybackRateAsync(double requestedPlaybackRate, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryChangePlaybackRateAsync(requestedPlaybackRate));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryChangeShuffleActiveAsync(bool requestedShuffleState, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryChangeShuffleActiveAsync(requestedShuffleState));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryChangePlaybackPositionAsync(int64_t requestedPlaybackPosition, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryChangePlaybackPositionAsync(requestedPlaybackPosition));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_TimelinePropertiesChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TimelinePropertiesChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession, winrt::Windows::Media::Control::TimelinePropertiesChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TimelinePropertiesChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TimelinePropertiesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PlaybackInfoChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PlaybackInfoChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession, winrt::Windows::Media::Control::PlaybackInfoChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PlaybackInfoChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackInfoChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_MediaPropertiesChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MediaPropertiesChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession, winrt::Windows::Media::Control::MediaPropertiesChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MediaPropertiesChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MediaPropertiesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager> : produce_base<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager>
    {
        int32_t __stdcall GetCurrentSession(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession>(this->shim().GetCurrentSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSessions(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession>>(this->shim().GetSessions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_CurrentSessionChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CurrentSessionChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, winrt::Windows::Media::Control::CurrentSessionChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CurrentSessionChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CurrentSessionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SessionsChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SessionsChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, winrt::Windows::Media::Control::SessionsChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SessionsChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SessionsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics> : produce_base<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics>
    {
        int32_t __stdcall RequestAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager>>(this->shim().RequestAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties> : produce_base<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties>
    {
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Subtitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Subtitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AlbumArtist(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AlbumArtist());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Artist(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Artist());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AlbumTitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AlbumTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TrackNumber(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().TrackNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Genres(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Genres());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AlbumTrackCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().AlbumTrackCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Media::MediaPlaybackType>>(this->shim().PlaybackType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Thumbnail(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls> : produce_base<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls>
    {
        int32_t __stdcall get_IsPlayEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPlayEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPauseEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPauseEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStopEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStopEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsRecordEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRecordEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsFastForwardEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsFastForwardEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsRewindEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRewindEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsNextEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsNextEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPreviousEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPreviousEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsChannelUpEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsChannelUpEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsChannelDownEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsChannelDownEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPlayPauseToggleEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPlayPauseToggleEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsShuffleEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsShuffleEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsRepeatEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRepeatEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPlaybackRateEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPlaybackRateEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPlaybackPositionEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPlaybackPositionEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo> : produce_base<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo>
    {
        int32_t __stdcall get_Controls(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls>(this->shim().Controls());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackStatus>(this->shim().PlaybackStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Media::MediaPlaybackType>>(this->shim().PlaybackType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutoRepeatMode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Media::MediaPlaybackAutoRepeatMode>>(this->shim().AutoRepeatMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackRate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<double>>(this->shim().PlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsShuffleActive(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<bool>>(this->shim().IsShuffleActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties> : produce_base<D, winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties>
    {
        int32_t __stdcall get_StartTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EndTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().EndTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinSeekTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().MinSeekTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxSeekTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().MaxSeekTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastUpdatedTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().LastUpdatedTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Control::IMediaPropertiesChangedEventArgs> : produce_base<D, winrt::Windows::Media::Control::IMediaPropertiesChangedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Control::IPlaybackInfoChangedEventArgs> : produce_base<D, winrt::Windows::Media::Control::IPlaybackInfoChangedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Control::ISessionsChangedEventArgs> : produce_base<D, winrt::Windows::Media::Control::ISessionsChangedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Control::ITimelinePropertiesChangedEventArgs> : produce_base<D, winrt::Windows::Media::Control::ITimelinePropertiesChangedEventArgs>
    {
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::Control
{
    inline auto GlobalSystemMediaTransportControlsSessionManager::RequestAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager>(*)(IGlobalSystemMediaTransportControlsSessionManagerStatics const&), GlobalSystemMediaTransportControlsSessionManager, IGlobalSystemMediaTransportControlsSessionManagerStatics>([](IGlobalSystemMediaTransportControlsSessionManagerStatics const& f) { return f.RequestAsync(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::Control::ICurrentSessionChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::IMediaPropertiesChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::IPlaybackInfoChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::ISessionsChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::ITimelinePropertiesChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::CurrentSessionChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::MediaPropertiesChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::PlaybackInfoChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::SessionsChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Control::TimelinePropertiesChangedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
